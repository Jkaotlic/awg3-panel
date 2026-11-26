// Adapted from payloadGen (MIT) — https://github.com/Sketchystan1/payloadGen
package warpsignature

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	mrand "math/rand"
)

const quicInitialSize = 1200 // RFC 9000 §14.1 минимум для Initial
const quicAEADTagLen = 16

// buildQUICProfileWithHost — статический валидный Initial: любой DPI выводит ключи
// Initial из DCID и расшифровывает пакет, поэтому внутри должен лежать
// настоящий ClientHello, а не <r>-мусор. Цена — байты одинаковы в каждом
// рукопожатии.
func buildQUICProfileWithHost(r *mrand.Rand, customHost string) (GeneratedPackets, string, error) {
	dcid, scid, pn := randBytes(8), randBytes(8), randBytes(4)
	host := customHost
	if host == "" {
		host = pickHost(r)
	}
	ch, err := buildClientHello(r, host, scid)
	if err != nil {
		return GeneratedPackets{}, "", err
	}
	frame := &wire{}
	frame.u8(0x06) // CRYPTO
	frame.varint(0)
	frame.varint(uint64(len(ch)))
	frame.raw(ch)
	payload := padInitial(frame.bytes(), len(dcid), len(scid), len(pn))
	pkt, err := protectInitial(dcid, scid, pn, payload)
	if err != nil {
		return GeneratedPackets{}, "", err
	}
	if len(pkt) != quicInitialSize {
		return GeneratedPackets{}, "", fmt.Errorf("quic initial: %d bytes, want %d", len(pkt), quicInitialSize)
	}
	return GeneratedPackets{I1: tokB(pkt)}, host, nil
}

// padInitial добивает payload нулями (PADDING-фреймы) до пакета в
// quicInitialSize байт. Размер поля длины — varint, поэтому итерируем (§1.5).
func padInitial(payload []byte, dcidLen, scidLen, pnLen int) []byte {
	headerPrefix := 1 + 4 + 1 + dcidLen + 1 + scidLen + 1 // +1 = varint(0) длины токена
	protected := pnLen + len(payload) + quicAEADTagLen
	pad := 0
	for i := 0; i < 4; i++ {
		next := quicInitialSize - (headerPrefix + varintLen(uint64(protected+pad)) + protected)
		if next < 0 {
			next = 0
		}
		if next == pad {
			break
		}
		pad = next
	}
	return append(payload, make([]byte, pad)...)
}

// protectInitial шифрует payload (AEAD, AAD = незащищённый заголовок) и
// накладывает header protection — RFC 9001 §5.3, §5.4.
// Требование к pn (packet number): 1 ≤ len(pn) ≤ 4 — иначе `0xC0 | byte((len(pn)-1)&0x03)`
// в первом байте заголовка молча съедает лишние биты длины (единственный вызов ниже передаёт 4).
func protectInitial(dcid, scid, pn, payload []byte) ([]byte, error) {
	key, iv, hpKey, err := deriveInitialKeys(dcid)
	if err != nil {
		return nil, err
	}

	h := &wire{}
	h.u8(int(0xC0 | byte((len(pn)-1)&0x03)))
	h.u32(0x00000001) // QUIC v1
	h.u8(len(dcid))
	h.raw(dcid)
	h.u8(len(scid))
	h.raw(scid)
	h.varint(0) // token length
	h.varint(uint64(len(pn) + len(payload) + quicAEADTagLen))
	h.raw(pn)
	header := h.bytes()

	packetBlock, err := aesBlock(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(packetBlock)
	if err != nil {
		return nil, err
	}
	nonce := append([]byte(nil), iv...)
	for i, b := range pn {
		nonce[len(nonce)-len(pn)+i] ^= b
	}
	ct := aead.Seal(nil, nonce, payload, header)

	hpBlock, err := aesBlock(hpKey)
	if err != nil {
		return nil, err
	}
	sampleOff := 4 - len(pn)
	mask := make([]byte, aes.BlockSize)
	hpBlock.Encrypt(mask, ct[sampleOff:sampleOff+aes.BlockSize])
	header[0] ^= mask[0] & 0x0F // длинный заголовок — только младшие 4 бита
	pnOff := len(header) - len(pn)
	for i := range pn {
		header[pnOff+i] ^= mask[1+i]
	}
	return append(header, ct...), nil
}

// aesBlock — AES на ключе фиксированной длины. Ошибка означала бы неверную
// длину ключа, чего вывод по RFC 9001 не допускает, но AddPeer fails closed —
// прокидываем, а не паникуем.
func aesBlock(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

// QUIC v1 initial salt (RFC 9001 §5.2)
var quicV1InitialSalt, _ = hex.DecodeString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

// deriveInitialKeys derives the client Initial key, IV, and HP key from a DCID.
func deriveInitialKeys(dcid []byte) (key, iv, hp []byte, err error) {
	// initial_secret = HKDF-Extract(initial_salt, DCID)
	initialSecret := hkdfExtract(quicV1InitialSalt, dcid)

	// client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
	clientSecret := hkdfExpandLabel(initialSecret, "client in", nil, 32)

	// key = HKDF-Expand-Label(client_secret, "quic key", "", 16)
	key = hkdfExpandLabel(clientSecret, "quic key", nil, 16)
	// iv = HKDF-Expand-Label(client_secret, "quic iv", "", 12)
	iv = hkdfExpandLabel(clientSecret, "quic iv", nil, 12)
	// hp = HKDF-Expand-Label(client_secret, "quic hp", "", 16)
	hp = hkdfExpandLabel(clientSecret, "quic hp", nil, 16)

	return key, iv, hp, nil
}

// hkdfExtract performs HKDF-Extract (RFC 5869) using HMAC-SHA256.
func hkdfExtract(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// hkdfExpandLabel performs HKDF-Expand-Label as defined in TLS 1.3 (RFC 8446 §7.1).
// Label is prefixed with "tls13 " automatically.
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	// HkdfLabel = length(2) + "tls13 " + label + context_length(1) + context
	fullLabel := "tls13 " + label
	var hkdfLabel []byte
	hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
	hkdfLabel = append(hkdfLabel, byte(len(fullLabel)))
	hkdfLabel = append(hkdfLabel, []byte(fullLabel)...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)

	return hkdfExpand(secret, hkdfLabel, length)
}

// hkdfExpand performs HKDF-Expand (RFC 5869) using HMAC-SHA256.
func hkdfExpand(prk, info []byte, length int) []byte {
	hashLen := sha256.Size
	n := (length + hashLen - 1) / hashLen
	var out []byte
	var prev []byte

	for i := 1; i <= n; i++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{byte(i)})
		prev = mac.Sum(nil)
		out = append(out, prev...)
	}

	return out[:length]
}
