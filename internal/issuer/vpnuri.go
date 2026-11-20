package issuer

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// RenderVPNURI собирает ссылку импорта AmneziaVPN (vpn://) — спека 2026-10-29,
// раздел 6. Разбор исходников amnezia-client (5.0.1.5 … 5.0.4.2):
//
//   - туннель строится НЕ из текста `config`, а из типизированной модели
//     AwgClientConfig (awgProtocolConfig.cpp) — каждое поле обязано лечь
//     отдельным ключом last_config, иначе клиент молча его выбросит; текст
//     config остаётся для показа и экспорта;
//   - типы важны: port в last_config — число (toInt), все AWG-ключи, mtu и
//     keepalive — строки (toString() у числа даёт пустую строку); внешний
//     port — строка;
//   - IPv6 в client_ip ломает десктопный клиент — отдаём только IPv4;
//   - кодирование — qCompress (4 байта длины big-endian + zlib), base64url
//     без «=», префикс vpn://.
//
// Подтверждено живым импортом пока НЕ было — см. спеку, раздел 6.
func RenderVPNURI(p ClientParams, description string) (string, error) {
	conf, err := RenderClientConfig(p)
	if err != nil {
		return "", err
	}
	host, portStr, err := net.SplitHostPort(p.Endpoint)
	if err != nil {
		return "", fmt.Errorf("vpn://: endpoint %q не в формате адрес:порт: %w", p.Endpoint, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", fmt.Errorf("vpn://: порт %q в endpoint не число 1..65535", portStr)
	}

	clientIP := firstIPv4(p.Address)
	if clientIP == "" {
		return "", fmt.Errorf("%w: vpn://: у пира нет IPv4-адреса (%q) — AmneziaVPN принимает в client_ip "+
			"только IPv4, такая ссылка импортировалась бы в нерабочий туннель", ErrInvalidInput, p.Address)
	}
	in := map[string]any{
		"client_ip":       clientIP,
		"client_priv_key": p.PrivateKey,
		"psk_key":         p.PresharedKey,
		"server_pub_key":  p.ServerPublicKey,
		"hostName":        host,
		"port":            port,
		"allowed_ips":     splitList(p.AllowedIPs),
		"config":          conf,
	}
	str := func(k, v string) {
		if v != "" {
			in[k] = v
		}
	}
	num := func(k string, v int) {
		if v > 0 {
			in[k] = strconv.Itoa(v)
		}
	}
	str("mtu", p.MTU)
	str("persistent_keep_alive", p.Keepalive)
	num("Jc", p.Jc)
	num("Jmin", p.Jmin)
	num("Jmax", p.Jmax)
	for _, k := range RequiredObfuscationKeys {
		str(k, p.Obfuscation[k])
	}
	for _, k := range TrailerKeys {
		if v := p.Obfuscation[k]; isOn(v) {
			in[k] = v
		}
	}
	for _, k := range TimingKeys {
		str(k, p.Obfuscation[k])
	}
	for k, v := range p.Extra {
		if isIKey(k) {
			str(strings.ToUpper(k), v) // клиент знает ключи только как I1..I5
		}
	}
	inner, err := json.Marshal(in)
	if err != nil {
		return "", err
	}

	outer := map[string]any{
		"containers": []any{map[string]any{
			"container": "amnezia-awg",
			"awg": map[string]any{
				"isThirdPartyConfig": true,
				"last_config":        string(inner),
				"port":               portStr,
				"protocol_version":   "2",
				"transport_proto":    "udp",
			},
		}},
		"defaultContainer": "amnezia-awg",
		"description":      description,
		"hostName":         host,
	}
	dns := splitList(p.DNS)
	if len(dns) > 0 {
		outer["dns1"] = dns[0]
	}
	if len(dns) > 1 {
		outer["dns2"] = dns[1]
	}
	js, err := json.Marshal(outer)
	if err != nil {
		return "", err
	}
	return "vpn://" + base64.RawURLEncoding.EncodeToString(qCompress(js)), nil
}

// qCompress — формат Qt: 4 байта длины исходных данных big-endian + поток zlib.
// Уровень сжатия клиенту безразличен (это свойство inflate).
func qCompress(data []byte) []byte {
	var b bytes.Buffer
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(data)))
	b.Write(n[:])
	zw := zlib.NewWriter(&b)
	zw.Write(data) // запись в bytes.Buffer не отказывает
	zw.Close()
	return b.Bytes()
}

// splitList режет список через запятую, отбрасывая пустые элементы.
func splitList(s string) []string {
	out := []string{}
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// firstIPv4 — первый IPv4 из Address без маски.
func firstIPv4(addr string) string {
	for _, a := range splitList(addr) {
		ip, _, _ := strings.Cut(a, "/")
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
			return ip
		}
	}
	return ""
}
