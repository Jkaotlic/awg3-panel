package issuer

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/store"
)

// Личный I1 на каждого пира (07.09.2026).
//
// I1 умолчаний интерфейса задаёт ПРОФИЛЬ мимикрии (quic/dns/stun — см.
// DetectProfile), а не сам пакет: одинаковый сигнатурный пакет у всех
// клиентов одного сервера — общий отпечаток, по которому их можно связать.
// Поэтому при выпуске (Add, Rotate) и при каждой выдаче (ConfigFor/QRFor)
// пир получает I1 того же профиля, но со своими случайными полями.
//
// Случайность — детерминированная, от id и публичного ключа пира: повторное
// скачивание конфига обязано давать тот же файл и тот же QR (тот же довод,
// что и у сортировки extra в RenderClientConfig), а ротация ключей меняет
// pubkey и вместе с ним I1. Хранить личный I1 в оверрайдах нельзя: Overrides.
// Extra заменяет карту умолчаний ЦЕЛИКОМ (см. Effective), и оператор,
// поменявший I2 в умолчаниях, не увидел бы изменения ни у одного пира.
//
// Явный I1 в оверрайдах пира — решение оператора, он не трогается.
// Нет ни I1 в умолчаниях, ни профиля у порта — личный I1 не сеется, конфиг
// уходит без него, как и раньше.

const personalSignatureDomain = "awg3panel-i1-v1"

// seededReader — детерминированный поток байт: sha256(домен ‖ seed ‖ счётчик).
// Криптостойкость здесь не нужна (I1 не секрет), нужна воспроизводимость.
type seededReader struct {
	seed []byte
	ctr  uint64
	buf  []byte
}

func newSeededReader(seed string) *seededReader {
	return &seededReader{seed: []byte(personalSignatureDomain + "\x00" + seed)}
}

func (r *seededReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(r.buf) == 0 {
			h := sha256.New()
			h.Write(r.seed)
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], r.ctr)
			h.Write(c[:])
			r.buf = h.Sum(nil)
			r.ctr++
		}
		k := copy(p[n:], r.buf)
		r.buf = r.buf[k:]
		n += k
	}
	return n, nil
}

var _ io.Reader = (*seededReader)(nil)

// personalSignature возвращает личный I1 пира или "" и false, если профиль
// вывести неоткуда. defaultsI1 — I1 умолчаний интерфейса (профиль), port —
// живой порт интерфейса (запасной источник профиля, как у mimicrySeedFor).
func personalSignature(peerID, peerPub, defaultsI1 string, port int) (string, bool) {
	profile, ok := DetectProfile(defaultsI1)
	if !ok {
		if profile, ok = ProfileForPort(port); !ok {
			return "", false
		}
	}
	i1, err := GenerateSignatureFor(newSeededReader(peerID+"\x00"+peerPub), profile)
	if err != nil {
		return "", false
	}
	return i1, true
}

// listenPort читает живой порт интерфейса; 0 — если устройство не отвечает
// (тогда профиль возможен только из I1 умолчаний).
func (s *Service) listenPort() int {
	dumpText, err := s.r.Show(s.iface.Interface)
	if err != nil {
		return 0
	}
	dev, err := runtime.ParseDumpDevice(dumpText)
	if err != nil {
		return 0
	}
	return dev.ListenPort
}

// personalizeI1 подставляет личный I1 в уже слитые клиентские параметры.
// o — оверрайды пира: явный I1 в них имеет приоритет и остаётся как есть.
func (s *Service) personalizeI1(e *EffectiveClient, o *store.Overrides, peerID, peerPub string) {
	if o != nil && o.Extra != nil && o.Extra["I1"] != "" {
		return
	}
	d := s.defaults()
	i1, ok := personalSignature(peerID, peerPub, d.Extra["I1"], s.listenPort())
	if !ok {
		return
	}
	if e.Extra == nil {
		e.Extra = map[string]string{}
	}
	e.Extra["I1"] = i1
}
