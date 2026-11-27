package issuer

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"strconv"

	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/store"
)

// Личный I1 на каждого пира (07.09.2026).
//
// I1 умолчаний интерфейса задаёт ПРОФИЛЬ мимикрии (см.
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

// i1Value accepts the canonical key and its lowercase form, as the client does.
func i1Value(extra map[string]string) string {
	if value := extra["I1"]; value != "" {
		return value
	}
	return extra["i1"]
}

// personalizeI1 is shared by issuance and export. The returned source
// describes the effective CPS, including an unrecognized manually supplied one.
func (s *Service) personalizeI1(e *EffectiveClient, o *store.Overrides, d store.Defaults, seeded bool, peerID, peerPub string) string {
	if o != nil && o.CPS != nil {
		if countIPackets(e.Extra) == 0 {
			return "none"
		}
		return "peer"
	}
	if o != nil && i1Value(o.Extra) != "" {
		return "peer"
	}

	defaultsI1 := i1Value(d.Extra)
	i1, ok := personalSignature(peerID, peerPub, defaultsI1, s.listenPort())
	if ok {
		delete(e.Extra, "i1")
		e.Extra["I1"] = i1
		if _, recognized := DetectProfile(defaultsI1); recognized && !seeded {
			return "defaults"
		}
		return "port"
	}
	if countIPackets(e.Extra) == 0 {
		return "none"
	}
	if o != nil && o.Extra != nil {
		return "peer"
	}
	return "defaults"
}

// PeerMimicry contains only the metadata needed to describe the effective CPS.
type PeerMimicry struct {
	Profile      MimicryProfile `json:"profile,omitempty"`
	Source       string         `json:"source"`
	EndpointPort int            `json:"endpoint_port"`
	ProfilePort  int            `json:"profile_port,omitempty"`
	PortMismatch bool           `json:"port_mismatch"`
	HasCPS       bool           `json:"has_cps"`
}

// PeerMimicryFor describes the same settings used when exporting the peer.
func (s *Service) PeerMimicryFor(id string) (PeerMimicry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, cp, err := s.clientParamsFor(id)
	if err != nil {
		return PeerMimicry{}, err
	}
	_, port, _ := net.SplitHostPort(cp.Endpoint)
	endpointPort, _ := strconv.Atoi(port)
	profile, _ := DetectProfile(i1Value(cp.Extra))
	profilePort, _ := PortForProfile(profile)
	return PeerMimicry{
		Profile: profile, Source: cp.mimicrySource, EndpointPort: endpointPort,
		ProfilePort: profilePort, PortMismatch: profilePort != 0 && endpointPort != 0 && profilePort != endpointPort,
		HasCPS: countIPackets(cp.Extra) != 0,
	}, nil
}

// ConfigWithoutCPSFor exports a control profile for the same peer and keys.
func (s *Service) ConfigWithoutCPSFor(id string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.configFor(id, true)
}

// ComparisonConfigFor exports a variant for the same client. Isolate the
// signature packets when present, otherwise toggle only junk padding.
func (s *Service) ComparisonConfigFor(id string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, cp, err := s.clientParamsFor(id)
	if err != nil {
		return "", "", err
	}
	switch {
	case countIPackets(cp.Extra) != 0:
		replaceCPS(cp.Extra, [5]string{})
	case cp.Jc != 0:
		cp.Jc, cp.Jmin, cp.Jmax = 0, 0, 0
	default:
		cp.Jc, cp.Jmin, cp.Jmax = 4, 20, 60
	}
	body, err := RenderClientConfig(cp)
	if err != nil {
		return "", "", err
	}
	return store.Slug(peer.Name) + "-compare.conf", body, nil
}
