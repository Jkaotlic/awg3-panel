package issuer

// Задача 3 (спека 2026-08-25, раздел 5.5): сев I1 в defaults.json нового
// интерфейса теперь берёт профиль мимикрии ПО ПОРТУ интерфейса, а не сеет
// DNS-пакет безусловно, как раньше. Отдельный внутренний (white-box) файл, а
// не правка service_test.go (который уже правит эта же ветка задачей 1/2 в
// части конструкторов) — тот же приём и то же обоснование, что у
// defaults_lock_internal_test.go: структурная проверка байтов I1 требует
// decodeTags (generate_test.go, тот же package issuer, неэкспортирован) —
// из внешнего issuer_test её не достать.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
)

// minimalDeviceConf — минимальный валидный конфиг для runtime.NewFake:
// Fake.Show разбирает f.Conf через wgconf.Parse ДО того, как напечатать
// строку устройства (devPub/devPort из SetDevice), поэтому пустая строка
// конфига валит Show ошибкой "секция [Interface] не найдена" раньше, чем
// порт вообще попадёт в игру — эти тесты проверяют не разбор конфига, а
// выбор профиля по порту, значит конфиг обязан быть валиден, но пуст
// содержательно.
const minimalDeviceConf = "[Interface]\nPrivateKey = " +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"

// seedTestIface — минимальный config.Interface для теста сева умолчаний:
// прямой слэш в Storage.State по той же причине, что и в
// defaults_lock_internal_test.go (DefaultsPath строит путь через path.Dir, а
// filepath.Join на Windows отдаёт обратный слэш, в котором path.Dir не
// находит разделителя).
func seedTestIface(t *testing.T, dir string) config.Interface {
	t.Helper()
	return config.Interface{
		ID:        "test",
		Interface: "test0",
		Client:    config.Client{Endpoint: "1.2.3.4:51772", AllowedIPs: "0.0.0.0/0"},
		Storage:   config.Storage{State: filepath.ToSlash(dir) + "/peers.json"},
	}
}

// captureLog перенаправляет стандартный логгер в буфер на время теста и
// возвращает функцию чтения накопленного текста.
func captureLog(t *testing.T) func() string {
	t.Helper()
	var buf bytes.Buffer
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return buf.String
}

// TestSeedI1QUICForPort443 — порт 443 (канонический для QUIC) даёт I1,
// структурно опознаваемый как клиентский QUIC Initial (длинный заголовок,
// версия 1) — те же маркеры, что проверяет TestQUICПрофильСтруктура.
func TestSeedI1QUICForPort443(t *testing.T) {
	dir := t.TempDir()
	iface := seedTestIface(t, dir)
	f := runtime.NewFake(minimalDeviceConf)
	f.SetDevice("devpub", 443)
	s := New(iface, "", f)

	d := s.Defaults()

	i1, ok := d.Extra["I1"]
	if !ok || i1 == "" {
		t.Fatalf("порт 443: I1 не посеян, Extra = %+v", d.Extra)
	}
	raw := decodeTags(t, i1)
	if len(raw) < 5 || raw[0]&0xc0 != 0xc0 {
		t.Fatalf("порт 443: первый байт %#x — не длинный заголовок QUIC (пакет не тот профиль)", raw[0])
	}
	if v := binary.BigEndian.Uint32(raw[1:5]); v != 1 {
		t.Fatalf("порт 443: версия QUIC %#x, ожидалась 1", v)
	}
}

// TestSeedI1DNSForPort53 — порт 53 (канонический для DNS) даёт I1,
// структурно опознаваемый как DNS-запрос (флаги 0x0100, ancount = 0) — те же
// маркеры, что TestDNSПрофильЭтоЗапросАНеОтвет.
func TestSeedI1DNSForPort53(t *testing.T) {
	dir := t.TempDir()
	iface := seedTestIface(t, dir)
	f := runtime.NewFake(minimalDeviceConf)
	f.SetDevice("devpub", 53)
	s := New(iface, "", f)

	d := s.Defaults()

	i1, ok := d.Extra["I1"]
	if !ok || i1 == "" {
		t.Fatalf("порт 53: I1 не посеян, Extra = %+v", d.Extra)
	}
	raw := decodeTags(t, i1)
	if len(raw) < 8 {
		t.Fatalf("порт 53: пакет короче 8 байт, заголовка DNS в нём нет: %d", len(raw))
	}
	if flags := binary.BigEndian.Uint16(raw[2:4]); flags != 0x0100 {
		t.Fatalf("порт 53: флаги %#x, ожидались 0x0100 (DNS-запрос) — пакет не тот профиль", flags)
	}
	if an := binary.BigEndian.Uint16(raw[6:8]); an != 0 {
		t.Fatalf("порт 53: ancount = %d, у запроса ответов быть не может", an)
	}
}

// TestSeedI1STUNForPort3478 — порт 3478 (канонический для STUN) даёт I1,
// структурно опознаваемый как Binding Request с магическим печеньем
// 0x2112a442 (RFC 5389) — тот же маркер, что TestSTUNПрофильСтруктура.
func TestSeedI1STUNForPort3478(t *testing.T) {
	dir := t.TempDir()
	iface := seedTestIface(t, dir)
	f := runtime.NewFake(minimalDeviceConf)
	f.SetDevice("devpub", 3478)
	s := New(iface, "", f)

	d := s.Defaults()

	i1, ok := d.Extra["I1"]
	if !ok || i1 == "" {
		t.Fatalf("порт 3478: I1 не посеян, Extra = %+v", d.Extra)
	}
	raw := decodeTags(t, i1)
	if len(raw) < 8 {
		t.Fatalf("порт 3478: пакет короче 8 байт, заголовка STUN в нём нет: %d", len(raw))
	}
	if binary.BigEndian.Uint16(raw[0:2]) != 0x0001 {
		t.Fatalf("порт 3478: тип не Binding Request — пакет не тот профиль")
	}
	if binary.BigEndian.Uint32(raw[4:8]) != 0x2112a442 {
		t.Fatalf("порт 3478: нет магического печенья 0x2112a442 — пакет не тот профиль")
	}
}

// TestSeedI1AbsentForUnmatchedPort — порт 51772 (боевой порт main/nl2,
// AmneziaWG 3.0/3.1) ничему не соответствует. Посеять DNS-пакет сюда значило
// бы молча ухудшить маскировку (спека, раздел 5.5): I1 не появляется вовсе,
// умолчания при этом создаются нормально, а в журнале остаётся строка с
// номером порта и объяснением.
func TestSeedI1AbsentForUnmatchedPort(t *testing.T) {
	dir := t.TempDir()
	iface := seedTestIface(t, dir)
	f := runtime.NewFake(minimalDeviceConf)
	f.SetDevice("devpub", 51772)
	s := New(iface, "", f)
	readLog := captureLog(t)

	d := s.Defaults()

	if _, ok := d.Extra["I1"]; ok {
		t.Fatalf("порт 51772 ничему не соответствует, I1 не должен появиться: %+v", d.Extra)
	}
	got := readLog()
	if !strings.Contains(got, "51772") {
		t.Fatalf("в журнале нет номера порта 51772:\n%s", got)
	}
	if !strings.Contains(got, "профил") {
		t.Fatalf("в журнале нет объяснения про отсутствие профиля:\n%s", got)
	}
}

// errShowRunner — Runner, у которого Show всегда отказывает: моделирует
// интерфейс, ещё не поднятый на момент первого создания умолчаний (порт
// узнать неоткуда — `awg show <iface> dump` не отвечает).
type errShowRunner struct {
	*runtime.Fake
	err error
}

func (r *errShowRunner) Show(iface string) (string, error) {
	return "", r.err
}

// TestSeedI1AbsentWhenPortUnreadable — порт прочитать не удалось (интерфейс
// поднят позже панели). Ведём себя ровно так же, как при «профиля нет»: I1
// не сеется, умолчания создаются, причина уходит в журнал. Посеять пакет
// наугад в этом случае хуже, чем не посеять вовсе (раздел «Откуда берётся
// порт» брифа задачи 3).
func TestSeedI1AbsentWhenPortUnreadable(t *testing.T) {
	dir := t.TempDir()
	iface := seedTestIface(t, dir)
	base := runtime.NewFake("")
	r := &errShowRunner{Fake: base, err: errors.New("устройство недоступно: интерфейс ещё не поднят")}
	s := New(iface, "", r)
	readLog := captureLog(t)

	d := s.Defaults()

	if _, ok := d.Extra["I1"]; ok {
		t.Fatalf("порт не прочитан, I1 не должен появиться: %+v", d.Extra)
	}
	got := readLog()
	if got == "" {
		t.Fatal("порт не прочитан, но журнал пуст — причина отказа не объяснена")
	}
}
