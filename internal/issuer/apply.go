package issuer

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

// ErrPostcondition означает, что после применения состояние живого
// устройства разошлось со снимком «до» — изменения откачены.
var ErrPostcondition = errors.New("постусловие не выполнено")

// ErrRollbackFailed означает, что откат НЕ восстановил пригодное состояние:
// либо не удалось перезаписать файл или повторно синхронизировать
// устройство, либо файл восстановлен, а живое устройство — нет. Отличать
// эту ошибку от штатного «изменения откачены» по errors.Is обязательно:
// в первом случае на диске или на устройстве лежит ПЛОХОЙ конфиг, во втором —
// состояние уже совпадает с тем, что было до Apply.
var ErrRollbackFailed = errors.New("откат не удался")

const maxBackups = 20

// Snapshot — состояние живого устройства до мутации.
type Snapshot struct {
	Device map[string]string           // параметры [Interface] из awg showconf
	Peers  map[string]runtime.DumpPeer // публичный ключ → данные из awg show dump
}

type Applier struct {
	mu        sync.Mutex // мутации сериализованы: два запроса не перепишут конфиг друг поверх друга
	r         runtime.Runner
	iface     string
	confPath  string
	backupDir string
	now       func() time.Time
	seq       int // порядковый номер бэкапа в рамках процесса
}

func NewApplier(r runtime.Runner, iface, confPath, backupDir string) *Applier {
	return &Applier{r: r, iface: iface, confPath: confPath, backupDir: backupDir, now: time.Now}
}

// Expect описывает изменение, которое обязано произойти на устройстве.
// Списки, а не одиночные ключи: одна мутация может добавить и убрать пира
// одновременно — ротация ключей выражается как Removed+Added, потому что на
// устройстве публичный ключ и есть идентичность пира.
type Expect struct {
	AddedRoutes map[string][]string // complete expected routes for a newly rotated key
	Added       []string
	Removed     []string
	Modified    []ExpectedPeerChange
}

// ExpectedPeerChange — пир, который остаётся на устройстве, но с заявленным
// изменением. Поля PresharedKey здесь нет намеренно: его меняет только
// ротация, а она идёт через Removed+Added (раздел 5.4 спеки).
type ExpectedPeerChange struct {
	PublicKey         string
	AllowedIPs        string // новое значение; "" = не менялось
	HandshakeMayReset bool
}

func (e Expect) removed(pub string) bool { return slices.Contains(e.Removed, pub) }
func (e Expect) added(pub string) bool   { return slices.Contains(e.Added, pub) }

func (e Expect) modified(pub string) (ExpectedPeerChange, bool) {
	for _, m := range e.Modified {
		if m.PublicKey == pub {
			return m, true
		}
	}
	return ExpectedPeerChange{}, false
}

// Snapshot снимает состояние живого устройства.
func (a *Applier) Snapshot() (Snapshot, error) {
	confText, err := a.r.ShowConf(a.iface)
	if err != nil {
		return Snapshot{}, fmt.Errorf("awg showconf: %w", err)
	}
	parsed, err := wgconf.Parse(confText)
	if err != nil {
		return Snapshot{}, fmt.Errorf("разбор вывода showconf: %w", err)
	}
	// Регистр ключей сохраняется: они попадают в текст ошибки, и
	// «HeaderProtectionKey» читается человеком лучше, чем «headerprotectionkey».
	device := map[string]string{}
	for _, kv := range parsed.Interface.Items {
		device[kv.Key] = kv.Value
	}
	dump, err := a.r.Show(a.iface)
	if err != nil {
		return Snapshot{}, fmt.Errorf("awg show dump: %w", err)
	}
	peers, err := runtime.ParseDump(dump)
	if err != nil {
		return Snapshot{}, fmt.Errorf("разбор dump: %w", err)
	}
	byKey := make(map[string]runtime.DumpPeer, len(peers))
	for _, p := range peers {
		byKey[p.PublicKey] = p
	}
	return Snapshot{Device: device, Peers: byKey}, nil
}

// Apply выполняет мутацию по инварианту раздела 6 спеки.
//
// mutate получает ТЕКСТ конфига и обязан вернуть текст, отличающийся от
// исходного только блоками [Peer]. Это проверяется до записи на диск.
func (a *Applier) Apply(mutate func(text string) (string, error), exp Expect) error {
	return a.apply(mutate, exp, nil)
}

func (a *Applier) apply(mutate func(string) (string, error), exp Expect, prepare func(string, string) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 0. Снимок ДО.
	before, err := a.Snapshot()
	if err != nil {
		return fmt.Errorf("снимок состояния до изменения: %w", err)
	}

	// 1. Прочитать конфиг как текст.
	origBytes, err := os.ReadFile(a.confPath)
	if err != nil {
		return fmt.Errorf("чтение %s: %w", a.confPath, err)
	}
	orig := string(origBytes)

	// 1.5. Предварительная сверка: файл на диске обязан совпадать с живым
	// устройством по [Interface] ДО того, как мы что-то с ним сделаем. Если
	// файл правили руками и он разошёлся с устройством, следующий syncconf
	// применит расходящееся значение к живому устройству — то самое молчаливое
	// отключение всех клиентов, ради обнаружения которого существует
	// постусловие, только шагом раньше и без возможности отката (см. CRITICAL 1
	// ревью Task 8: повторный syncconf при откате воспроизвёл бы то же самое
	// расхождение из того же файла).
	if err := assertFileMatchesDevice(before.Device, orig); err != nil {
		return err
	}

	configured, err := configuredPeers(orig)
	if err != nil {
		return err
	}
	if pub, reason := peerDiff(configured, before.Peers); reason != "" {
		return fmt.Errorf("%w: пир %s: %s", ErrStateConflict, shortKey(pub), reason)
	}

	// 2. Изменить текст.
	next, err := mutate(orig)
	if err != nil {
		return err
	}
	if err := assertInterfaceUntouched(orig, next); err != nil {
		return err
	}

	expected, err := configuredPeers(next)
	if err != nil {
		return err
	}
	for _, pub := range exp.Added {
		if _, ok := expected[pub]; !ok {
			return fmt.Errorf("%w: нового пира %s нет в конфиге", ErrPostcondition, shortKey(pub))
		}
	}

	// 3. Бэкап.
	if err := a.backup(orig); err != nil {
		return fmt.Errorf("бэкап: %w", err)
	}

	if prepare != nil {
		if err := prepare(orig, next); err != nil {
			return err
		}
	}

	// 4. Атомарная запись.
	if err := writeAtomic(a.confPath, next); err != nil {
		return fmt.Errorf("запись %s: %w", a.confPath, err)
	}

	// 5. Применить и 6. проверить постусловие; при любой беде — откат.
	if err := a.sync(); err != nil {
		return a.rollback(before, orig, fmt.Errorf("применение конфига: %w", err))
	}
	after, err := a.Snapshot()
	if err != nil {
		return a.rollback(before, orig, fmt.Errorf("снимок состояния после изменения: %w", err))
	}
	if err := checkPostcondition(before, after, exp); err != nil {
		return a.rollback(before, orig, err)
	}
	for _, pub := range exp.Added {
		if reason := peerSettingsDiff(expected[pub], after.Peers[pub]); reason != "" {
			return a.rollback(before, orig, fmt.Errorf("%w: у нового пира %s %s", ErrPostcondition, shortKey(pub), reason))
		}
	}

	return nil
}

func configuredPeers(raw string) (map[string]runtime.DumpPeer, error) {
	conf, err := wgconf.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("разбор пиров в конфиге: %w", err)
	}
	peers := make(map[string]runtime.DumpPeer, len(conf.Peers))
	for _, section := range conf.Peers {
		pub := section.Get("PublicKey")
		if _, duplicate := peers[pub]; duplicate || pub == "" {
			return nil, fmt.Errorf("%w: пустой или повторяющийся PublicKey в серверном конфиге", ErrStateConflict)
		}
		peers[pub] = runtime.DumpPeer{
			PublicKey: pub, PresharedKey: section.Get("PresharedKey"),
			AllowedIPs: section.AllowedIPEntries(), Keepalive: section.Get("PersistentKeepalive"),
		}
	}
	return peers, nil
}

func normalizedPSK(value string) string {
	if value == "(none)" || value == strings.Repeat("A", 43)+"=" {
		return ""
	}
	return value
}

func normalizedKeepalive(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "off") {
		return "0"
	}
	first, last, isRange := strings.Cut(value, "-")
	lo, err := strconv.ParseUint(strings.TrimSpace(first), 10, 16)
	if err != nil {
		return value
	}
	if !isRange {
		return strconv.FormatUint(lo, 10)
	}
	hi, err := strconv.ParseUint(strings.TrimSpace(last), 10, 16)
	if err != nil {
		return value
	}
	if lo == hi {
		return strconv.FormatUint(lo, 10)
	}
	return fmt.Sprintf("%d-%d", lo, hi)
}

// Endpoint может меняться при роуминге и не входит в сравнение статических полей.
func peerSettingsDiff(before, after runtime.DumpPeer) string {
	switch {
	case sortedJoin(before.AllowedIPs) != sortedJoin(after.AllowedIPs):
		return "изменились allowed-ips"
	case normalizedPSK(before.PresharedKey) != normalizedPSK(after.PresharedKey):
		return "изменился PresharedKey"
	case normalizedKeepalive(before.Keepalive) != normalizedKeepalive(after.Keepalive):
		return "изменился PersistentKeepalive"
	default:
		return ""
	}
}

// assertInterfaceUntouched — последний рубеж перед записью: секция
// [Interface] обязана совпасть побайтово (раздел 6.1 спеки).
func assertInterfaceUntouched(orig, next string) error {
	oc, err := wgconf.Parse(orig)
	if err != nil {
		return fmt.Errorf("исходный конфиг не разбирается: %w", err)
	}
	nc, err := wgconf.Parse(next)
	if err != nil {
		return fmt.Errorf("результат мутации не разбирается: %w", err)
	}
	if oc.Interface.Bytes(orig) != nc.Interface.Bytes(next) {
		return fmt.Errorf("мутация изменила секцию [Interface] — запись отменена")
	}
	return nil
}

// requiredDeviceKeys — device-параметры, чьё отсутствие в файле при наличии
// на устройстве бьёт по обфускации и идентичности интерфейса, то есть роняет
// туннель у ВСЕХ клиентов. Список нужен не для того, чтобы решить, отказывать
// ли (отказывают оба направления, 2 и 3), а для того, чтобы отказ назывался
// своим именем: у этих ключей цена расхождения другая, и сообщение оператору
// должно говорить именно про обфускацию.
//
// У всех перечисленных ключей представление однозначно: decimal-числа
// (ListenPort, S1..S4, H1..H4, Jc, Jmin, Jmax) или base64/строки, которые
// awg-quick не переформатирует (PrivateKey, HeaderProtectionKey,
// ContentPaddingAddition, I1..I5) — сравнение сырым строковым равенством
// здесь не рискует ложным отказом на разных представлениях одного значения,
// в отличие от FwMark, который печатается в hex.
var requiredDeviceKeys = map[string]bool{
	"privatekey": true, "listenport": true,
	"s1": true, "s2": true, "s3": true, "s4": true,
	"h1": true, "h2": true, "h3": true, "h4": true,
	"headerprotectionkey": true, "contentpaddingaddition": true,
	"jc": true, "jmin": true, "jmax": true,
	"i1": true, "i2": true, "i3": true, "i4": true, "i5": true,
}

// assertFileMatchesDevice сверяет секцию [Interface] файла на диске со
// снимком живого устройства ДО применения мутации, в обе стороны:
//
//  1. Ключ, присутствующий И в файле, И на устройстве, обязан совпадать по
//     значению. Сравниваются только ключи из пересечения: awg showconf по
//     построению не публикует Address, MTU, PostUp/PostDown, DNS и т.п.
//     (см. Fake.stripped) — сверка всех ключей файла давала бы ложный отказ
//     на любом нормальном конфиге.
//
//  2. Обязательный device-параметр (см. requiredDeviceKeys), присутствующий
//     на устройстве, обязан присутствовать и в файле. Без этого направления
//     ключ, которого в файле нет вовсе (а не просто другое значение),
//     проходил бы предварительную сверку молча: assertInterfaceUntouched не
//     возразит («в обеих версиях одинаково нет»), запись и syncconf пройдут,
//     и клиенты отвалятся ровно так же, как при расхождении по значению —
//     только уже после факта, а не до него.
//
//  3. ЛЮБОЙ прочий параметр устройства тоже обязан присутствовать в файле.
//     Прежде это направление отсутствовало сознательно: device-only ключ
//     (характерный пример — FwMark, который выставляет сам awg-quick и
//     никогда не пишет в файл) считался законной собственностью устройства,
//     потому что syncconf якобы не трогает то, чего нет во входных данных.
//     Живой эксперимент на AmneziaWG v3.0.20260730 это опроверг: syncconf
//     СБРАСЫВАЕТ device-поле, отсутствующее в пушимом конфиге (`awg set awg3
//     fwmark 42` → `awg syncconf awg3 <strip>` → `awg show awg3 fwmark` = off).
//     Единственное основание для исключения исчезло вместе с допущением.
//
//     Ловить это надо именно здесь, ДО записи. Постусловие расхождение
//     заметит (deviceDiff сверяет все ключи снимка), но уже после того, как
//     syncconf снёс параметр с устройства, — а откат такого не исправляет:
//     единственный рычаг отката это тот же файл, в котором параметра нет,
//     поэтому повторный syncconf воспроизводит ту же потерю, и оператор
//     получает ErrRollbackFailed «требуется ручное вмешательство» вместо
//     чистого отказа без единой побочки.
//
// Все три случая означают, что файл разошёлся с устройством, и применять его
// в этом состоянии небезопасно: следующий syncconf перепишет устройство —
// расходящимся значением обфускации либо потерей device-параметра.
func assertFileMatchesDevice(device map[string]string, orig string) error {
	oc, err := wgconf.Parse(orig)
	if err != nil {
		return fmt.Errorf("исходный конфиг не разбирается: %w", err)
	}
	file := map[string]string{}
	for _, kv := range oc.Interface.Items {
		file[kv.Key] = kv.Value
	}
	for k, v := range file {
		live, ok := lookupCI(device, k)
		if !ok {
			continue // showconf не публикует этот ключ — сравнивать нечего
		}
		if live != v {
			// Печатается только ИМЯ параметра и сам факт расхождения.
			// Значения — никогда: requiredDeviceKeys покрывает PrivateKey и
			// HeaderProtectionKey, а эта ошибка уезжает в journal обеими
			// дорогами (web.writeError → log.Printf; CLI → os.Stderr). Правило
			// 4 CLAUDE.md сформулировано без исключений, а срабатывает проверка
			// ровно в том сценарии, ради которого написана — файл правили
			// руками или восстановили старый бэкап. Оператору для починки
			// нужны обе версии значения, но брать их он обязан глазами из
			// файла и `awg showconf`, а не из лога (ревью финальное, C1).
			return fmt.Errorf(
				"файл конфига разошёлся с живым устройством по параметру %s (значения не совпадают) — "+
					"применять файл небезопасно: это может расстроить обфускацию у всех клиентов; "+
					"сверьте файл с выводом awg showconf и исправьте расхождение вручную", k)
		}
	}
	for k := range device {
		if !requiredDeviceKeys[strings.ToLower(k)] {
			continue // не обязательный — им займётся направление 3 ниже
		}
		if _, ok := lookupCI(file, k); !ok {
			return fmt.Errorf(
				"обязательный device-параметр %s есть на устройстве, но отсутствует в файле — "+
					"применять файл небезопасно: это может расстроить обфускацию у всех клиентов; "+
					"добавьте параметр в файл вручную, сверившись с устройством", k)
		}
	}
	// Направление 3: прочие device-параметры. Отдельным проходом и с отдельным
	// текстом — цена и способ починки здесь другие, чем у обфускации, и
	// сообщение обязано вести оператора к верному действию, а не пугать
	// клиентами. Ключ печатается только по имени; значение — никогда.
	for k := range device {
		if requiredDeviceKeys[strings.ToLower(k)] {
			continue // уже проверен направлением 2, с более точным сообщением
		}
		if _, ok := lookupCI(file, k); !ok {
			return fmt.Errorf(
				"device-параметр %s есть на устройстве, но отсутствует в файле — "+
					"syncconf сбрасывает поля, которых нет в применяемом конфиге (измерено на "+
					"AmneziaWG v3.0.20260730), и откат этого не вернёт: единственный рычаг отката — "+
					"тот же файл; впишите параметр в [Interface] ровно в том виде, в каком его "+
					"печатает awg showconf, либо снимите его с устройства", k)
		}
	}
	return nil
}

// lookupCI ищет ключ без учёта регистра: awg showconf и ручная правка файла
// не обязаны согласовывать регистр имени параметра.
func lookupCI(m map[string]string, key string) (string, bool) {
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

func (a *Applier) sync() error {
	stripped, err := a.r.Strip(a.confPath)
	if err != nil {
		return fmt.Errorf("awg-quick strip: %w", err)
	}
	// Никакой подстановки процессов: stdout strip уходит во временный файл,
	// чтобы ключи не попали в аргументы процесса (они видны в /proc любому,
	// кто может читать список процессов). Сам код гарантирует ровно две
	// вещи, и обе проверяются в TestSyncWritesStrippedConfToPrivateTempFile:
	// файл создаётся os.CreateTemp с правами 0600 (плюс явный Chmod ниже —
	// на случай, если umask когда-нибудь окажется мягче) и удаляется сразу
	// после syncconf.
	//
	// ИЗОЛЯЦИЯ каталога — это НЕ гарантия этого кода: os.CreateTemp("", ...)
	// пишет в общий /tmp, и от чужих процессов файл защищён только правами
	// 0600. Прежняя редакция комментария утверждала «внутри PrivateTmp» —
	// требование к systemd-юниту (PrivateTmp=yes), которого в ветке ещё нет:
	// каталог deploy/ появится задачей 12 (ревью финальное, I5). До тех пор
	// это ТРЕБОВАНИЕ К ВЫКАТУ, а не свойство кода: без PrivateTmp=yes в
	// юните гарантией остаются только права на файле.
	tmp, err := os.CreateTemp("", "awg3panel-sync-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(stripped); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return a.r.SyncConf(a.iface, tmp.Name())
}

func checkPostcondition(before, after Snapshot, exp Expect) error {
	// 6.3 device-параметры идентичны снимку — сверяем в обе стороны:
	// пропажу, изменение и появление.
	if key, reason := deviceDiff(before.Device, after.Device); key != "" {
		return fmt.Errorf("%w: device-параметр %s %s", ErrPostcondition, key, reason)
	}
	// 6.1 и 6.2 прежние пиры на месте, allowed-ips и PresharedKey те же (или
	// заявленно изменились через exp.Modified), handshake не обнулён (кроме
	// пира, которому это разрешено поимённо через HandshakeMayReset).
	for pub, was := range before.Peers {
		if exp.removed(pub) {
			continue
		}
		now, ok := after.Peers[pub]
		if !ok {
			return fmt.Errorf("%w: прежний пир %s пропал с устройства", ErrPostcondition, shortKey(pub))
		}
		// Сортируем перед сравнением: порядок allowed-ips в выводе dump не
		// гарантирован, а разный порядок при том же множестве префиксов —
		// не расхождение.
		m, isMod := exp.modified(pub)
		wantIPs := sortedJoin(was.AllowedIPs)
		if isMod && m.AllowedIPs != "" {
			wantIPs = sortedJoin(strings.Split(m.AllowedIPs, ","))
		}
		if sortedJoin(now.AllowedIPs) != wantIPs {
			return fmt.Errorf("%w: у пира %s allowed-ips не совпали с ожидаемыми",
				ErrPostcondition, shortKey(pub))
		}
		if normalizedPSK(now.PresharedKey) != normalizedPSK(was.PresharedKey) {
			return fmt.Errorf("%w: у пира %s изменился PresharedKey — обфускация/сессия с этим клиентом "+
				"будет рассогласована", ErrPostcondition, shortKey(pub))
		}
		if normalizedKeepalive(now.Keepalive) != normalizedKeepalive(was.Keepalive) {
			return fmt.Errorf("%w: у пира %s изменился PersistentKeepalive", ErrPostcondition, shortKey(pub))
		}
		if was.LatestHandshake != 0 && now.LatestHandshake == 0 && !(isMod && m.HandshakeMayReset) {
			return fmt.Errorf("%w: handshake пира %s обнулился — сессии сброшены",
				ErrPostcondition, shortKey(pub))
		}
	}
	// Симметрично: пир, появившийся на устройстве без объяснения (не был в
	// снимке «до» и не является ожидаемым добавлением) — тоже расхождение.
	// Достижимо, например, если файл на диске уже расходится с устройством
	// (ранее провалившийся откат, ручная правка) — тогда несвязанная мутация
	// попутно даёт такому пиру живой доступ.
	for pub := range after.Peers {
		if exp.added(pub) {
			continue
		}
		if _, ok := before.Peers[pub]; !ok {
			return fmt.Errorf("%w: на устройстве неожиданно появился пир %s, не запрошенный этим применением",
				ErrPostcondition, shortKey(pub))
		}
	}
	// 6.4 ожидаемое изменение произошло
	for _, pub := range exp.Added {
		now, ok := after.Peers[pub]
		if !ok {
			return fmt.Errorf("%w: новый пир %s не появился на устройстве", ErrPostcondition, shortKey(pub))
		}
		if want, checked := exp.AddedRoutes[pub]; checked && sortedJoin(want) != sortedJoin(now.AllowedIPs) {
			return fmt.Errorf("%w: маршруты нового пира %s не совпали", ErrPostcondition, shortKey(pub))
		}
	}
	for _, pub := range exp.Removed {
		if _, ok := after.Peers[pub]; ok {
			return fmt.Errorf("%w: удалённый пир %s остался на устройстве", ErrPostcondition, shortKey(pub))
		}
	}
	for _, m := range exp.Modified {
		if _, ok := after.Peers[m.PublicKey]; !ok {
			return fmt.Errorf("%w: изменённый пир %s исчез с устройства",
				ErrPostcondition, shortKey(m.PublicKey))
		}
	}
	return nil
}

// deviceDiff возвращает имя первого расходящегося device-параметра и
// причину («исчез с устройства» / «изменился» / «появился на устройстве»),
// либо "", "" если снимки идентичны. Используется и постусловием (сверка
// «после» со снимком «до»), и откатом (сверка состояния устройства после
// повторного syncconf с тем же снимком «до») — см. rollback.
func deviceDiff(before, after map[string]string) (key, reason string) {
	for k, v := range before {
		got, ok := after[k]
		if !ok {
			return k, "исчез с устройства"
		}
		if got != v {
			return k, "изменился"
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			return k, "появился на устройстве"
		}
	}
	return "", ""
}

// sortedJoin — join с предварительной сортировкой, не мутирующий исходный срез.
func sortedJoin(ips []string) string {
	s := append([]string(nil), ips...)
	for i, v := range s {
		v = strings.TrimSpace(v)
		if p, e := netip.ParsePrefix(v); e == nil {
			s[i] = p.Masked().String()
		} else if a, e := netip.ParseAddr(v); e == nil {
			s[i] = netip.PrefixFrom(a, a.BitLen()).String()
		} else {
			s[i] = v
		}
	}
	sort.Strings(s)
	return strings.Join(slices.Compact(s), ",")
}

// peerDiff возвращает публичный ключ первого расходящегося пира и причину
// («пропал с устройства» / «изменились allowed-ips» / «изменился
// PresharedKey» / «появился на устройстве»), либо "", "" если состав пиров
// идентичен. Используется откатом: после восстановления файла и повторного
// syncconf устройство обязано вернуться к тому же составу пиров, что был в
// снимке before, — иначе повторный вызов из того же файла воспроизвёл ту же
// порчу пира (см. Fake.FaultDropPeer, Fake.FaultChangePeerPSK — оба
// перманентны и срабатывают на каждом syncconf, включая откатный).
//
// Handshake сознательно НЕ сравнивается: он не описывает конфигурацию пира,
// а срабатывающий на каждом syncconf Fake.FaultResetHandshakes закономерно
// обнулит его и при повторном (откатном) вызове — это не признак того, что
// откат не удался, а ожидаемое поведение при повторной синхронизации.
func peerDiff(before, after map[string]runtime.DumpPeer) (key, reason string) {
	for pub, was := range before {
		now, ok := after[pub]
		if !ok {
			return pub, "пропал с устройства"
		}
		if reason := peerSettingsDiff(was, now); reason != "" {
			return pub, reason
		}

	}
	for pub := range after {
		if _, ok := before[pub]; !ok {
			return pub, "появился на устройстве"
		}
	}
	return "", ""
}

// shortKey укорачивает публичный ключ для сообщений: полные ключи в логи
// не пишем даже публичные — короткого префикса достаточно для опознания.
func shortKey(k string) string {
	if len(k) > 8 {
		return k[:8] + "…"
	}
	return k
}

// rollback возвращает файл из памяти и повторно синхронизирует устройство.
//
// Единственный рычаг отката на живое устройство — тот же файл, откаченный и
// прогнанный через тот же sync(). Если причина отказа в том, что сам
// syncconf исказил что-то — device-параметр ([Interface]: S1..S4, H1..H4,
// HeaderProtectionKey, ContentPaddingAddition — см. Fake.FaultDropDeviceKey)
// или конкретного пира (см. Fake.FaultDropPeer, Fake.FaultChangePeerPSK) —
// повторный вызов из того же файла воспроизведёт то же самое искажение:
// рычаг ведь один и тот же. Поэтому после успешного восстановления файла и
// повторной синхронизации мы явно проверяем, вернулось ли устройство к
// снимку before — и по device-параметрам, и по составу пиров, — и если нет,
// ошибка обязана честно сказать «файл восстановлен, устройство — нет», а не
// молча заявить об успешном откате.
func (a *Applier) rollback(before Snapshot, orig string, cause error) error {
	if err := writeAtomic(a.confPath, orig); err != nil {
		return fmt.Errorf("%w; %w: восстановите конфиг из %s вручную: %v",
			cause, ErrRollbackFailed, a.backupDir, err)
	}
	if err := a.sync(); err != nil {
		return fmt.Errorf("%w; %w: файл откачен, но повторный syncconf не удался: %v",
			cause, ErrRollbackFailed, err)
	}
	after, err := a.Snapshot()
	if err != nil {
		return fmt.Errorf("%w; %w: файл откачен, но проверить состояние устройства после отката не удалось: %v",
			cause, ErrRollbackFailed, err)
	}
	if key, reason := deviceDiff(before.Device, after.Device); key != "" {
		return fmt.Errorf("%w; %w: файл восстановлен, но device-параметр %s на устройстве %s — "+
			"требуется ручное вмешательство, повторный откат этого не исправит",
			cause, ErrRollbackFailed, key, reason)
	}
	// То же самое, но для состава пиров — расхождение по пирам, которое
	// воспроизводится и на откатном syncconf, иначе прошло бы под видом
	// «изменения откачены» ровно с той же ложью, что и для device-параметров.
	if pub, reason := peerDiff(before.Peers, after.Peers); pub != "" {
		return fmt.Errorf("%w; %w: файл восстановлен, но пир %s на устройстве %s — "+
			"требуется ручное вмешательство, повторный откат этого не исправит",
			cause, ErrRollbackFailed, shortKey(pub), reason)
	}
	return fmt.Errorf("%w; изменения откачены", cause)
}

func (a *Applier) backup(orig string) error {
	if err := os.MkdirAll(a.backupDir, 0o700); err != nil {
		return err
	}
	// Счётчик в имени нужен потому, что разрешение системного таймера на
	// Windows — миллисекунды: две мутации подряд получили бы одно имя,
	// и второй бэкап затёр бы первый.
	a.seq++
	// Имя — по файлу конфига, а не «awg3.conf» для всех: у awgref/awgtop
	// бэкап awg3.conf.* в их же каталоге вводил в заблуждение при ручном
	// восстановлении (аудит 07.09.2026).
	tmp, err := os.CreateTemp(a.backupDir, ".config-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err := tmp.WriteString(orig); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if _, err := publishBackup(tmp.Name(), a.backupDir, filepath.Base(a.confPath), "", a.now(), a.seq); err != nil {
		return err
	}

	a.pruneBackups()
	return nil
}

func (a *Applier) pruneBackups() {
	entries, err := os.ReadDir(a.backupDir)
	if err != nil {
		return
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Type().IsRegular() && backupName(e.Name(), filepath.Base(a.confPath), "") {
			names = append(names, e.Name())
		}
	}
	if len(names) <= maxBackups {
		return
	}
	sort.Strings(names) // имена содержат UTC-таймштамп, лексикографический порядок = хронологический
	for _, n := range names[:len(names)-maxBackups] {
		_ = os.Remove(filepath.Join(a.backupDir, n))
	}
}

// writeAtomic — имя, под которым эту функцию вызывает остальной apply.go (и
// продолжит вызывать задача 13). Реализация вынесена в atomic.go как
// writeFileAtomic0600, чтобы её мог использовать и KeyStore (keys.go).
func writeAtomic(path, body string) error {
	return writeFileAtomic0600(path, body)
}

func (a *Applier) recoverPeerMutation(before, next string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := assertInterfaceUntouched(before, next); err != nil {
		return err
	}
	current, err := os.ReadFile(a.confPath)
	if err != nil {
		return err
	}
	if string(current) != before && string(current) != next {
		return fmt.Errorf("%w: серверный файл изменён вне незавершённой операции", ErrStateConflict)
	}
	want, err := configuredPeers(before)
	if err != nil {
		return err
	}
	live, err := a.Snapshot()
	if err != nil {
		return err
	}
	if err := assertFileMatchesDevice(live.Device, before); err != nil {
		return err
	}
	if key, _ := peerDiff(want, live.Peers); key == "" {
		if string(current) == before {
			return nil
		}
		return writeAtomic(a.confPath, before)
	}
	proposed, err := configuredPeers(next)
	if err != nil {
		return err
	}
	// A killed sync may have changed only some target peers. Refuse any
	// change to peers outside this transaction, including a live-only peer.
	for key, was := range want {
		candidate, kept := proposed[key]
		if kept && peerSettingsDiff(was, candidate) == "" {
			if current, found := live.Peers[key]; !found || peerSettingsDiff(was, current) != "" {
				return fmt.Errorf("%w: обнаружено стороннее изменение пира %s", ErrStateConflict, shortKey(key))
			}
		}
	}
	for key := range live.Peers {
		if _, existed := want[key]; existed {
			continue
		}
		if _, added := proposed[key]; !added {
			return fmt.Errorf("%w: обнаружен сторонний пир %s", ErrStateConflict, shortKey(key))
		}
	}
	if err := writeAtomic(a.confPath, before); err != nil {
		return err
	}
	if err := a.sync(); err != nil {
		return err
	}
	after, err := a.Snapshot()
	if err != nil {
		return err
	}
	if key, reason := deviceDiff(live.Device, after.Device); key != "" {
		return fmt.Errorf("после восстановления device-параметр %s %s", key, reason)
	}
	if key, reason := peerDiff(want, after.Peers); key != "" {
		return fmt.Errorf("после восстановления пир %s: %s", shortKey(key), reason)
	}
	return nil
}
