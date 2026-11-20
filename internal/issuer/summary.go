package issuer

import (
	"fmt"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/store"
)

// OnlineWindow — возраст хендшейка, до которого пир считается живым.
// Три минуты, а не «сколько-нибудь»: RejectAfterTime у AmneziaWG 3.1
// доходит до 195 секунд, и живой пир с редким трафиком не должен мигать
// «оффлайн» между сессионными обновлениями.
const OnlineWindow = 180 * time.Second

// StaleAfter — возраст хендшейка, после которого пир попадает в
// «нет связи»: интервал, заметный человеку, а не порог протокола.
const StaleAfter = 24 * time.Hour

// PeerStat — то, что агрегатору нужно знать про одного пира. Отдельный тип,
// а не PeerView: агрегация обязана проверяться тестом без файловой системы и
// без живого сервера, а PeerView тянет за собой оверрайды и хранилище.
type PeerStat struct {
	Name             string
	Enabled          bool
	LastHandshake    int64
	RxBytes, TxBytes int64
}

// IfaceSummary — состояние интерфейса целиком, то, что консоль показывает
// плитками. Нигде не сохраняется: это производная живого состояния, и
// файла с застывшим результатом не существует.
type IfaceSummary struct {
	Interface         string `json:"interface"`
	ListenPort        int    `json:"listen_port"`
	PublicKey         string `json:"public_key"`
	MTU               string `json:"mtu"`
	PeersTotal        int    `json:"peers_total"`
	PeersOnline       int    `json:"peers_online"`
	PeersStale        int    `json:"peers_stale"`
	PeersNever        int    `json:"peers_never"`
	RxBytes           int64  `json:"rx_bytes"`
	TxBytes           int64  `json:"tx_bytes"`
	LastHandshake     int64  `json:"last_handshake"`
	LastHandshakePeer string `json:"last_handshake_peer"`
	// Version — вывод `amneziawg-go --version` бинаря, обслуживающего этот
	// интерфейс. omitempty: пустое поле в консоли не показывается вовсе —
	// пустое место честнее слова "неизвестно", которое ничего не значит.
	Version string `json:"version,omitempty"`
	// MimicryMismatch — предупреждение раздела 5.6 спеки 2026-08-25: непусто,
	// когда в умолчаниях интерфейса есть I1, а порт живого интерфейса не
	// соответствует профилю, которым I1 опознаётся (mimicryMismatch ниже), —
	// или не соответствует вообще ничему. omitempty по тому же рассуждению,
	// что и у Version: согласованная пара или отсутствующий I1 — это "нечего
	// показывать", а не "неизвестно".
	MimicryMismatch string `json:"mimicry_mismatch,omitempty"`
	// ConfigWarnings — нарушения правил AWG 3.x в живом [Interface]
	// (interfaceWarnings, спека 2026-10-29, раздел 3). Только чтение:
	// панель [Interface] не правит (правило 2), оператор чинит руками.
	ConfigWarnings []string `json:"config_warnings,omitempty"`
}

// summarize — вся арифметика сводки в одном месте, с временем параметром.
// Время инъецируется не ради чистоты: пороги здесь — границы (180 секунд,
// 24 часа), и проверить поведение РОВНО НА границе можно только тестом с
// фиксированным «сейчас».
//
// Выключенный пир учитывается АСИММЕТРИЧНО, и это не небрежность:
//   - его трафик входит в суммы — эти байты через сервер реально прошли, и
//     вычесть их значило бы показать оператору цифру, не совпадающую с
//     awg show;
//   - в категории (онлайн / нет связи / никогда) он не попадает — «выключен»
//     это отдельное состояние, а не разновидность аварии;
//   - в «последнюю активность» он тоже не попадает: выключенный пир снят с
//     живого сервера, и его последний хендшейк — археология, а не ответ на
//     вопрос «когда интерфейсом last пользовались».
//
// Отсюда порядок внутри цикла: суммы считаются ДО отсева выключенных,
// максимум хендшейка и категории — ПОСЛЕ.
func summarize(now time.Time, iface string, dev runtime.DumpDevice, mtu string, peers []PeerStat) IfaceSummary {
	s := IfaceSummary{
		Interface:  iface,
		ListenPort: dev.ListenPort,
		PublicKey:  dev.PublicKey,
		MTU:        mtu,
		PeersTotal: len(peers),
	}
	onlineFrom := now.Add(-OnlineWindow).Unix()
	staleBefore := now.Add(-StaleAfter).Unix()
	for _, p := range peers {
		s.RxBytes += p.RxBytes
		s.TxBytes += p.TxBytes
		if !p.Enabled {
			continue
		}
		if p.LastHandshake > s.LastHandshake {
			s.LastHandshake = p.LastHandshake
			s.LastHandshakePeer = p.Name
		}
		switch {
		case p.LastHandshake == 0:
			s.PeersNever++
		case p.LastHandshake >= onlineFrom:
			s.PeersOnline++
		case p.LastHandshake < staleBefore:
			s.PeersStale++
		}
	}
	return s
}

// Summary собирает состояние интерфейса. Делает ОДИН вызов awg show — тот же
// самый, что делает List: сводка и список запрашиваются консолью отдельными
// запросами, и складывать их в один вызов значило бы связать два независимых
// маршрута общим кэшем ради экономии одного exec.
func (s *Service) Summary() (IfaceSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, c, err := s.readConf()
	if err != nil {
		return IfaceSummary{}, err
	}
	st, err := s.loadState(raw, c)
	if err != nil {
		return IfaceSummary{}, err
	}
	dumpText, err := s.r.Show(s.iface.Interface)
	if err != nil {
		return IfaceSummary{}, fmt.Errorf("awg show: %w", err)
	}
	dev, err := runtime.ParseDumpDevice(dumpText)
	if err != nil {
		return IfaceSummary{}, err
	}
	dump, err := runtime.ParseDump(dumpText)
	if err != nil {
		return IfaceSummary{}, err
	}
	live := make(map[string]runtime.DumpPeer, len(dump))
	for _, p := range dump {
		live[p.PublicKey] = p
	}

	stats := make([]PeerStat, 0, len(st.Peers))
	for _, p := range st.Peers {
		ps := PeerStat{Name: p.Name, Enabled: p.Enabled}
		if d, ok := live[p.PublicKey]; ok {
			ps.LastHandshake, ps.RxBytes, ps.TxBytes = d.LatestHandshake, d.RxBytes, d.TxBytes
		}
		stats = append(stats, ps)
	}
	sum := summarize(time.Now(), s.iface.Interface, dev, c.Interface.Get("MTU"), stats)
	sum.MimicryMismatch = mimicryMismatch(dev.ListenPort, s.currentSignature())
	sum.ConfigWarnings = interfaceWarnings(c.Interface)
	// В отличие от Show() выше (тоже внешний процесс, но выполняется на
	// КАЖДЫЙ вызов Summary), readVersion под этим же мьютексом ждёт запуска
	// внешнего процесса только при первом обращении за жизнь процесса —
	// дальше отдаёт кэш. Не считать залоченные секции этого файла дешёвыми
	// по умолчанию: здесь под одной блокировкой соседствуют и память/диск, и
	// exec.
	sum.Version = s.readVersion()
	return sum, nil
}

// readVersion возвращает кэшированную версию бинаря amneziawg-go, при
// необходимости запрашивая её у Runner ровно один раз (см. комментарий у
// полей Service.version/versionRead). Вызывать только под s.mu — как
// readConf и loadState, sync.Mutex здесь не реентрантен.
//
// Ошибка не пробрасывается наружу нарочно: это единственный НОВЫЙ вызов к
// серверу во всей задаче про сводку, и его отказ не должен срывать всю
// остальную, давно работающую сводку. Пустая строка честнее и подсказки об
// отказе, которая тут же устареет, и повторных попыток на каждый опрос
// консоли.
func (s *Service) readVersion() string {
	if !s.versionRead {
		if v, err := s.r.Version(); err == nil {
			s.version = v
		}
		s.versionRead = true
	}
	return s.version
}

// currentSignature читает I1 из умолчаний интерфейса, если они уже есть на
// диске, БЕЗ бутстрапа. В отличие от s.defaults() (service.go), который при
// первом обращении СОЗДАЁТ defaults.json и сеет I1 профилем по порту
// (mimicrySeedFor) — то есть пишет на диск и вызывает crypto/rand, — этот
// метод только читает. Разница принципиальна: Summary() вызывается
// БЕЗУСЛОВНО в обеих сборках панели (это PeerLister.Summary, доступный и
// read-only бинарю без единого обработчика мутации, см.
// internal/web/server.go), а s.defaults() сегодня зовётся только из
// пишущих обработчиков (handlers_mutate.go) и только там имеет право сеять
// новый пакет. Если бы Summary() вызывала s.defaults(), read-only панель
// начала бы создавать файлы и генерировать случайные данные от одного
// открытия вкладки "Сводка" — это тихо стёрло бы границу между "показать
// состояние" и "изменить состояние", которую весь read-only-режим и
// проводит.
//
// Ошибка чтения (файла ещё нет, JSON битый) не пробрасывается наружу —
// тем же рассуждением, что и у readVersion выше: предупреждение о профиле
// мимикрии не настолько важно, чтобы ронять всю остальную, давно
// работающую сводку. Пустая строка здесь означает "I1 нечем опознать",
// что mimicryMismatch и так трактует как "сравнивать не с чем" (см. её
// комментарий).
//
// Вызывать только под s.mu — Summary() уже держит его на всё время своего
// тела, а store.LoadDefaults читает файл, который SetDefaults и s.defaults()
// пишут под тем же мьютексом.
func (s *Service) currentSignature() string {
	d, _, err := store.LoadDefaults(s.iface.DefaultsPath(), store.Defaults{})
	if err != nil {
		return ""
	}
	return d.Extra["I1"]
}

// mimicryMismatch — раздел 5.6 спеки 2026-08-25: предупреждение оператору,
// когда лежащий в умолчаниях I1 имитирует протокол, для которого порт живого
// интерфейса не подходит. Порт при этом НЕ меняется и меняться не может
// (правило 2 репозитория) — это только предупреждение, а не исправление.
//
// Пустой результат — "предупреждать не о чем": либо I1 согласован с портом,
// либо сравнивать вообще не с чем (I1 не задан, DetectProfile его не узнал —
// например, defaults.json заполнен руками до появления профилей мимикрии).
// DetectProfile("") и DetectProfile("мусор") дают одинаковое false, и оба
// трактуются одинаково: "нечего сравнивать", а НЕ "точно несогласовано" —
// раздел 5.6 явно требует не путать эти два случая.
func mimicryMismatch(port int, i1 string) string {
	profile, ok := DetectProfile(i1)
	if !ok {
		return ""
	}
	canonical, _ := PortForProfile(profile) // profile всегда из profilePort — DetectProfile не возвращает ничего другого.
	if canonical == port {
		return ""
	}
	return fmt.Sprintf(
		"порт %d не соответствует профилю %s — сигнатурный пакет здесь не маскирует, а выделяет; профиль %s работает на порту %d",
		port, profile, profile, canonical)
}
