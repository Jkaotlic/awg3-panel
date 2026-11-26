package issuer

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/store"
	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

// ErrInvalidInput и ErrNotFound помечают ошибки, вызванные ЗАПРОСОМ
// пользователя, а не состоянием сервера: пустое имя, имя длиннее предела,
// неизвестный id. Их текст сочинён здесь целиком и не содержит ни ключей,
// ни PSK, ни путей — поэтому web-слой вправе показать его пользователю
// (4xx). Всё остальное — внутренние ошибки: наружу уходит родовая
// формулировка, подробности только в лог (см. web.writeError, защита из
// ревью Task 11).
var (
	ErrInvalidInput = errors.New("некорректные данные запроса")
	ErrNotFound     = errors.New("пир не найден")
)

// ErrStateConflict помечает расхождение peers.json с живым устройством,
// обнаруженное ДО применения мутации (см. checkRotateStateMatchesServer) —
// находка финального ревью I4. Не ErrInvalidInput: то, что прислал
// оператор, тут ни при чём — расхождение возникло раньше, само по себе. Не
// ErrPostcondition (apply.go): та означает «мутация УЖЕ применена к
// устройству, а после проверки состояние разошлось со снимком, изменения
// откачены» — здесь же применения не было вовсе, отказ ранний и объяснимый.
// Раньше эта ошибка была обёрнута именно в ErrPostcondition, statusFor давала
// ей 500, а writeError на 5xx стирает текст в «внутренняя ошибка» — причина
// уходила только в journal, оператор её не видел. Собственный класс даёт
// собственный (4xx) код в statusFor: 409 подходит по смыслу «состояние
// конфликтует», а не «сломалось что-то внутри».
var ErrStateConflict = errors.New("состояние пира разошлось с сервером")

type Service struct {
	iface   config.Interface
	listen  string
	r       runtime.Runner
	applier *Applier
	// keys — хранилище приватных ключей клиентских пиров (задача 4).
	// Появилось вместе с задачей 5: клиентский .conf больше не хранится
	// файлом в Storage.ClientConfigs, а собирается заново при каждой выдаче
	// из этого ключа, живого [Interface] сервера, оверрайдов пира и
	// умолчаний интерфейса (раздел 5.2 спеки).
	keys *KeyStore

	// stateSeq — счётчик в именах снимков состояния (snapshot, statebackup.go):
	// две мутации в одну секунду не должны давать одно имя.
	stateSeq int

	// defaultsLoggedOnce ограничивает строку про игнорируемую секцию client
	// (см. defaults() ниже) ОДНИМ разом за жизнь процесса на этот интерфейс.
	// defaults() дёргается лениво — из Add, Rotate, configFor и экспортированного
	// Defaults() — сколько угодно раз за время работы панели, и log.Printf без
	// этой защиты на каждый вызов заспамил бы журнал (находка ревью задачи 16).
	defaultsLoggedOnce sync.Once

	// version, versionRead — кэш версии бинаря amneziawg-go (задача 10).
	// Версия не меняется без рестарта сервиса, а Summary опрашивается
	// консолью раз в 10 секунд — второй и все последующие вызовы обязаны
	// брать значение отсюда, не трогая Runner. versionRead взводится и при
	// успехе, и при отказе чтения: отказ тоже кэшируется навсегда, иначе
	// недоступный бинарь (снесли пакет, отобрали права) заново дёргал бы exec
	// на КАЖДОМ опросе консоли — то самое злоупотребление, ради которого
	// задача помечена особо бережной. version в этом случае остаётся пустым.
	version     string
	versionRead bool

	// mu даёт согласованный снимок читателям внутри процесса и сериализует
	// выбор адреса, изменение устройства и сохранение метаданных.
	// beginWrite добавляет межпроцессную блокировку для CLI и демона.
	mu sync.Mutex
}

func New(iface config.Interface, listen string, r runtime.Runner) *Service {
	return &Service{
		iface:   iface,
		listen:  listen,
		r:       r,
		applier: NewApplier(r, iface.Interface, iface.Config, iface.Storage.Backups),
		keys:    NewKeyStore(iface.Storage.Keys),
	}
}

// Defaults читает умолчания интерфейса, при первом обращении создавая файл
// из секции client конфига. Ошибка чтения не роняет путь выдачи: она
// логируется, и панель работает на сиде — иначе один битый JSON лишил бы
// оператора доступа ко всем конфигам разом.
//
// Карта Extra в возвращаемом значении клонируется (cloneExtra) вторым
// рубежом защиты, а не потому что достижимый сегодня баг живёт здесь: сам
// алиасинг устранён в store.LoadDefaults (её ветка «файла ещё нет» —
// единственная, где он в принципе возможен, — теперь тоже клонирует, см.
// internal/store/defaults.go). Здесь seed вдобавок никогда не несёт
// непустую Extra: у config.Client, из которого он строится, такого поля
// нет вовсе. Клон оставлен на будущее — если LoadDefaults когда-нибудь
// перестанет копировать защитно (например, оптимизация переиспользует
// карту), эта строка не даст регрессии дотянуться до вызывающего кода
// (находка ревью «Долг задачи 2», task-5-report.md: раздел «Правки после
// ревью»).
//
// Берёт s.mu — отложенная находка ревью задачи 5: метод экспортирован, но
// до задачи 10 не брал мьютекс сам, и это было безопасно только потому, что
// ВСЕ тогдашние вызывающие (Add, Rotate, configFor) уже держали s.mu сами.
// GET /api/ifaces/{iface}/defaults (задача 10, web.handleGetDefaults) —
// первый вызывающий СНАРУЖИ пакета issuer, который s.mu подержать не может
// (поле не экспортировано), и его bootstrap-запись — создание defaults.json
// из сида при первом обращении, ниже — гонялась бы с одновременным
// SetDefaults: конкурентный PUT успевает сохранить присланные оператором
// умолчания, а GET, всё ещё выполняющий ветку created, следом перезаписывает
// их сидом из config.yaml поверх. Захват мьютекса здесь закрывает именно
// это окно. Выбор варианта — не «отдельный публичный метод», а именно лок в
// самом Defaults: два экспортируемых имени с разной семантикой блокировки
// («быстрый» и «безопасный Defaults») выглядели бы как случайность вызова
// не того метода, а не как осознанный контракт.
func (s *Service) Defaults() store.Defaults {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readDefaults(false)
}

// defaults — тело Defaults БЕЗ захвата мьютекса. sync.Mutex не реентрантен:
// вызывать эту версию можно только из кода, который s.mu уже держит сам
// (Add, Rotate, configFor — все трое сериализованы через s.mu.Lock() в
// начале своего тела). Второй Lock изнутри этих методов, если бы они звали
// экспортированный Defaults(), — гарантированный deadlock, а не гонка.
func (s *Service) defaults() store.Defaults { return s.readDefaults(true) }

func (s *Service) readDefaults(persist bool) store.Defaults {
	d, _ := s.readDefaultsWithOrigin(persist)
	return d
}

// readDefaultsWithOrigin reports whether the settings came from the seed.
func (s *Service) readDefaultsWithOrigin(persist bool) (store.Defaults, bool) {
	seed := store.Defaults{
		Endpoint: s.iface.Client.Endpoint, AllowedIPs: s.iface.Client.AllowedIPs,
		Keepalive: s.iface.Client.PersistentKeepalive, DNS: s.iface.Client.DNS,
		Jc: s.iface.Client.Jc, Jmin: s.iface.Client.Jmin, Jmax: s.iface.Client.Jmax,
	}
	d, created, err := store.LoadDefaults(s.iface.DefaultsPath(), seed)
	if err != nil {
		log.Printf("умолчания интерфейса %s: %v — работаю на значениях из config.yaml", s.iface.ID, err)
		seed.Version = store.DefaultsVersion
		return seed, false
	}
	if created {
		// Existing defaults are authoritative. A rejected seed stays in
		// config.yaml so correcting it is enough to retry issuance.
		if err := ValidateDefaults(*d); err != nil {
			if persist {
				log.Printf("умолчания интерфейса %s из config.yaml не сохранены: %v", s.iface.ID, err)
			}
			return *d, false
		}
		// I1 сеется ТОЛЬКО здесь, в ветке "файла ещё не было": defaults.json,
		// уже существующий на диске, ниже (ветка else) не трогается ни на одно
		// поле — умолчания работающего интерфейса меняет оператор, а не
		// апгрейд панели (CLAUDE.md, раздел «Боевая эксплуатация»). Поле
		// ОДНОСТОРОННЕЕ (README amneziawg-go — "no need to specify it on both
		// sides"), сервер о нём не знает, поэтому взять его заранее для
		// нового интерфейса можно без риска расхождения с сервером.
		//
		// С задачи 3 (спека 2026-08-25, раздел 5.5) пакет — не безусловный
		// DNS, а профиль, выведенный из ПОРТА интерфейса: сигнатурный пакет
		// имитирует конкретный протокол, и имитация без согласованного порта
		// не просто бесполезна, а вредна (DNS-пакет на udp/52441 не прячет
		// туннель, а выделяет его). Если профиль по порту не выводится —
		// I1 не сеется вовсе, что не хуже поведения панели до этой задачи.
		if i1, reason := s.mimicrySeedFor(rand.Reader); reason == "" {
			if d.Extra == nil {
				d.Extra = map[string]string{}
			}
			d.Extra["I1"] = i1
		} else {
			log.Printf("умолчания нового интерфейса %s: I1 не посеян — %s", s.iface.ID, reason)
		}
		if persist {
			if err := d.Save(s.iface.DefaultsPath()); err != nil {
				log.Printf("создание defaults.json для %s: %v", s.iface.ID, err)
			}
		}
	} else {
		// Файл уже существовал ДО этого вызова — секция client интерфейса в
		// config.yaml была сидом только при первом запуске и с этого момента
		// молча игнорируется. Печатаем это разово, а не на каждый вызов
		// defaults() — см. комментарий у поля Service.defaultsLoggedOnce.
		s.defaultsLoggedOnce.Do(func() {
			log.Printf("интерфейс %s: умолчания клиента читаются из %s — секция client в "+
				"config.yaml учтена только как сид при первом запуске и теперь игнорируется",
				s.iface.ID, s.iface.DefaultsPath())
		})
	}
	out := *d
	out.Extra = cloneExtra(d.Extra)
	return out, created
}

// mimicrySeedFor решает, каким профилем мимикрии засеять I1 нового
// интерфейса (спека 2026-08-25, раздел 5.5), и генерирует пакет источником
// rnd. Пустая reason означает успех — i1 тогда несёт готовый пакет; непустая
// reason объясняет, почему сеять нечего, и в этом случае i1 всегда "".
//
// Порт читается ТЕМ ЖЕ способом, каким его берёт сводка (Summary,
// summary.go): awg show <iface> dump → runtime.ParseDumpDevice. Значит,
// интерфейс обязан быть поднят на момент первого создания defaults.json —
// если это ещё не так (панель стартовала раньше туннеля) или устройство
// недоступно по любой другой причине, узнать порт неоткуда, и метод ведёт
// себя ровно так же, как при «профиля для порта нет»: посеять сигнатурный
// пакет наугад хуже, чем не посеять вовсе, а осиротевший I1 оператор досеет
// кнопкой из консоли, когда порт станет известен.
func (s *Service) mimicrySeedFor(rnd io.Reader) (i1, reason string) {
	// s.r нарочно не проверяется на nil: единственный конструктор,
	// собирающий боевой Service (New, internal/issuer/registry.go), всегда
	// передаёт настоящий Runner — nil здесь означал бы баг в вызывающем
	// коде, а не эксплуатационный случай, который стоит различать отдельной
	// веткой и отдельным текстом в логе. Отсутствующий Runner паникует на
	// s.r.Show ниже так же, как паникует любой другой из полутора десятков
	// вызовов s.r.* в пакете (summary.go, apply.go, mutate.go) — их
	// симметрия важнее, чем избирательная защита одного вызывающего.
	dumpText, err := s.r.Show(s.iface.Interface)
	if err != nil {
		return "", fmt.Sprintf(
			"не удалось прочитать порт интерфейса (awg show: %v) — поднимите интерфейс и досейте I1 кнопкой в консоли",
			err)
	}
	dev, err := runtime.ParseDumpDevice(dumpText)
	if err != nil {
		return "", fmt.Sprintf(
			"не удалось прочитать порт интерфейса (%v) — поднимите интерфейс и досейте I1 кнопкой в консоли",
			err)
	}
	profile, ok := ProfileForPort(dev.ListenPort)
	if !ok {
		// Оборот "выбрав профиль вручную" убирался в c6f8a36 (ревью этой же
		// ветки): на тот момент выбора профиля в веб-слое не было вовсе, и
		// подсказка обещала бы то, чего кнопка не умела. Задача 5 добавила
		// селектор профиля рядом с обеими кнопками "Сгенерировать I1"
		// (вкладка «Умолчания» и модалка правки пира, index.html) — выбор
		// появился, и обещание снова верно. Не удалять эту фразу второй раз
		// без того, чтобы сперва проверить, что селектор всё ещё существует.
		return "", fmt.Sprintf(
			"порт %d не соответствует ни одному профилю мимикрии — при необходимости досейте I1 кнопкой в консоли, выбрав профиль вручную",
			dev.ListenPort)
	}
	packet, err := GenerateSignatureFor(rnd, profile)
	if err != nil {
		return "", fmt.Sprintf(
			"генератор профиля %s: %v — повторите кнопкой в консоли",
			profile, err)
	}
	return packet, ""
}

// cloneExtra возвращает независимую копию карты дополнительных client-side
// полей — см. комментарий у Defaults.
func cloneExtra(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// SetDefaults сохраняет умолчания интерфейса после проверки ValidateDefaults
// (задача 3). Берёт s.mu не ради защиты собственного состояния Service (его
// здесь нет — умолчания живут только на диске), а чтобы конкурентная запись
// не гонялась сама с собой за одним и тем же defaults.json.
func (s *Service) SetDefaults(d store.Defaults) error {
	if err := ValidateDefaults(d); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer lock.Close()

	if err := s.snapshot(); err != nil {
		return err
	}
	return d.Save(s.iface.DefaultsPath())
}

// PeerView — то, что видит веб-интерфейс. Полных публичных ключей здесь
// нет: для опознания достаточно префикса, а показывать больше незачем.
//
// Overrides добавлен задачей 11: форма правки пира показывает плейсхолдером
// наследуемое из умолчаний значение и текущий персональный оверрайд поверх
// него, а PATCH ничего не возвращает, кроме {"status":"ok"} — List() здесь
// единственный источник. nil (в JSON — поле отсутствует благодаря omitempty)
// значит «оверрайдов нет вовсе», а не «оверрайды пустые»: то же самое
// различие, которое store.Overrides хранит указателями внутри себя (см. её
// комментарий), обязано пережить дорогу до браузера.
type PeerView struct {
	ID             string           `json:"id"`
	Name           string           `json:"name"`
	Address        string           `json:"address"`
	PublicKeyShort string           `json:"public_key_short"`
	Enabled        bool             `json:"enabled"`
	LastHandshake  int64            `json:"last_handshake"`
	RxBytes        int64            `json:"rx_bytes"`
	TxBytes        int64            `json:"tx_bytes"`
	NeverConnected bool             `json:"never_connected"`
	CreatedAt      string           `json:"created_at"`
	Overrides      *store.Overrides `json:"overrides,omitempty"`
}

// readConf разбирает серверный конфиг с диска.
func (s *Service) readConf() (string, *wgconf.Config, error) {
	b, err := os.ReadFile(s.iface.Config)
	if err != nil {
		return "", nil, fmt.Errorf("чтение %s: %w", s.iface.Config, err)
	}
	c, err := wgconf.Parse(string(b))
	if err != nil {
		return "", nil, fmt.Errorf("разбор %s: %w", s.iface.Config, err)
	}
	return string(b), c, nil
}

func (s *Service) resolvedState(raw string, c *wgconf.Config) (*store.State, error) {
	st, err := store.Load(s.iface.Storage.State)
	if err != nil {
		return nil, err
	}

	addrOf := map[string]string{}
	nameOf := map[string]string{}
	var pubs []string
	for _, p := range c.Peers {
		pub := p.Get("PublicKey")
		pubs = append(pubs, pub)
		assigned := ""
		if previous, ok := st.ByPublicKey(pub); ok {
			assigned = previous.AssignedAddress
		}
		addrOf[pub], _ = primaryHost(c.Interface.Get("Address"), p.AllowedIPEntries(), assigned)
		// Имя берётся из ЛЮБОГО комментария блока, а не только из своего
		// «# awg3panel: <имя>» (wgconf.PeerName). Прежний разбор узнавал
		// ровно те имена, которые панель написала сама, — то есть пиру,
		// заведённому руками до её установки, имя не доставалось никогда,
		// и он показывался как «peer-<12 hex>». Цена этого выяснилась на
		// боевом awg3: удаление подтверждается вводом имени символ в
		// символ, поэтому пять пиров из шести оказались практически неудаляемыми.
		if n := wgconf.PeerName(p, raw); n != "" {
			nameOf[pub] = n
		}
	}
	st.Reconcile(pubs, func(pub string) string { return addrOf[pub] })
	// Имя из комментария имеет приоритет над сгенерированным peer-<id>,
	// но не затирает имя, заданное пользователем через панель.
	for i := range st.Peers {
		p := &st.Peers[i]
		if addr, ok := addrOf[p.PublicKey]; ok {
			p.Address = addr
			p.SavedRoutes = nil
			p.SavedEndpoint = ""
			p.SavedKeepalive = ""
		}
		if n, ok := nameOf[p.PublicKey]; ok && strings.HasPrefix(p.Name, "peer-") {
			p.Name = n
		}
	}

	return st, nil
}

// List читает состав пиров и живой статус без записи метаданных.
func (s *Service) List() ([]PeerView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	guard, err := s.beginRead()
	if err != nil {
		return nil, err
	}

	defer guard.close()
	raw, c, err := s.readConf()
	if err != nil {
		return nil, err
	}
	st, err := s.resolvedState(raw, c)
	if err != nil {
		return nil, err
	}
	dumpText, err := s.r.Show(s.iface.Interface)
	if err != nil {
		return nil, fmt.Errorf("awg show: %w", err)
	}
	dump, err := runtime.ParseDump(dumpText)
	if err != nil {
		return nil, err
	}
	live := make(map[string]runtime.DumpPeer, len(dump))
	for _, p := range dump {
		live[p.PublicKey] = p
	}

	views := make([]PeerView, 0, len(st.Peers))
	for _, p := range st.Peers {
		v := PeerView{
			ID: p.ID, Name: p.Name, Address: p.Address,
			PublicKeyShort: shortKey(p.PublicKey),
			Enabled:        p.Enabled, CreatedAt: p.CreatedAt,
			// Указатель делится тем же объектом, что лежит в st.Peers, а не
			// клонируется: ничего не мутирует Overrides НА МЕСТЕ (Update
			// переставляет указатель pp.Overrides = patch.Overrides целиком,
			// см. её комментарий), поэтому alias безопасен даже после
			// возврата List() и снятия мьютекса.
			Overrides: p.Overrides,
		}
		if d, ok := live[p.PublicKey]; ok {
			v.LastHandshake = d.LatestHandshake
			v.RxBytes, v.TxBytes = d.RxBytes, d.TxBytes
		}
		// Отключённый пир не «никогда не подключался» — он просто выключен.
		v.NeverConnected = p.Enabled && v.LastHandshake == 0
		views = append(views, v)
	}
	sort.Slice(views, func(i, j int) bool {
		return addrLess(views[i].Address, views[j].Address)
	})
	if err := guard.validate(); err != nil {
		return nil, err
	}
	return views, nil
}

// addrLess сравнивает адреса численно, чтобы 10.11.0.10 шёл после 10.11.0.9,
// а не между .1 и .2, как при строковой сортировке.
//
// Порядок обязан быть тотальным — sort.Slice требует строгий слабый
// порядок и при его нарушении не паникует, а молча даёт неопределённый
// результат. Прежняя версия сравнивала ЦЕЛИКОМ строково, если хотя бы один
// из двух адресов не разбирался, и это ловило цикл: A="10.11.0.9"
// (разбирается) < B="10.11.0.10" (разбирается) — численно, но B < C и
// C < A для неразбираемого C — строково (ревью Task 10, Finding 1).
// addrOf[pub] в loadState может быть пустой строкой (у пира в конфиге нет
// AllowedIPs) — она тоже не разбирается, так что триггер реален, а не
// гипотетический.
//
// Разбиение по случаям: оба разбираются → численно; ровно один не
// разбирается → он идёт ПОСЛЕ разбираемого, с какой бы стороны вызова ни
// оказался; оба не разбираются → строковый тай-брейк. Это тотальный
// порядок: иррефлексивность, асимметрия и транзитивность проверены на
// разбираемых и неразбираемых адресах в TestAddrLess* (service_internal_test.go).
func addrLess(a, b string) bool {
	ia, ea := netip.ParseAddr(HostIP(a))
	ib, eb := netip.ParseAddr(HostIP(b))
	switch {
	case ea == nil && eb == nil:
		return ia.Less(ib)
	case ea == nil:
		return true // a разбирается, b — нет: разбираемые всегда раньше
	case eb == nil:
		return false // a не разбирается, b разбирается: a идёт позже
	default:
		return a < b // оба не разбираются — строковый тай-брейк
	}
}

// ListenAddr возвращает адрес, на котором слушает демон (s.listen — то же
// значение cfg.Listen, с которым Service был создан через New).
//
// Единственный потребитель — CLI-мутации (cmd/awg3panel/cli.go,
// refuseIfDaemonRunning, Task 14): Service.mu (см. комментарий к полю)
// сериализует мутации только внутри ОДНОГО процесса, а CLI-команда — это
// отдельный процесс со своим экземпляром Service и своим мьютексом. Чтобы
// CLI мог хотя бы посоветоваться сам с собой о том, не занят ли этот адрес
// демоном, ему нужен доступ к этому значению — без протаскивания
// *config.Config через сигнатуру runCLI, которая фиксирована планом задачи.
func (s *Service) ListenAddr() string {
	return s.listen
}

// ServerPublicKey вычисляет публичный ключ сервера из приватного через
// awg pubkey — единый источник, без отдельного .pub-файла, который может
// разъехаться с конфигом (раздел 7.3 спеки).
func (s *Service) ServerPublicKey() (string, error) {
	_, c, err := s.readConf()
	if err != nil {
		return "", err
	}
	priv := c.Interface.Get("PrivateKey")
	if priv == "" {
		return "", fmt.Errorf("в серверном [Interface] нет PrivateKey")
	}
	return s.r.PubKey(priv)
}

// --- Мутации (Task 13). Любая из них проходит через Applier.Apply, то есть
// через полный инвариант раздела 6 спеки: снимок → бэкап → атомарная запись →
// syncconf → проверка постусловия → откат при расхождении. Обхода нет и не
// должно появиться: awg3.conf меняется только текстовой хирургией блоков
// [Peer] из wgconf, секция [Interface] копируется побайтово. ---

// Issued — результат выпуска пира.
type Issued struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Config  string `json:"config"`
	QRPNG   []byte `json:"-"`
}

const maxNameLen = 40

// validateName приводит имя к каноническому виду и отвергает то, что нельзя
// записать в конфиг. Сообщения об ошибках НЕ повторяют само имя: оно уедет в
// лог через writeError, а лог — не место для пользовательских данных сверх
// необходимого (CLAUDE.md, п. 4; ревью Task 11).
func validateName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if n == "" {
		return "", fmt.Errorf("%w: имя пира не может быть пустым", ErrInvalidInput)
	}
	if len([]rune(n)) > maxNameLen {
		return "", fmt.Errorf("%w: имя длиннее %d символов", ErrInvalidInput, maxNameLen)
	}
	if strings.ContainsAny(n, "\r\n") {
		return "", fmt.Errorf("%w: имя содержит перевод строки", ErrInvalidInput)
	}
	// Те же символы отвергает wgconf.PeerSpec.validate — имя уезжает в конфиг
	// комментарием, и заголовок секции внутри него был бы инъекцией. Проверка
	// продублирована здесь не ради второй линии обороны, а ради КОДА ответа:
	// отказ из wgconf случился бы уже внутри Apply и ушёл бы пользователю как
	// 500 «внутренняя ошибка», из которой невозможно понять, что не так с
	// именем. Здесь он остаётся тем, чем является, — ошибкой ввода (400).
	if strings.ContainsAny(n, "[]") {
		return "", fmt.Errorf("%w: имя содержит квадратные скобки", ErrInvalidInput)
	}
	return n, nil
}

// sameHost сравнивает два адреса по ХОСТОВОЙ части, игнорируя маску:
// "10.11.0.4/32" и "10.11.0.4/24" — один и тот же адрес, и второй занимает
// его ничуть не меньше первого. Если хотя бы один из двух не разбирается как
// IP, сравнение падает обратно на строковое равенство — так неразбираемый
// мусор в конфиге не начинает молча совпадать со всем подряд.
func sameHost(a, b string) bool {
	ha := HostIP(strings.TrimSpace(a))
	hb := HostIP(strings.TrimSpace(b))
	ipa, ea := netip.ParseAddr(ha)
	ipb, eb := netip.ParseAddr(hb)
	if ea == nil && eb == nil {
		return ipa == ipb
	}
	return ha != "" && ha == hb
}

// peerHoldingAddress возвращает секцию первого пира конфига, чьи AllowedIPs
// содержат адрес addr. AllowedIPs разбивается по запятой: пир вправе нести
// несколько префиксов, и адрес, спрятанный вторым в списке, занят ровно так
// же, как единственный.
func peerHoldingAddress(c *wgconf.Config, addr string) (*wgconf.Section, bool) {
	if strings.TrimSpace(addr) == "" {
		return nil, false
	}
	for _, sec := range c.Peers {
		for _, part := range sec.AllowedIPEntries() {
			if sameHost(part, addr) {
				return sec, true
			}
		}
	}
	return nil, false
}

// usedAddresses собирает все занятые адреса: живые пиры плюс отключённые,
// чьи адреса обязаны остаться зарезервированными до включения обратно.
func usedAddresses(c *wgconf.Config, st *store.State) []string {
	var used []string
	for _, p := range c.Peers {
		used = append(used, p.AllowedIPEntries()...)
	}
	for _, p := range st.Peers {
		if !p.Enabled {
			used = append(used, savedRoutes(p)...)
		}
	}
	return used
}

// Add выпускает нового пира: генерирует ключи, выделяет адрес, добавляет блок
// [Peer] в серверный конфиг и возвращает готовый клиентский конфиг с QR.
//
// Порядок шагов выбран так, чтобы ВСЁ, что может отказать без последствий,
// отказывало ДО применения к живому устройству: клиентский конфиг и QR
// собираются раньше Apply, хотя нужны только после него. Иначе отказ рендера
// (неполная обфускация, противоречивая тройка джиттера) оставлял бы пира на
// сервере, а оператору возвращал ошибку — то есть расхождение между тем, что
// видит оператор, и тем, что применено. Приватный ключ сохраняется ДО Apply:
// обрыв после применения не лишает оператора возможности экспортировать профиль.
// После подтверждённого отката неиспользованный ключ удаляется; при неопределённом
// результате сохраняется для восстановления. Метаданные после обрыва восстанавливает
// Reconcile внутри List/ConfigFor/QRFor.
//
// Клиентский конфиг собирается через Effective(Defaults(), nil, ...) — тот
// же путь, которым позже пойдёт ConfigFor (у свежего пира оверрайдов ещё
// нет). Единая точка сборки — не только DRY: раньше Add печатал поля прямо
// из s.iface.Client.*, минуя Defaults() и Extra, и первый же ConfigFor после
// правки умолчаний вернул бы клиенту ДРУГОЙ конфиг, чем показанный при
// выпуске.
func (s *Service) Add(name string) (*Issued, error) {
	n, err := validateName(name)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.beginWrite()
	if err != nil {
		return nil, err
	}
	defer lock.Close()

	if err := s.snapshot(); err != nil {
		return nil, err
	}
	raw, c, err := s.readConf()
	if err != nil {
		return nil, err
	}
	st, err := s.resolvedState(raw, c)
	if err != nil {
		return nil, err
	}
	obf, err := ExtractObfuscation(c.Interface)
	if err != nil {
		return nil, err
	}
	addr, err := AllocateAddress(c.Interface.Get("Address"), usedAddresses(c, st))
	if err != nil {
		return nil, err
	}
	serverPub, err := s.ServerPublicKey()
	if err != nil {
		return nil, err
	}
	priv, err := s.r.GenKey()
	if err != nil {
		return nil, fmt.Errorf("генерация ключа: %w", err)
	}
	pub, err := s.r.PubKey(priv)
	if err != nil {
		return nil, fmt.Errorf("вычисление публичного ключа: %w", err)
	}
	psk, err := s.r.GenPSK()
	if err != nil {
		return nil, fmt.Errorf("генерация PSK: %w", err)
	}

	d := s.defaults()
	e := Effective(d, nil, c.Interface.Get("MTU"))
	s.personalizeI1(&e, nil, d, false, store.PeerID(pub), pub)
	clientConf, err := RenderClientConfig(ClientParams{
		PrivateKey: priv, Address: addr, ServerPublicKey: serverPub, PresharedKey: psk,
		Endpoint: e.Endpoint, AllowedIPs: e.AllowedIPs, Keepalive: e.Keepalive,
		DNS: e.DNS, MTU: e.MTU, Obfuscation: obf,
		Jc: e.Jc, Jmin: e.Jmin, Jmax: e.Jmax, Extra: e.Extra,
	})
	if err != nil {
		return nil, fmt.Errorf("сборка клиентского конфига: %w", err)
	}
	qr, err := QRPNG(clientConf)
	if err != nil {
		return nil, fmt.Errorf("генерация QR: %w", err)
	}

	spec := wgconf.PeerSpec{Name: n, PublicKey: pub, PresharedKey: psk, AllowedIPs: addr}
	mutate := func(text string) (string, error) { return wgconf.AppendPeer(text, spec) }
	id := store.PeerID(pub)
	slug := st.UniqueSlug(n)
	st.Upsert(store.Peer{
		ID: id, Name: n, PublicKey: pub, Address: addr, AssignedAddress: addr, Slug: slug,
		CreatedAt: time.Now().UTC().Format(time.RFC3339), Enabled: true,
	})
	if err := s.commitPeer(st, id, priv, mutate, Expect{Added: []string{pub}}); err != nil {
		return nil, err
	}
	log.Printf("выпущен пир id=%s адрес=%s", id, addr)

	return &Issued{ID: id, Name: n, Address: addr, Config: clientConf, QRPNG: qr}, nil
}

func (s *Service) resolvePeer(id string) (string, *wgconf.Config, *store.State, store.Peer, error) {
	raw, c, err := s.readConf()
	if err != nil {
		return "", nil, nil, store.Peer{}, err
	}
	st, err := s.resolvedState(raw, c)
	if err != nil {
		return "", nil, nil, store.Peer{}, err
	}
	p, ok := st.Get(id)
	if !ok {
		return "", nil, nil, store.Peer{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return raw, c, st, *p, nil
}

func (s *Service) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer lock.Close()

	_, _, st, p, err := s.resolvePeer(id)
	if err != nil {
		return err
	}
	// Снимок — после проверок, перед первой записью: отвергнутая операция
	// слот ротации не расходует (финальное ревью, M1).
	if err := s.snapshot(); err != nil {
		return err
	}
	var mutate func(string) (string, error)
	var exp Expect
	if p.Enabled {
		mutate = func(text string) (string, error) { return wgconf.RemovePeerByPublicKey(text, p.PublicKey) }
		exp.Removed = []string{p.PublicKey}
	}
	st.Delete(id)
	if err := s.commitPeerChange(st, id, mutate, exp, nil, func() error {
		path, err := s.keys.path(id)
		if err != nil {
			return err
		}
		return removeDurable(path)
	}); err != nil {
		return err
	}

	log.Printf("удалён пир id=%s", id)
	return nil
}

// Disable вырезает блок [Peer] из конфига, сохраняя PSK и адрес в peers.json:
// без них обратное включение выдало бы клиенту другой туннель.
func (s *Service) Disable(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer lock.Close()

	_, c, st, p, err := s.resolvePeer(id)
	if err != nil {
		return err
	}
	if !p.Enabled {
		return nil // идемпотентно
	}
	// Снимок — после проверок, перед первой записью: отвергнутая операция
	// слот ротации не расходует (финальное ревью, M1).
	if err := s.snapshot(); err != nil {
		return err
	}
	sec, ok := wgconf.FindPeer(c, p.PublicKey)
	if !ok {
		// Защитная ветка: через loadState она недостижима — Reconcile
		// оставляет Enabled=true только пирам, найденным в конфиге, а
		// отключённые отсеиваются проверкой выше. Класс всё равно проставлен:
		// это состояние, требующее вмешательства человека, и если ветка
		// когда-нибудь оживёт, оператор должен прочитать причину, а не
		// «внутреннюю ошибку», неотличимую от случайного сбоя.
		return fmt.Errorf("%w: пир %s есть в метаданных, но не в конфиге", ErrInvalidInput, id)
	}
	psk := sec.Get("PresharedKey")
	routes := sec.AllowedIPEntries()
	// Пир без PresharedKey отключать НЕЛЬЗЯ: сохранять в peers.json нечего, а
	// Enable собирает блок через wgconf.AppendPeer, который требует непустой
	// PresharedKey, — то есть обратно такой пир уже не вернуть, и ключевой
	// материал останется только в бэкапе awg3.conf. Пиры, заведённые вручную
	// до установки панели, бывают без PSK (на боевом сервере такой есть),
	// поэтому это рабочий сценарий, а не теория. Отказ ДО касания живого
	// устройства честнее, чем молча оборвать клиента навсегда.
	if psk == "" {
		return fmt.Errorf("%w: у пира %s нет PresharedKey в серверном конфиге — "+
			"отключение сделало бы его невосстановимым", ErrInvalidInput, id)
	}

	pp, _ := st.Get(id)
	pp.Enabled = false
	pp.PresharedKey = psk
	pp.SavedRoutes = routes
	pp.SavedEndpoint = sec.Get("Endpoint")
	pp.SavedKeepalive = sec.Get("PersistentKeepalive")
	mutate := func(text string) (string, error) { return wgconf.RemovePeerByPublicKey(text, p.PublicKey) }
	if err := s.commitPeerChange(st, id, mutate, Expect{Removed: []string{p.PublicKey}}, nil, nil); err != nil {
		return err
	}

	log.Printf("отключён пир id=%s", id)
	return nil
}

func (s *Service) Enable(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer lock.Close()

	_, _, st, p, err := s.resolvePeer(id)
	if err != nil {
		return err
	}
	if p.Enabled {
		return nil // идемпотентно
	}
	if p.PresharedKey == "" {
		return fmt.Errorf("%w: у пира %s не сохранён PSK — восстановить подключение нельзя, "+
			"выпустите нового", ErrInvalidInput, id)
	}
	// Снимок — после проверок, перед первой записью: отвергнутая операция
	// слот ротации не расходует (финальное ревью, M1).
	if err := s.snapshot(); err != nil {
		return err
	}
	routes := savedRoutes(p)
	spec := wgconf.PeerSpec{
		Name: p.Name, PublicKey: p.PublicKey,
		PresharedKey: p.PresharedKey, AllowedIPs: strings.Join(routes, ", "),
		Endpoint: p.SavedEndpoint, PersistentKeepalive: p.SavedKeepalive,
	}
	// Проверка занятости адреса стоит ВНУТРИ замыкания, а не выше по коду:
	// сюда Apply передаёт текст, прочитанный уже под своим мьютексом и после
	// предварительной сверки с устройством, — то есть самый свежий, какой
	// вообще доступен. Пока пир отключён, его адрес зарезервирован только в
	// peers.json: блока [Peer] в конфиге нет, и занять адрес мимо панели
	// может как пир, заведённый руками, так и второй процесс (CLI против
	// демона — остаточная гонка, оставленная незакрытой сознательно).
	// Собственных рубежей против этого не было: AppendPeer ловит повтор
	// PublicKey, но не повтор AllowedIPs, а checkPostcondition выводит
	// exp.Added из-под ВСЕХ проверок пиров, — и Enable молча
	// разводил двух клиентов на одном IP (ревью финальное, I3).
	mutate := func(text string) (string, error) {
		c, err := wgconf.Parse(text)
		if err != nil {
			return "", fmt.Errorf("исходный конфиг не разбирается: %w", err)
		}
		for _, route := range routes {
			if other, taken := peerHoldingAddress(c, route); taken {
				return "", fmt.Errorf("%w: адрес %s пира %s занят другим пиром %s в серверном конфиге — "+
					"включение развело бы два клиента на одном IP; освободите адрес "+
					"или выпустите нового пира", ErrInvalidInput, route, id,
					shortKey(other.Get("PublicKey")))
			}
		}
		return wgconf.AppendPeer(text, spec)
	}
	pp, _ := st.Get(id)
	pp.Enabled = true
	pp.SavedRoutes = nil
	pp.SavedEndpoint = ""
	pp.SavedKeepalive = ""
	pp.PresharedKey = ""
	if err := s.commitPeerChange(st, id, mutate, Expect{Added: []string{p.PublicKey}, AddedRoutes: map[string][]string{p.PublicKey: routes}}, nil, nil); err != nil {
		return err
	}

	log.Printf("включён пир id=%s", id)
	return nil
}

// normalizeAddress приводит адрес пира к виду "IP/32". Оператор вправе
// написать и "10.11.0.7", и "10.11.0.7/32" — в серверном конфиге это одна и
// та же строка AllowedIPs, и различие форм привело бы к тому, что usedAddresses
// не узнаёт занятый адрес в другой записи.
func normalizeAddress(s string) (string, error) {
	v := strings.TrimSpace(s)
	if v == "" {
		return "", fmt.Errorf("%w: адрес пуст", ErrInvalidInput)
	}
	if !strings.Contains(v, "/") {
		v += "/32"
	}
	pfx, err := netip.ParsePrefix(v)
	if err != nil {
		return "", fmt.Errorf("%w: адрес %q не разбирается: %v", ErrInvalidInput, s, err)
	}
	if !pfx.Addr().Is4() || pfx.Bits() != 32 {
		return "", fmt.Errorf("%w: адрес пира должен быть одиночным IPv4 вида 10.11.0.7/32", ErrInvalidInput)
	}
	return pfx.String(), nil
}

// checkAddressFree проверяет, что адрес лежит в подсети сервера и не занят
// кем-то, кроме самого пира selfID.
// savedRoutes also accepts pre-upgrade records with comma-separated routes in Address.
func savedRoutes(p store.Peer) []string {
	if len(p.SavedRoutes) > 0 {
		return slices.Clone(p.SavedRoutes)
	}
	if p.Address == "" {
		return nil
	}
	parts := strings.Split(p.Address, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
func usableHost(pool netip.Prefix, ip netip.Addr) bool {
	return ip.Is4() && pool.Contains(ip) && ip != pool.Addr() && ip != pool.Masked().Addr() && pool.Contains(ip.Next())
}

// primaryHost accepts an explicit assignment or one unique usable pool host. Old
// metadata derived from Reconcile cannot disambiguate multiple routes.
func primaryHost(server string, routes []string, assigned string) (string, error) {
	pool, err := netip.ParsePrefix(server)
	if err != nil || !pool.Addr().Is4() {
		return "", ErrInvalidInput
	}
	primary := ""
	for _, v := range routes {
		h, e := normalizeAddress(v)
		if e != nil || (assigned != "" && h != assigned) {
			continue
		}
		a, _ := netip.ParsePrefix(h)
		ip := a.Addr()
		if !usableHost(pool, ip) {
			continue
		}
		if primary != "" {
			return "", ErrInvalidInput
		}
		primary = h
	}
	if primary == "" {
		return "", ErrInvalidInput
	}
	return primary, nil
}

func checkAddressFree(c *wgconf.Config, st *store.State, selfID, addr string) error {
	serverAddr := c.Interface.Get("Address")
	net, err := netip.ParsePrefix(serverAddr)
	if err != nil {
		return fmt.Errorf("Address сервера %q не разбирается: %w", serverAddr, err)
	}
	want, _ := netip.ParsePrefix(addr) // уже нормализован
	if !net.Contains(want.Addr()) {
		return fmt.Errorf("%w: адрес %s вне подсети сервера %s", ErrInvalidInput, addr, net)
	}
	if !usableHost(net, want.Addr()) {
		return fmt.Errorf("%w: адрес %s зарезервирован", ErrInvalidInput, addr)
	}
	for _, p := range st.Peers {
		if p.ID == selfID {
			continue
		}
		if !p.Enabled {
			for _, route := range savedRoutes(p) {
				if sameHost(route, addr) {
					return fmt.Errorf("%w: адрес %s уже занят отключённым пиром", ErrInvalidInput, addr)
				}
			}
		}
		if p.Address == addr {
			return fmt.Errorf("%w: адрес %s уже занят пиром %q", ErrInvalidInput, addr, p.Name)
		}
	}
	if sec, ok := peerHoldingAddress(c, addr); ok {
		if pub := sec.Get("PublicKey"); pub != "" {
			if own, found := st.Get(selfID); !found || own.PublicKey != pub {
				return fmt.Errorf("%w: адрес %s занят пиром в серверном конфиге", ErrInvalidInput, addr)
			}
		}
	}
	return nil
}

// PeerPatch — частичная правка пира. Указатели различают «поле не прислали»
// и «поле прислали». Overrides заменяются ЦЕЛИКОМ, а не сливаются по полям:
// сброс оверрайда в наследование выражается его отсутствием в присланном
// объекте, и слияние сделало бы сброс невыразимым (раздел 8 спеки).
type PeerPatch struct {
	Name      *string          `json:"name"`
	Address   *string          `json:"address"`
	Overrides *store.Overrides `json:"overrides"`
	// Jitter changes only the three junk settings in the current overrides.
	Jitter *Jitter `json:"jitter"`
}

// Update правит имя, адрес и/или клиентские оверрайды уже выпущенного пира.
//
// Серверный конфиг трогается только теми полями, что в нём реально хранятся —
// имя (комментарий блока) и адрес (AllowedIPs) — и только если у пира вообще
// есть блок [Peer]: у отключённого его нет, менять там нечего, а новое имя
// или адрес уедут на сервер при следующем Enable (он строит блок из
// актуальной записи peers.json). Оверрайды в awg3.conf не попадают никогда —
// они участвуют только в сборке клиентского конфига (configFor).
//
// Патч без единого действительного изменения возвращается ДО бэкапа и
// Apply: мутация ради нуля изменений — лишний риск на живом устройстве.
func (s *Service) Update(id string, patch PeerPatch) error {
	return s.update(id, patch, nil)
}

// UpdateJitterIfProfile applies measured jitter only while the peer still has
// the profile that was measured, under the same lock as the write.
func (s *Service) UpdateJitterIfProfile(id string, jitter Jitter, check func(string) error) error {
	return s.update(id, PeerPatch{Jitter: &jitter}, check)
}

func (s *Service) update(id string, patch PeerPatch, checkProfile func(string) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer lock.Close()

	raw, c, st, p, err := s.resolvePeer(id)
	if err != nil {
		return err
	}
	if checkProfile != nil {
		if !p.Enabled {
			return fmt.Errorf("%w: тестовый пир выключен", ErrStateConflict)
		}
		cp, err := s.clientParamsFromPeer(raw, c, p)
		if err != nil {
			return err
		}
		body, err := RenderClientConfig(cp)
		if err != nil {
			return err
		}
		if err := checkProfile(body); err != nil {
			return err
		}
	}
	newName := p.Name
	if patch.Name != nil {
		n, err := validateName(*patch.Name)
		if err != nil {
			return err
		}
		newName = n
	}
	sec, inConf := wgconf.FindPeer(c, p.PublicKey)
	var disabledRoutes []string
	newAddr := p.Address
	if patch.Address != nil {
		a, err := normalizeAddress(*patch.Address)
		if err != nil {
			return err
		}
		if !inConf {
			disabledRoutes = savedRoutes(p)
			primary, e := primaryHost(c.Interface.Get("Address"), disabledRoutes, p.AssignedAddress)
			if e != nil {
				return fmt.Errorf("%w: нет однозначного основного адреса", ErrInvalidInput)
			}
			p.Address = primary
			for i, route := range disabledRoutes {
				h, e := normalizeAddress(route)
				if e != nil {
					continue
				}
				switch {
				case h == primary:
					disabledRoutes[i] = a
				case h == a:
					return fmt.Errorf("%w: новый адрес уже есть у пира", ErrInvalidInput)
				}
			}
		}
		if p.Address == "" {
			return fmt.Errorf("%w: нет однозначного основного адреса", ErrInvalidInput)
		}
		if err := checkAddressFree(c, st, id, a); err != nil {
			return err
		}
		newAddr = a
	}
	if patch.Overrides != nil {
		if err := ValidateOverrides(patch.Overrides); err != nil {
			return err
		}
	}
	if jitter := patch.Jitter; jitter != nil {
		if patch.Overrides != nil {
			return fmt.Errorf("%w: jitter и overrides нельзя прислать вместе", ErrInvalidInput)
		}
		var overrides store.Overrides
		if p.Overrides != nil {
			overrides = *p.Overrides
		}
		mtu := c.Interface.Get("MTU")
		if overrides.MTU != nil {
			mtu = *overrides.MTU
		}
		if err := validateEffectiveJitter(jitter.Jc, jitter.Jmin, jitter.Jmax, mtu); err != nil {
			return err
		}
		overrides.Jc, overrides.Jmin, overrides.Jmax = &jitter.Jc, &jitter.Jmin, &jitter.Jmax
		patch.Overrides = &overrides
	}

	nameChanged := newName != p.Name
	addrChanged := newAddr != p.Address
	if !nameChanged && !addrChanged && patch.Overrides == nil {
		return nil // нечего менять — до syncconf дело не доходит
	}
	// Снимок — после проверок, перед первой записью: отвергнутая операция
	// слот ротации не расходует (финальное ревью, M1).
	exp := Expect{}
	mutate := func(text string) (string, error) {
		if addrChanged {
			next, e := wgconf.ReplacePeerAddress(text, p.PublicKey, p.Address, newAddr)
			if e != nil {
				return "", fmt.Errorf("%w: %v", ErrInvalidInput, e)
			}
			text = next
		}
		if nameChanged {
			return wgconf.ReplacePeerIdentity(text, p.PublicKey, wgconf.PeerSpec{Name: newName, PublicKey: p.PublicKey, PresharedKey: sec.Get("PresharedKey")})
		}
		return text, nil
	}
	if inConf && addrChanged {
		preview, e := mutate(raw)
		if e != nil {
			return e
		}
		parsed, e := wgconf.Parse(preview)
		if e != nil {
			return e
		}
		target, _ := wgconf.FindPeer(parsed, p.PublicKey)
		exp.Modified = []ExpectedPeerChange{{PublicKey: p.PublicKey, AllowedIPs: strings.Join(target.AllowedIPEntries(), ","), HandshakeMayReset: true}}
	}
	if err := s.snapshot(); err != nil {
		return err
	}
	if !inConf || (!nameChanged && !addrChanged) {
		mutate = nil
	}
	pp, _ := st.Get(id)

	pp.Name = newName
	pp.Address = newAddr
	if patch.Address != nil {
		pp.AssignedAddress = newAddr
		if !inConf {
			pp.SavedRoutes = disabledRoutes
		}
	}
	if patch.Overrides != nil {
		pp.Overrides = normalizeOverrides(patch.Overrides)
	}
	if err := s.commitPeerChange(st, id, mutate, exp, nil, nil); err != nil {
		return err
	}

	log.Printf("изменён пир id=%s (имя:%v адрес:%v оверрайды:%v)",
		id, nameChanged, addrChanged, patch.Overrides != nil)
	return nil
}

// normalizeOverrides возвращает nil, если o не хранит НИ ОДНОГО значимого
// поля (все указатели nil и Extra пуст) — такой объект неотличим по
// содержанию от «оверрайдов нет вовсе» и не должен занимать это место в
// peers.json (находка ревью задачи 11).
//
// index.html пересобирает и шлёт "overrides" целиком при КАЖДОМ сохранении
// формы правки пира — включая случай «менял только имя» — а пир без единого
// персонального значения даёт для этого поля пустой, но НЕ nil указатель
// (JSON "overrides":{}, не отсутствие ключа: см. комментарий у PeerPatch).
// Без этой нормализации naive `pp.Overrides = patch.Overrides` превратил бы
// nil в &store.Overrides{} на первом же сохранении ЛЮБОЙ формы, разрушив
// именно то различие, ради которого PeerView.Overrides введён.
//
// Явно пустая строка (например, DNS — указатель на "") НЕ считается пустым
// полем: она несёт собственный сигнал «наследовать нельзя, задано явно
// пусто» (раздел 5.3 спеки) и обязана остаться отличимой от отсутствия
// поля — именно поэтому проверка смотрит на nil-ность УКАЗАТЕЛЕЙ, а не на
// нулевые значения того, на что они указывают.
func normalizeOverrides(o *store.Overrides) *store.Overrides {
	if o == nil {
		return nil
	}
	if o.DNS != nil || o.AllowedIPs != nil || o.Keepalive != nil || o.MTU != nil ||
		o.Endpoint != nil || o.Jc != nil || o.Jmin != nil || o.Jmax != nil || len(o.Extra) > 0 {
		return o
	}
	return nil
}

// Rotate выдаёт пиру новую пару ключей и новый PSK, сохраняя id, имя и адрес.
//
// id намеренно НЕ пересчитывается от нового публичного ключа: он назначается
// при выпуске и живёт дальше как исторический (раздел 7.2 спеки). Иначе
// ротация меняла бы URL пира, имя файла с приватным ключом и все ссылки,
// которые оператор успел кому-то отдать.
//
// На устройстве смена публичного ключа — это не изменение пира, а замена
// одного другим, поэтому ожидание описывается как Removed+Added.
func (s *Service) Rotate(id string) (*Issued, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.beginWrite()
	if err != nil {
		return nil, err
	}
	defer lock.Close()

	if err := s.checkRotateStateMatchesServer(id); err != nil {
		return nil, err
	}

	_, c, st, p, err := s.resolvePeer(id)
	if err != nil {
		return nil, err
	}
	// Снимок — после проверок, перед первой записью: отвергнутая операция
	// слот ротации не расходует (финальное ревью, M1).
	if _, err := normalizeAddress(p.Address); err != nil {
		return nil, fmt.Errorf("%w: нет однозначного адреса для выдачи", ErrInvalidInput)
	}
	if err := s.snapshot(); err != nil {
		return nil, err
	}
	priv, err := s.r.GenKey()
	if err != nil {
		return nil, fmt.Errorf("генерация ключа: %w", err)
	}
	pub, err := s.r.PubKey(priv)
	if err != nil {
		return nil, fmt.Errorf("вычисление публичного ключа: %w", err)
	}
	psk, err := s.r.GenPSK()
	if err != nil {
		return nil, fmt.Errorf("генерация PSK: %w", err)
	}

	// Всё, что может отказать без последствий, — до применения к устройству.
	obf, err := ExtractObfuscation(c.Interface)
	if err != nil {
		return nil, err
	}
	serverPub, err := s.ServerPublicKey()
	if err != nil {
		return nil, err
	}
	d := s.defaults()
	e := Effective(d, p.Overrides, c.Interface.Get("MTU"))
	s.personalizeI1(&e, p.Overrides, d, false, p.ID, pub)
	clientConf, err := RenderClientConfig(ClientParams{
		PrivateKey: priv, Address: p.Address, ServerPublicKey: serverPub, PresharedKey: psk,
		Endpoint: e.Endpoint, AllowedIPs: e.AllowedIPs, Keepalive: e.Keepalive,
		DNS: e.DNS, MTU: e.MTU, Obfuscation: obf,
		Jc: e.Jc, Jmin: e.Jmin, Jmax: e.Jmax, Extra: e.Extra,
	})
	if err != nil {
		return nil, fmt.Errorf("сборка клиентского конфига: %w", err)
	}
	qr, err := QRPNG(clientConf)
	if err != nil {
		return nil, fmt.Errorf("генерация QR: %w", err)
	}

	var mutate func(string) (string, error)
	var exp Expect
	if sec, found := wgconf.FindPeer(c, p.PublicKey); found {
		spec := wgconf.PeerSpec{Name: p.Name, PublicKey: pub, PresharedKey: psk}
		mutate = func(text string) (string, error) { return wgconf.ReplacePeerIdentity(text, p.PublicKey, spec) }
		exp = Expect{Added: []string{pub}, Removed: []string{p.PublicKey}, AddedRoutes: map[string][]string{pub: sec.AllowedIPEntries()}}
	}
	previous, _ := st.Get(id)
	previous.PublicKey = pub
	if !p.Enabled {
		previous.PresharedKey = psk
	}
	if err := s.commitPeer(st, id, priv, mutate, exp); err != nil {
		return nil, err
	}

	log.Printf("ротация ключей пира id=%s", id)
	return &Issued{ID: id, Name: p.Name, Address: p.Address, Config: clientConf, QRPNG: qr}, nil
}

// checkRotateStateMatchesServer обнаруживает расхождение peers.json с
// серверным конфигом ДО обычного peerByID — тот вызывает loadState →
// store.Reconcile на КАЖДОМ обращении, а для пира, который ЧИСЛИТСЯ
// включённым (Enabled=true), но не найден в текущем конфиге, Reconcile
// действует не отказом, а «самолечением»: молча УДАЛЯЕТ такую запись из
// peers.json (см. её собственный комментарий — «нет в конфиге, включён →
// удалить, убран из конфига мимо панели») и, если конфиг сейчас содержит
// пира на том же адресе, заводит взамен новую запись с ДРУГИМ id, посчитанным
// от текущего публичного ключа устройства.
//
// Это осмысленный компромисс, когда пира ДЕЙСТВИТЕЛЬНО убрали руками мимо
// панели, — но губительный ровно тогда, когда причина расхождения другая:
// прошлая ротация успела заменить ключ пира на устройстве (Apply прошёл), а
// следующий шаг (keys.Put/updatePeer) отказал ДО того, как новый PublicKey
// попал в peers.json. Тогда peers.json ещё хранит СТАРЫЙ ключ, конфиг — уже
// НОВЫЙ, и первый же вызов ЛЮБОГО метода, идущего через peerByID (не только
// повторная ротация — так же сработали бы List, ConfigFor, Enable, Disable,
// Update), молча стирает id/slug/created_at/оверрайды этого пира и подменяет
// его фантомной записью — то есть гарантия задачи 9 «id переживает ротацию»
// нарушается тем же кодом, который её обеспечивает.
//
// Проверено эмпирически (находка ревью задач 8-9, раздел «Правка после
// ревью: расхождение состояния в Rotate», task-8-9-report.md): буквальное
// описание симптома находки («повторный Rotate трактует inConf==false как
// «отключён» и молча пишет третий ключ, возвращая nil») в реальности не
// воспроизводится — Reconcile успевает стереть улику раньше, чем тело Rotate
// до неё доберётся, и повторный вызов падает на peerByID с ErrNotFound.
// Настоящая потеря происходит МОЛЧА, на файле, ещё до этого возврата.
// Поэтому проверка здесь читает peers.json НАПРЯМУЮ через store.Load, минуя
// loadState/Reconcile целиком, — самолечению просто нечего лечить, если оно
// не вызывается.
//
// Класс ошибки — ErrStateConflict, не ErrPostcondition (находка финального
// ревью, I4): см. комментарий у ErrStateConflict. Текст НЕ советует «откройте
// список пиров, чтобы согласовать состояние» — этот совет и есть
// разрушительное действие: список опрашивается вебом каждые 10 секунд, а
// один List() на расходящемся состоянии — это и есть то самое самолечение
// Reconcile, описанное выше в комментарии к функции, — оно выбрасывает
// запись и заводит новую с другим id, теряя id, slug, дату выпуска и
// персональные оверрайды пира. Структурная починка (согласование, не
// выбрасывающее запись) в этой версии не сделана — текст честно предупреждает
// о цене автоматического согласования вместо того, чтобы советовать вызвать
// его вручную.
func (s *Service) checkRotateStateMatchesServer(id string) error {
	_, c, err := s.readConf()
	if err != nil {
		return err
	}
	st, err := store.Load(s.iface.Storage.State)
	if err != nil {
		return nil // peerByID прочитает то же самое и вернёт содержательную ошибку сам
	}
	p, ok := st.Get(id)
	if !ok || !p.Enabled {
		return nil // нет записи или пир легитимно отключён — блока и не должно быть
	}
	if _, inConf := wgconf.FindPeer(c, p.PublicKey); inConf {
		return nil
	}
	return fmt.Errorf("%w: пир %s числится включённым в peers.json, но его блока нет в серверном "+
		"конфиге — состояние разошлось с сервером (похоже, предыдущая ротация заменила ключ на "+
		"устройстве, но не успела записать его в peers.json); ротация не выполнена, чтобы не "+
		"потерять метаданные пира; состояние согласуется автоматически при следующем обновлении "+
		"списка пиров, но пир при этом потеряет id, дату выпуска и персональные оверрайды",
		ErrStateConflict, id)
}

// ConfigFor проверяет соответствие файла устройству и собирает профиль заново.
func (s *Service) ConfigFor(id string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.configFor(id, false)
}

// configFor собирает клиентский конфиг заново при каждом обращении: из
// приватного ключа, живого [Interface] сервера, оверрайдов пира и умолчаний
// интерфейса. Файла, который мог бы устареть, больше нет (раздел 5.2 спеки,
// задача 5) — раньше .conf собирался один раз при Add и лежал в
// Storage.ClientConfigs, и правка обфускации/DNS/маршрутов молча делала
// выданные файлы негодными без единого способа об этом узнать.
//
// БЕЗ захвата мьютекса: sync.Mutex не реентрантен, а QRFor обязан взять
// мьютекс на всю свою работу и при этом переиспользовать эту логику.
// Вызывать только под s.mu.
func (s *Service) configFor(id string, withoutCPS bool) (string, string, error) {
	p, cp, err := s.clientParamsFor(id)
	if err != nil {
		return "", "", err
	}
	name := store.Slug(p.Name)
	if withoutCPS {
		for key := range cp.Extra {
			if isIKey(key) {
				delete(cp.Extra, key)
			}
		}
		name += "-no-cps"
	}
	body, err := RenderClientConfig(cp)
	if err != nil {
		return "", "", err
	}
	return name + ".conf", body, nil
}

// clientParamsFor собирает параметры клиентского конфига пира — общая часть
// configFor и vpnURIFor (одни и те же значения обязаны попасть и в .conf, и
// в vpn://). Вызывать только под s.mu.
func (s *Service) clientParamsFor(id string) (store.Peer, ClientParams, error) {
	guard, err := s.beginRead()
	if err != nil {
		return store.Peer{}, ClientParams{}, err
	}
	defer guard.close()

	raw, c, _, p, err := s.resolvePeer(id)
	if err != nil {
		return store.Peer{}, ClientParams{}, err
	}
	cp, err := s.clientParamsFromPeer(raw, c, p)
	if err != nil {
		return store.Peer{}, ClientParams{}, err
	}
	if err := guard.validate(); err != nil {
		return store.Peer{}, ClientParams{}, err
	}
	return p, cp, nil
}

func (s *Service) clientParamsFromPeer(raw string, c *wgconf.Config, p store.Peer) (ClientParams, error) {
	if _, err := normalizeAddress(p.Address); err != nil {
		return ClientParams{}, fmt.Errorf("%w: нет однозначного адреса для выдачи", ErrInvalidInput)
	}
	live, err := s.applier.Snapshot()
	if err != nil {
		return ClientParams{}, err
	}
	if err := assertFileMatchesDevice(live.Device, raw); err != nil {
		return ClientParams{}, err
	}
	configured, err := configuredPeers(raw)
	if err != nil {
		return ClientParams{}, err
	}
	if key, reason := peerDiff(configured, live.Peers); reason != "" {
		return ClientParams{}, fmt.Errorf("%w: пир %s: %s", ErrStateConflict, shortKey(key), reason)
	}

	priv, err := s.privateKey(p)
	if err != nil {
		return ClientParams{}, err
	}
	obf, err := ExtractObfuscation(c.Interface)
	if err != nil {
		return ClientParams{}, err
	}
	serverPub, err := s.r.PubKey(c.Interface.Get("PrivateKey"))
	if err != nil {
		return ClientParams{}, err
	}
	// PSK живёт в конфиге, пока пир включён, и в peers.json — пока выключен.
	psk := p.PresharedKey
	if sec, ok := wgconf.FindPeer(c, p.PublicKey); ok {
		psk = sec.Get("PresharedKey")
	}
	d, seeded := s.readDefaultsWithOrigin(false)
	e := Effective(d, p.Overrides, c.Interface.Get("MTU"))
	source := s.personalizeI1(&e, p.Overrides, d, seeded, p.ID, p.PublicKey)
	return ClientParams{
		mimicrySource: source,
		PrivateKey:    priv, Address: p.Address, ServerPublicKey: serverPub, PresharedKey: psk,
		Endpoint: e.Endpoint, AllowedIPs: e.AllowedIPs, Keepalive: e.Keepalive,
		DNS: e.DNS, MTU: e.MTU, Obfuscation: obf,
		Jc: e.Jc, Jmin: e.Jmin, Jmax: e.Jmax, Extra: e.Extra,
	}, nil
}

// VPNURIFor — ссылка импорта AmneziaVPN для пира (спека 2026-10-29,
// раздел 6), собранная из тех же параметров, что и .conf.
func (s *Service) VPNURIFor(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.vpnURIFor(id)
}

func (s *Service) vpnURIFor(id string) (string, error) {
	p, cp, err := s.clientParamsFor(id)
	if err != nil {
		return "", err
	}
	return RenderVPNURI(cp, p.Name)
}

// VPNQRFor — QR со ссылкой vpn://: AmneziaVPN сканирует его целиком.
func (s *Service) VPNQRFor(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	uri, err := s.vpnURIFor(id)
	if err != nil {
		return nil, err
	}
	return QRPNG(uri)
}

// privateKey reads either the current key or its verified legacy profile.
func (s *Service) privateKey(p store.Peer) (string, error) {
	priv, err := s.keys.Get(p.ID)
	if err == nil || !errors.Is(err, ErrNoPrivateKey) {
		return priv, err
	}
	if p.Slug == "" {
		return "", fmt.Errorf("%w: пир %s заведён вручную до установки панели — выпустите нового пира, если конфиг нужен", ErrNoPrivateKey, p.ID)
	}
	dir := s.iface.Storage.ClientConfigs
	if dir == "" || p.Slug != filepath.Base(p.Slug) || strings.ContainsAny(p.Slug, `/\`) {
		return "", ErrNoPrivateKey
	}
	priv, err = readLegacyKey(s.r, p.ID, filepath.Join(dir, p.Slug+".conf"), p.PublicKey)
	if err != nil {
		return "", ErrNoPrivateKey
	}
	return priv, nil
}

func (s *Service) QRFor(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Именно configFor, а не ConfigFor: вторая взяла бы тот же нереентрантный
	// мьютекс повторно и намертво заблокировала бы вызывающего.
	_, body, err := s.configFor(id, false)
	if err != nil {
		return nil, err
	}
	return QRPNG(body)
}
