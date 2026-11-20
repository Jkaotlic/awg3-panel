package iface

import (
	"crypto/rand"
	"fmt"
	"net"
	"path"
	"regexp"
	"strings"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

// Env — окружение планировщика: всё, что он читает, и ничего, что он
// пишет. Планировщик побочных действий не совершает вовсе: его результат —
// заявка, то есть намерение (спека 2026-08-25, раздел 6А.1).
type Env struct {
	Cfg       *config.Config
	ConfDir   string // /etc/amnezia/amneziawg
	StateRoot string // /var/lib/awg3panel
	BinRoot   string // /opt
	H         Host
	R         func(binDir string) runtime.Runner
}

// AttachInput — три поля, которые спрашиваются у оператора (спека
// 2026-08-25, раздел 6А.2). Всё остальное блока config.yaml планировщик
// выводит сам.
type AttachInput struct {
	ID       string
	Title    string
	ConfName string // имя файла в ConfDir, из списка Adoptable
}

// idRe — тот же алфавит, что у валидатора config.Validate. Дублируется, а
// не импортируется, потому что отказ обязан случиться ЗДЕСЬ: валидатор
// сработал бы уже после записи config.yaml, то есть на испорченном файле.
var idRe = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// PlanAttach выводит блок config.yaml для интерфейса, уже существующего на
// хосте, и проверяет все отказы подключения (спека 2026-08-25, раздел 7).
//
// Файл .conf только читается. Кода, способного его записать, здесь нет —
// незыблемое правило 2 репозитория остаётся в силе буквально.
func PlanAttach(in AttachInput, env Env) (AttachPayload, error) {
	if !idRe.MatchString(in.ID) {
		return AttachPayload{}, fmt.Errorf("id %q не slug: строчные латинские буквы, цифры и дефис, 1-32 символа", in.ID)
	}
	for _, ex := range env.Cfg.Interfaces {
		if ex.ID == in.ID {
			return AttachPayload{}, fmt.Errorf("интерфейс с id %q уже есть в config.yaml", in.ID)
		}
	}

	device := strings.TrimSuffix(in.ConfName, ".conf")
	if device == in.ConfName || device == "" {
		return AttachPayload{}, fmt.Errorf("%q не похоже на имя файла конфига", in.ConfName)
	}
	for _, ex := range env.Cfg.Interfaces {
		if ex.Interface == device {
			return AttachPayload{}, fmt.Errorf("устройство %q уже есть в config.yaml", device)
		}
	}

	// path, а не filepath: ConfDir и имя файла — путь на целевом Linux-хосте,
	// а не на машине, где выполняется код (панель разрабатывается на
	// Windows) — та же ловушка, что уже описана у config.Interface.StateDir.
	confPath := path.Join(env.ConfDir, in.ConfName)
	raw, err := env.H.ReadFile(confPath)
	if err != nil {
		return AttachPayload{}, fmt.Errorf("чтение %s: %w", confPath, err)
	}
	c, err := wgconf.Parse(string(raw))
	if err != nil {
		return AttachPayload{}, fmt.Errorf("%s не разбирается: %w", confPath, err)
	}
	for _, key := range []string{"PrivateKey", "ListenPort", "Address"} {
		if c.Interface.Get(key) == "" {
			return AttachPayload{}, fmt.Errorf("в [Interface] файла %s нет %s", confPath, key)
		}
	}

	binDir := path.Join(env.BinRoot, device, "bin")
	ok, err := env.H.Exists(path.Join(binDir, "awg"))
	if err != nil {
		return AttachPayload{}, err
	}
	if !ok {
		return AttachPayload{}, fmt.Errorf("в %s нет исполняемого awg — панель отдавала бы 500 по всему интерфейсу", binDir)
	}

	// Устройство обязано быть поднято. Проверка не формальность: подключив
	// опущенный интерфейс, панель начнёт отвечать 500 на весь список — это
	// уже наблюдалось живьём, когда bin_dir указывал на снесённый каталог.
	if _, err := env.R(binDir).Show(device); err != nil {
		return AttachPayload{}, fmt.Errorf("устройство %s не поднято: %w", device, err)
	}

	stateDir := path.Join(env.StateRoot, in.ID)
	empty, err := env.H.DirEmpty(stateDir)
	if err != nil {
		return AttachPayload{}, err
	}
	if !empty {
		return AttachPayload{}, fmt.Errorf("каталог состояния %s не пуст — в нём метаданные другого интерфейса", stateDir)
	}

	// env.Cfg.Interfaces[0] ниже опирается на то, что панель уже обслуживает
	// хотя бы один интерфейс, — раздел 6А.3 спеки 2026-08-25 объясняет, что
	// заимствовать адрес «всегда есть у кого», ссылаясь на config.Validate,
	// который отвергает конфиг без единого интерфейса. Но эта гарантия живёт
	// ВЫШЕ по стеку (при загрузке config.yaml), а не внутри самой функции:
	// PlanAttach экспортирована и вызывается HTTP-обработчиком напрямую с
	// Env, собранным вызывающим кодом, — без проверки здесь пустой
	// env.Cfg.Interfaces уронил бы её паникой по индексу, то есть дал бы
	// 500 без объяснения вместо понятного отказа (раздел 7 спеки существует
	// ровно для того, чтобы этого не было).
	if len(env.Cfg.Interfaces) == 0 {
		return AttachPayload{}, fmt.Errorf("в config.yaml нет ни одного интерфейса — неоткуда позаимствовать публичный адрес для нового")
	}

	host, _, err := net.SplitHostPort(env.Cfg.Interfaces[0].Client.Endpoint)
	if err != nil {
		return AttachPayload{}, fmt.Errorf("не удалось позаимствовать публичный адрес у интерфейса %q: %w",
			env.Cfg.Interfaces[0].ID, err)
	}

	// Джиттер сеется ЗДЕСЬ, а не «обычным механизмом первого обращения»
	// (посылка раздела 6А.3 спеки 2026-08-25, исправленная финальным ревью
	// ветки). Посылка была ложна: обычный механизм — issuer.Service.defaults()
	// — сеет defaults.json из s.iface.Client, то есть из ТОГО ЖЕ блока,
	// который пишет attach. Пустой блок сеет пустые умолчания, store.LoadDefaults
	// нули не нормализует, а RenderClientConfig при нулевой тройке просто не
	// печатает Jc/Jmin/Jmax — подключённый интерфейс молча выдавал бы
	// клиентские конфиги без джиттера, тише рукописных, без единой ошибки.
	//
	// Второго источника правды это не заводит: генератор — тот самый, что
	// панель уже использует для параметров нового интерфейса
	// (issuer.GenerateJitter, диапазоны раздела 6 спеки 2026-08-24), а сами
	// значения после первого обращения живут в defaults.json и правятся
	// оператором через вкладку «Умолчания», как и у любого другого
	// интерфейса.
	j, err := issuer.GenerateJitter(rand.Reader)
	if err != nil {
		return AttachPayload{}, fmt.Errorf("генерация джиттера для нового интерфейса: %w", err)
	}

	return AttachPayload{
		ConfPath: confPath,
		Device:   device,
		Block: config.Interface{
			ID: in.ID, Title: in.Title, Interface: device,
			Config: confPath, BinDir: binDir,
			Client: config.Client{
				Endpoint: net.JoinHostPort(host, c.Interface.Get("ListenPort")),
				// AllowedIPs обязано быть непустым: config.Validate
				// отвергает интерфейс без него ("client.allowed_ips пуст"),
				// а без него записанный config.yaml не грузится —
				// TestApplyAttachResultLoads (задача 7, apply_test.go)
				// нашла это, гоняя итог хирургии через настоящий
				// config.Load. Константы, а не литералы: тот же полный
				// туннель и тот же диапазон keepalive, что у
				// config.Default(), из одного объявления — второй литерал
				// разошёлся бы с ним при первой же правке.
				AllowedIPs:          config.DefaultAllowedIPs,
				PersistentKeepalive: config.DefaultKeepalive,
				// DNS пуст сознательно и совпадает с рукописным образцом
				// (deploy/config.example.yaml: «свой DNS конфликтует с
				// AdGuard Home в домашней сети»). Выдумывать резолвер за
				// оператора хуже, чем не задавать его вовсе.
				Jc: j.Jc, Jmin: j.Jmin, Jmax: j.Jmax,
			},
			Storage: config.Storage{
				State:   path.Join(stateDir, "peers.json"),
				Backups: path.Join(stateDir, "backups"),
				Keys:    path.Join(stateDir, "keys"),
			},
		},
	}, nil
}

// PlanDetach собирает снимок отвязываемого интерфейса и проверяет
// единственный, но решающий отказ: панель не вправе отвязать интерфейс, на
// адресе которого сама слушает (спека 2026-08-25, раздел 7).
//
// Сравнение по ПРИНАДЛЕЖНОСТИ подсети, а не по совпадению строк: listen —
// это один адрес, а Address интерфейса — сеть, и панель слушает, вообще
// говоря, не на .1. Совпадение строк пропустило бы 10.30.0.15 при
// Address = 10.30.0.1/24 и отрезало бы консоль ровно тем действием, от
// которого этот отказ и защищает.
//
// Ошибка разбора listen ИЛИ Address — это ОТКАЗ, а не «не совпадает».
// Отличие важно: continue на ошибке ParseCIDR (было в первой версии этой
// функции, найдено ревью задачи 6) означает не «безопасно», а «проверить не
// удалось», и трактовать это как «совпадения нет» — fail-open ровно там,
// где отказ существует для защиты консоли и SSH к боевому хосту. Оба случая
// достижимы не в теории: .conf — файл внешний, панель его не пишет и формат
// Address нигде не валидирует; listen вида ":8081" синтаксически валиден
// для net.SplitHostPort, но означает «слушать на всех адресах», то есть и
// внутри отвязываемого интерфейса тоже.
func PlanDetach(id string, env Env) (DetachPayload, error) {
	var in *config.Interface
	for i := range env.Cfg.Interfaces {
		if env.Cfg.Interfaces[i].ID == id {
			in = &env.Cfg.Interfaces[i]
			break
		}
	}
	if in == nil {
		return DetachPayload{}, fmt.Errorf("интерфейса с id %q в config.yaml нет", id)
	}

	raw, err := env.H.ReadFile(in.Config)
	if err != nil {
		return DetachPayload{}, fmt.Errorf("чтение %s: %w", in.Config, err)
	}
	c, err := wgconf.Parse(string(raw))
	if err != nil {
		return DetachPayload{}, fmt.Errorf("%s не разбирается: %w", in.Config, err)
	}

	listenHost, _, err := net.SplitHostPort(env.Cfg.Listen)
	if err != nil {
		return DetachPayload{}, fmt.Errorf("listen %q: %w", env.Cfg.Listen, err)
	}
	listenIP := net.ParseIP(listenHost)
	if listenIP == nil {
		return DetachPayload{}, fmt.Errorf(
			"listen %q: адрес %q не разбирается как IP — панель могла бы слушать на всех адресах, проверить безопасность отвязки невозможно",
			env.Cfg.Listen, listenHost)
	}
	for _, addr := range strings.Split(c.Interface.Get("Address"), ",") {
		addr = strings.TrimSpace(addr)
		_, netw, err := net.ParseCIDR(addr)
		if err != nil {
			return DetachPayload{}, fmt.Errorf(
				"Address интерфейса %s не разбирается как подсеть (%q в %s): проверить принадлежность адреса панели невозможно: %w",
				in.Interface, addr, in.Config, err)
		}
		if netw.Contains(listenIP) {
			return DetachPayload{}, fmt.Errorf(
				"панель слушает %s внутри этого интерфейса — отвязка отрезала бы консоль", env.Cfg.Listen)
		}
	}

	return DetachPayload{
		ID: id, Device: in.Interface, ConfPath: in.Config,
		StateDir: path.Dir(in.Storage.State),
		Peers:    len(c.Peers),
	}, nil
}
