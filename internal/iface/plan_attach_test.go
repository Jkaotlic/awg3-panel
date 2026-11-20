package iface_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/iface"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
)

// sampleConf — серверный конфиг подключаемого интерфейса. Значения
// обфускации выдуманы: живые в тесты не попадают (CLAUDE.md).
const sampleConf = `[Interface]
Address = 10.30.0.1/24
ListenPort = 3478
PrivateKey = cHJpdmF0ZS1rZXktZmFrZS0wMDAwMDAwMDAwMDAwMDAwMD0=
S1 = 40
S2 = 52

[Peer]
# первый
PublicKey = cGVlci1wdWJsaWMta2V5LWZha2UtMDAwMDAwMDAwMDAwMD0=
AllowedIPs = 10.30.0.2/32
`

// planEnv собирает окружение планировщика на подставном хосте: конфиг с
// одним уже подключённым интерфейсом, каталог с двумя .conf и рабочий
// bin_dir у подключаемого.
func planEnv(t *testing.T) iface.Env {
	t.Helper()
	h := iface.NewFakeHost()
	h.Files["/etc/amnezia/amneziawg/awg2.conf"] = []byte(sampleConf)
	h.Files["/opt/awg2/bin/awg"] = []byte("бинарь")
	return iface.Env{
		Cfg: &config.Config{
			Listen: "10.11.0.1:8081",
			Interfaces: []config.Interface{{
				ID: "awg3", Interface: "awg3",
				Config: "/etc/amnezia/amneziawg/awg3.conf",
				Client: config.Client{Endpoint: "203.0.113.10:51772"},
			}},
		},
		ConfDir: "/etc/amnezia/amneziawg", StateRoot: "/var/lib/awg3panel",
		BinRoot: "/opt", H: h,
		R: func(string) runtime.Runner { return runtime.NewFake(sampleConf) },
	}
}

// TestPlanAttachDerivesBlock — панель выводит сама всё, кроме трёх полей
// ввода (спека 2026-08-25, раздел 6А.3). Проверяются именно выведенные:
// имя устройства из имени файла, bin_dir по соглашению, endpoint —
// заимствованный адрес плюс СВОЙ порт, пути состояния по id.
func TestPlanAttachDerivesBlock(t *testing.T) {
	got, err := iface.PlanAttach(iface.AttachInput{
		ID: "awg2", Title: "awg2 (2.0)", ConfName: "awg2.conf",
	}, planEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	// Джиттер СЛУЧАЕН по построению (issuer.GenerateJitter) — сравнивать его
	// на равенство нечему, он проверяется отдельно диапазонами (тест ниже).
	// Из ожидаемого блока он поэтому подставляется как есть, чтобы ВСЕ
	// остальные поля сверялись строго, а не «примерно».
	jc, jmin, jmax := got.Block.Client.Jc, got.Block.Client.Jmin, got.Block.Client.Jmax
	want := config.Interface{
		ID: "awg2", Title: "awg2 (2.0)", Interface: "awg2",
		Config: "/etc/amnezia/amneziawg/awg2.conf",
		BinDir: "/opt/awg2/bin",
		Client: config.Client{
			Endpoint: "203.0.113.10:3478", AllowedIPs: "0.0.0.0/0",
			PersistentKeepalive: "22-30",
			Jc:                  jc, Jmin: jmin, Jmax: jmax,
		},
		Storage: config.Storage{
			State:   "/var/lib/awg3panel/awg2/peers.json",
			Backups: "/var/lib/awg3panel/awg2/backups",
			Keys:    "/var/lib/awg3panel/awg2/keys",
		},
	}
	if !reflect.DeepEqual(got.Block, want) {
		t.Errorf("блок =\n%+v\nожидали\n%+v", got.Block, want)
	}
	if got.Device != "awg2" || got.ConfPath != "/etc/amnezia/amneziawg/awg2.conf" {
		t.Errorf("устройство=%q путь=%q", got.Device, got.ConfPath)
	}
}

// TestPlanAttachSeedsJitterInProtocolRanges — джиттер подключаемого
// интерфейса берётся у существующего генератора панели
// (issuer.GenerateJitter), а не выдумывается на месте, и потому обязан
// лежать в диапазонах раздела 6 спеки 2026-08-24: Jc 4–7, Jmin 64–150,
// Jmax = Jmin + 200…600 с потолком 1000 — заведомо меньше боевого MTU 1280,
// иначе junk-пакет фрагментируется.
//
// Прогон повторный: одна выборка о генераторе не говорит ничего.
func TestPlanAttachSeedsJitterInProtocolRanges(t *testing.T) {
	for i := 0; i < 50; i++ {
		got, err := iface.PlanAttach(iface.AttachInput{
			ID: "awg2", Title: "awg2 (2.0)", ConfName: "awg2.conf",
		}, planEnv(t))
		if err != nil {
			t.Fatal(err)
		}
		c := got.Block.Client
		if c.Jc < 4 || c.Jc > 7 {
			t.Fatalf("Jc = %d, ожидали 4..7", c.Jc)
		}
		if c.Jmin < 64 || c.Jmin > 150 {
			t.Fatalf("Jmin = %d, ожидали 64..150", c.Jmin)
		}
		if c.Jmax <= c.Jmin || c.Jmax > 1000 {
			t.Fatalf("Jmax = %d при Jmin = %d, ожидали Jmin < Jmax <= 1000", c.Jmax, c.Jmin)
		}
	}
}

// TestPlanAttachRefusals — таблица отказов раздела 7 спеки 2026-08-25.
// Каждый отказ проверяется отдельным случаем, потому что каждый описывает
// СВОЁ состояние хоста, и общая проверка «вернулась ошибка» пропустила бы
// подмену одного отказа другим.
//
// Случаи «каталог состояния не пуст» и «устройство уже занято» добавлены
// сверх исходного брифа задачи 5: раздел 7 спеки называет непустой каталог
// состояния отдельным условием отказа, а PlanAttach его действительно
// проверяет — без своего случая отказ мог бы незаметно сломаться и никто бы
// не заметил. То же для дублирующегося имени устройства: строка раздела 7
// «id или имя устройства уже заняты» покрывает оба поля, а не только id.
func TestPlanAttachRefusals(t *testing.T) {
	cases := []struct {
		title  string
		mutate func(*iface.Env)
		in     iface.AttachInput
		want   string
	}{
		{
			title: "конфиг не разбирается",
			mutate: func(e *iface.Env) {
				e.H.(*iface.FakeHost).Files["/etc/amnezia/amneziawg/awg2.conf"] = []byte("мусор\n")
			},
			in:   iface.AttachInput{ID: "awg2", ConfName: "awg2.conf"},
			want: "не разбирается",
		},
		{
			title: "в [Interface] нет ListenPort",
			mutate: func(e *iface.Env) {
				e.H.(*iface.FakeHost).Files["/etc/amnezia/amneziawg/awg2.conf"] =
					[]byte("[Interface]\nAddress = 10.30.0.1/24\nPrivateKey = x\n")
			},
			in:   iface.AttachInput{ID: "awg2", ConfName: "awg2.conf"},
			want: "ListenPort",
		},
		{
			title: "bin_dir без awg",
			mutate: func(e *iface.Env) {
				delete(e.H.(*iface.FakeHost).Files, "/opt/awg2/bin/awg")
			},
			in:   iface.AttachInput{ID: "awg2", ConfName: "awg2.conf"},
			want: "/opt/awg2/bin",
		},
		{
			title:  "id уже занят",
			mutate: func(*iface.Env) {},
			in:     iface.AttachInput{ID: "awg3", ConfName: "awg2.conf"},
			want:   "уже есть",
		},
		{
			title:  "id не slug",
			mutate: func(*iface.Env) {},
			in:     iface.AttachInput{ID: "AWG 2!", ConfName: "awg2.conf"},
			want:   "slug",
		},
		{
			title: "устройство не поднято",
			mutate: func(e *iface.Env) {
				e.R = func(string) runtime.Runner { return downRunner{} }
			},
			in:   iface.AttachInput{ID: "awg2", ConfName: "awg2.conf"},
			want: "не поднято",
		},
		{
			// Дефект брифа, найден при ревью: раздел 7 спеки 2026-08-25
			// называет непустой каталог состояния ОТДЕЛЬНЫМ условием отказа
			// («каталог состояния <id> существует и НЕ пуст»), а исходная
			// таблица TestPlanAttachRefusals его не проверяла — при том что
			// PlanAttach эту проверку делает. Сеется SeedDir, а не прямой
			// записью в Files: DirEmpty у FakeHost смотрит в карту Dirs, и
			// запись в Files её бы не задела — тест остался бы
			// ложнозелёным, проходя независимо от того, работает ли отказ.
			title: "каталог состояния не пуст",
			mutate: func(e *iface.Env) {
				e.H.(*iface.FakeHost).SeedDir("/var/lib/awg3panel/awg2")
			},
			in:   iface.AttachInput{ID: "awg2", ConfName: "awg2.conf"},
			want: "не пуст",
		},
		{
			// Раздел 7 одной строкой описывает оба поля — «id или имя
			// устройства уже заняты» — а PlanAttach проверяет их отдельными
			// сравнениями (ID и Interface). Случай «id уже занят» выше
			// проверяет первое сравнение; это — второе: тот же .conf нельзя
			// подключить под новым id, если его устройство уже числится в
			// config.yaml за другим интерфейсом.
			title: "устройство уже занято",
			mutate: func(e *iface.Env) {
				e.Cfg.Interfaces = append(e.Cfg.Interfaces, config.Interface{
					ID: "other", Interface: "awg2",
					Config: "/etc/amnezia/amneziawg/other.conf",
				})
			},
			in:   iface.AttachInput{ID: "new-awg2", ConfName: "awg2.conf"},
			want: "awg2",
		},
		{
			// Ревью задачи 5: PlanAttach брал env.Cfg.Interfaces[0] без
			// проверки длины, чтобы позаимствовать публичный адрес (раздел
			// 6А.3 спеки 2026-08-25). Раздел 6А.3 объясняет, что заимствовать
			// «всегда есть у кого», ссылаясь на валидатор config.Validate,
			// который отвергает конфиг без единого интерфейса, — но эта
			// гарантия живёт ВЫШЕ по стеку, а не внутри самой функции.
			// PlanAttach экспортирована и будет вызвана HTTP-обработчиком
			// (задача 9) — вызывающий с пустым Cfg.Interfaces обязан получить
			// внятный отказ, а не panic: index out of range, то есть не 500
			// без объяснения, от которого весь раздел 7 и защищает.
			title: "config.yaml без интерфейсов — неоткуда позаимствовать адрес",
			mutate: func(e *iface.Env) {
				e.Cfg.Interfaces = nil
			},
			in:   iface.AttachInput{ID: "awg2", ConfName: "awg2.conf"},
			want: "неоткуда позаимствовать",
		},
		{
			// Раздел 7 сводит отсутствие PrivateKey/ListenPort/Address в
			// [Interface] в одну строку таблицы, а PlanAttach проверяет их
			// ТРЕМЯ отдельными сравнениями в цикле. До этого случая тестом
			// было закрыто только ListenPort — тот же паттерн пропуска, что
			// уже нашёлся и был закрыт для пары id/устройство: опечатка,
			// подменившая проверку Address повторной проверкой PrivateKey,
			// не была бы замечена ни одним тестом.
			title: "в [Interface] нет PrivateKey",
			mutate: func(e *iface.Env) {
				e.H.(*iface.FakeHost).Files["/etc/amnezia/amneziawg/awg2.conf"] =
					[]byte("[Interface]\nAddress = 10.30.0.1/24\nListenPort = 3478\n")
			},
			in:   iface.AttachInput{ID: "awg2", ConfName: "awg2.conf"},
			want: "PrivateKey",
		},
		{
			title: "в [Interface] нет Address",
			mutate: func(e *iface.Env) {
				e.H.(*iface.FakeHost).Files["/etc/amnezia/amneziawg/awg2.conf"] =
					[]byte("[Interface]\nListenPort = 3478\nPrivateKey = x\n")
			},
			in:   iface.AttachInput{ID: "awg2", ConfName: "awg2.conf"},
			want: "Address",
		},
		{
			// Ветка недостижима из реального потока (ConfName приходит из
			// Adoptable, а там уже только *.conf), но раз она есть в коде и
			// возвращает отказ, стоить теста ей копейки — а не покрыть было
			// бы дырой, замеченной следующим ревью так же, как эта.
			title:  "имя файла не похоже на .conf",
			mutate: func(*iface.Env) {},
			in:     iface.AttachInput{ID: "awg2", ConfName: "awg2"},
			want:   "не похоже",
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			env := planEnv(t)
			tc.mutate(&env)
			_, err := iface.PlanAttach(tc.in, env)
			if err == nil {
				t.Fatal("ожидался отказ, получен успех")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ошибка %q не содержит %q", err, tc.want)
			}
		})
	}
}

// downRunner — устройство, которого нет: Show отвечает так же, как
// настоящий awg по опущенному интерфейсу. Объявлен здесь, а не в
// internal/runtime: подставной Runner общего назначения там уже есть
// (runtime.Fake), и заводить второй в ПРОДАКШЕН-пакете ради одного
// отрицательного случая значило бы тащить тестовую нужду в бинарь.
// Встраивается ИНТЕРФЕЙС, а не runtime.Fake: нужен ровно один метод,
// остальные вызовами не достигаются, и вложенный nil об этом честно
// сообщит паникой, если предположение однажды перестанет быть верным.
type downRunner struct{ runtime.Runner }

func (downRunner) Show(iface string) (string, error) {
	return "", fmt.Errorf("Unable to access interface %s: No such device", iface)
}

// TestPlanAttachAllowsLongID — id длиннее 15 символов при ПОДКЛЮЧЕНИИ
// допустим: имя устройства уже существует и приходит из имени файла, а
// потолок IFNAMSIZ бьёт только по имени устройства (спека 2026-08-25,
// раздел 6А.2). Страж против обобщения валидатора «заодно и здесь».
func TestPlanAttachAllowsLongID(t *testing.T) {
	if _, err := iface.PlanAttach(iface.AttachInput{
		ID: "ochen-dlinnyj-identifikator", Title: "т", ConfName: "awg2.conf",
	}, planEnv(t)); err != nil {
		t.Fatalf("длинный id отвергнут при подключении: %v", err)
	}
}
