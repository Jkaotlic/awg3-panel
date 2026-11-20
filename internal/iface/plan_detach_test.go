package iface_test

import (
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/iface"
)

// TestPlanDetachSnapshot — снимок для подтверждения: что именно исчезнет
// из панели и сколько пиров это затронет.
func TestPlanDetachSnapshot(t *testing.T) {
	env := planEnv(t)
	env.Cfg.Interfaces = append(env.Cfg.Interfaces, config.Interface{
		ID: "awg2", Interface: "awg2",
		Config:  "/etc/amnezia/amneziawg/awg2.conf",
		Storage: config.Storage{State: "/var/lib/awg3panel/awg2/peers.json"},
	})

	got, err := iface.PlanDetach("awg2", env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Device != "awg2" || got.StateDir != "/var/lib/awg3panel/awg2" {
		t.Errorf("снимок = %+v", got)
	}
	if got.Peers != 1 {
		t.Errorf("пиров в снимке %d, ожидали 1 (по составу .conf)", got.Peers)
	}
}

// TestPlanDetachRefusesOwnAddress — интерфейс, на адресе которого слушает
// панель, отвязать нельзя. Это первая строка таблицы отказов спеки
// 2026-08-25 и защита от самострела: на боевых хостах listen указывает
// внутрь awg3, через который же идёт SSH, а прямого SSH из РФ нет.
func TestPlanDetachRefusesOwnAddress(t *testing.T) {
	env := planEnv(t)
	env.Cfg.Listen = "10.30.0.1:8081" // адрес из [Interface] sampleConf
	env.Cfg.Interfaces = append(env.Cfg.Interfaces, config.Interface{
		ID: "awg2", Interface: "awg2",
		Config: "/etc/amnezia/amneziawg/awg2.conf",
	})

	_, err := iface.PlanDetach("awg2", env)
	if err == nil {
		t.Fatal("отвязка интерфейса с адресом панели прошла — это отрезало бы консоль")
	}
	if !strings.Contains(err.Error(), "слушает") {
		t.Errorf("ошибка %q не объясняет причину", err)
	}
}

// TestPlanDetachRefusesForeignAddressNotConfused — отказ обязан бить по
// принадлежности адреса ПОДСЕТИ, а не по совпадению строк: 10.30.0.1 и
// 10.30.0.15 — разные адреса одной подсети, и оба обязаны срабатывать,
// тогда как 10.31.0.1 — нет.
func TestPlanDetachRefusesForeignAddressNotConfused(t *testing.T) {
	for _, tc := range []struct {
		listen string
		refuse bool
	}{
		{"10.30.0.1:8081", true},
		{"10.30.0.15:8081", true},
		{"10.31.0.1:8081", false},
	} {
		env := planEnv(t)
		env.Cfg.Listen = tc.listen
		env.Cfg.Interfaces = append(env.Cfg.Interfaces, config.Interface{
			ID: "awg2", Interface: "awg2",
			Config: "/etc/amnezia/amneziawg/awg2.conf",
		})
		_, err := iface.PlanDetach("awg2", env)
		if tc.refuse && err == nil {
			t.Errorf("listen %s: отказа не было", tc.listen)
		}
		if !tc.refuse && err != nil {
			t.Errorf("listen %s: лишний отказ %v", tc.listen, err)
		}
	}
}

// TestPlanDetachUnknownID — отвязывать нечего, значит отказ.
func TestPlanDetachUnknownID(t *testing.T) {
	if _, err := iface.PlanDetach("нетакого", planEnv(t)); err == nil {
		t.Fatal("ожидался отказ")
	}
}

// TestPlanDetachAddressWithoutMaskRefuses — Address без маски CIDR не
// разбирается net.ParseCIDR. Ошибка разбора обязана быть ОТКАЗОМ, а не
// молчаливым «не совпадает» через continue: иначе оператор получил бы
// успешный снимок для интерфейса, чья принадлежность адреса панели вообще
// не была проверена (ревью задачи 6, находка 1 — fail-open). .conf — файл
// внешний, панель его не пишет и формат Address нигде не валидирует, так
// что запись без маски достижима не только в теории.
func TestPlanDetachAddressWithoutMaskRefuses(t *testing.T) {
	env := planEnv(t)
	env.H.(*iface.FakeHost).Files["/etc/amnezia/amneziawg/awg2.conf"] = []byte(
		"[Interface]\nAddress = 10.30.0.1\nListenPort = 3478\nPrivateKey = x\n")
	env.Cfg.Interfaces = append(env.Cfg.Interfaces, config.Interface{
		ID: "awg2", Interface: "awg2",
		Config: "/etc/amnezia/amneziawg/awg2.conf",
	})

	_, err := iface.PlanDetach("awg2", env)
	if err == nil {
		t.Fatal("Address без маски прошёл — принадлежность адреса панели не проверена, а отказа не было")
	}
	if !strings.Contains(err.Error(), "не разбирается") {
		t.Errorf("ошибка %q не называет причину — неразличима от «панель слушает внутри»", err)
	}
}

// TestPlanDetachEmptyAddressRefuses — пустой Address (ключ есть, значения
// нет) даёт после strings.Split один пустой элемент, который тоже не
// разбирается как CIDR. То же самое требование: неспособность проверить —
// это отказ, а не тихий пропуск.
func TestPlanDetachEmptyAddressRefuses(t *testing.T) {
	env := planEnv(t)
	env.H.(*iface.FakeHost).Files["/etc/amnezia/amneziawg/awg2.conf"] = []byte(
		"[Interface]\nAddress = \nListenPort = 3478\nPrivateKey = x\n")
	env.Cfg.Interfaces = append(env.Cfg.Interfaces, config.Interface{
		ID: "awg2", Interface: "awg2",
		Config: "/etc/amnezia/amneziawg/awg2.conf",
	})

	_, err := iface.PlanDetach("awg2", env)
	if err == nil {
		t.Fatal("пустой Address прошёл — принадлежность адреса панели не проверена, а отказа не было")
	}
}

// TestPlanDetachMultipleAddressesOneWithoutMaskRefuses — Address из
// нескольких записей через запятую, где ИМЕННО опасная (та, что содержит
// адрес панели) записана без маски. Прежний continue пропустил бы её и
// проверил только безобидную соседнюю запись, вернув успех там, где отказ
// был решающим.
func TestPlanDetachMultipleAddressesOneWithoutMaskRefuses(t *testing.T) {
	env := planEnv(t)
	env.Cfg.Listen = "10.30.0.1:8081"
	env.H.(*iface.FakeHost).Files["/etc/amnezia/amneziawg/awg2.conf"] = []byte(
		"[Interface]\nAddress = 10.31.0.0/24,10.30.0.1\nListenPort = 3478\nPrivateKey = x\n")
	env.Cfg.Interfaces = append(env.Cfg.Interfaces, config.Interface{
		ID: "awg2", Interface: "awg2",
		Config: "/etc/amnezia/amneziawg/awg2.conf",
	})

	_, err := iface.PlanDetach("awg2", env)
	if err == nil {
		t.Fatal("вторая запись Address без маски содержала адрес панели, а отказа не было")
	}
}

// TestPlanDetachListenWithoutHostRefuses — listen вида ":8081" (пустой
// хост) синтаксически валиден для net.SplitHostPort, но net.ParseIP("")
// даёт nil. Пустой хост означает «слушать на всех адресах» — то есть
// панель слушает и внутри отвязываемого интерфейса тоже, а прежний код
// молча пропускал этот случай через тот же continue (ревью задачи 6,
// находка 2). В проде это перекрыто config.Validate выше по стеку, но
// PlanDetach экспортирована и вызывается HTTP-обработчиком напрямую с
// Env, собранным вызывающим кодом, — тот же довод, что уже записан
// комментарием у PlanAttach про env.Cfg.Interfaces[0].
func TestPlanDetachListenWithoutHostRefuses(t *testing.T) {
	env := planEnv(t)
	env.Cfg.Listen = ":8081"
	env.Cfg.Interfaces = append(env.Cfg.Interfaces, config.Interface{
		ID: "awg2", Interface: "awg2",
		Config: "/etc/amnezia/amneziawg/awg2.conf",
	})

	_, err := iface.PlanDetach("awg2", env)
	if err == nil {
		t.Fatal("listen без хоста означает «слушать на всех адресах» — отказа не было")
	}
}
