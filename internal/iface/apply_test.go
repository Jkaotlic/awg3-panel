package iface_test

import (
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/iface"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
)

// countRestarts — сколько раз в журнале встречается "systemctl restart
// awg3panel". Общий хелпер для тестов отката: рассказывает, сколько РАЗ
// панель пытались поднять, а не только пытались ли вообще.
func countRestarts(calls []string) int {
	n := 0
	for _, c := range calls {
		if c == "systemctl restart awg3panel" {
			n++
		}
	}
	return n
}

// applyEnv — окружение исполнителя: подставной хост с config.yaml на месте.
func applyEnv(t *testing.T) (iface.Env, *iface.FakeHost) {
	t.Helper()
	env := planEnv(t)
	h := env.H.(*iface.FakeHost)
	h.Files["/etc/awg3panel/config.yaml"] = []byte(sampleYAML)
	return env, h
}

// TestApplyAttachStepOrder — порядок шагов раздела 6А.5 спеки 2026-08-25.
// Проверяется именно ПОРЯДОК, а не итог: копия config.yaml, сделанная
// ПОСЛЕ его перезаписи, бесполезна ровно в том случае, ради которого
// существует, — когда применение сорвалось на середине.
func TestApplyAttachStepOrder(t *testing.T) {
	env, h := applyEnv(t)
	payload, err := iface.PlanAttach(iface.AttachInput{
		ID: "awg2", Title: "awg2 (2.0)", ConfName: "awg2.conf",
	}, env)
	if err != nil {
		t.Fatal(err)
	}
	req := iface.Request{
		Version: 1, Action: iface.ActionAttach, ID: "awg2",
		CreatedAt: "2026-08-27T10:00:00Z", Attach: &payload,
	}

	if err := iface.Apply(req, env, "/etc/awg3panel/config.yaml"); err != nil {
		t.Fatal(err)
	}

	var backup, write, mkdir, restart int
	for i, c := range h.Calls {
		switch {
		case strings.HasPrefix(c, "write /etc/awg3panel/config.yaml.bak-"):
			backup = i + 1
		case c == "write /etc/awg3panel/config.yaml":
			write = i + 1
		case c == "mkdir /var/lib/awg3panel/awg2":
			mkdir = i + 1
		case c == "systemctl restart awg3panel":
			restart = i + 1
		}
	}
	if backup == 0 || write == 0 || mkdir == 0 || restart == 0 {
		t.Fatalf("не все шаги выполнены: %v", h.Calls)
	}
	if !(backup < write && write < mkdir && mkdir < restart) {
		t.Errorf("порядок шагов нарушен: %v", h.Calls)
	}
}

// TestApplyAttachResultLoads — итоговый config.yaml грузится настоящим
// загрузчиком и несёт оба интерфейса. Без этой проверки исполнитель мог бы
// «успешно» записать файл, с которого панель не поднимется, — и оператор
// узнал бы об этом, уже потеряв консоль.
func TestApplyAttachResultLoads(t *testing.T) {
	env, h := applyEnv(t)
	payload, _ := iface.PlanAttach(iface.AttachInput{
		ID: "awg2", Title: "awg2 (2.0)", ConfName: "awg2.conf",
	}, env)
	req := iface.Request{Version: 1, Action: iface.ActionAttach, ID: "awg2",
		CreatedAt: "2026-08-27T10:00:00Z", Attach: &payload}
	if err := iface.Apply(req, env, "/etc/awg3panel/config.yaml"); err != nil {
		t.Fatal(err)
	}
	cfg := loadFrom(t, string(h.Files["/etc/awg3panel/config.yaml"]))
	if len(cfg.Interfaces) != 2 {
		t.Fatalf("интерфейсов %d, ожидали 2", len(cfg.Interfaces))
	}
}

// TestApplyAttachRollsBackConfigOnRestartFailure — панель не поднялась,
// значит config.yaml обязан вернуться к исходному. Иначе следующая попытка
// стартовать демон снова упрётся в блок, который её и уронил.
func TestApplyAttachRollsBackConfigOnRestartFailure(t *testing.T) {
	env, h := applyEnv(t)
	payload, _ := iface.PlanAttach(iface.AttachInput{
		ID: "awg2", Title: "awg2 (2.0)", ConfName: "awg2.conf",
	}, env)
	h.FailAt = "systemctl restart awg3panel"
	req := iface.Request{Version: 1, Action: iface.ActionAttach, ID: "awg2",
		CreatedAt: "2026-08-27T10:00:00Z", Attach: &payload}

	if err := iface.Apply(req, env, "/etc/awg3panel/config.yaml"); err == nil {
		t.Fatal("ожидался отказ")
	}
	if string(h.Files["/etc/awg3panel/config.yaml"]) != sampleYAML {
		t.Errorf("config.yaml не откачен:\n%s", h.Files["/etc/awg3panel/config.yaml"])
	}
}

// TestApplyDetachDeletesNothing — сторож раздела 11 спеки 2026-08-25.
// Проверяется по журналу вызовов, а не по наличию файлов: «файл на месте»
// прошло бы и при удалении с последующим восстановлением, а обещание
// отвязки — что удаления не было вовсе.
func TestApplyDetachDeletesNothing(t *testing.T) {
	env, h := applyEnv(t)
	env.Cfg.Interfaces = append(env.Cfg.Interfaces, config.Interface{
		ID: "awg2", Interface: "awg2",
		Config:  "/etc/amnezia/amneziawg/awg2.conf",
		Storage: config.Storage{State: "/var/lib/awg3panel/awg2/peers.json"},
	})
	h.Files["/etc/awg3panel/config.yaml"] = []byte(mustInsert(t, sampleYAML, "awg2"))
	payload, err := iface.PlanDetach("awg2", env)
	if err != nil {
		t.Fatal(err)
	}
	req := iface.Request{Version: 1, Action: iface.ActionDetach, ID: "awg2",
		CreatedAt: "2026-08-27T10:00:00Z", Detach: &payload}

	if err := iface.Apply(req, env, "/etc/awg3panel/config.yaml"); err != nil {
		t.Fatal(err)
	}
	for _, c := range h.Calls {
		if strings.HasPrefix(c, "remove ") || strings.HasPrefix(c, "rmdir ") {
			t.Errorf("отвязка удалила %q — она обязана не удалять ничего", c)
		}
	}
	cfg := loadFrom(t, string(h.Files["/etc/awg3panel/config.yaml"]))
	if len(cfg.Interfaces) != 1 || cfg.Interfaces[0].ID != "awg3" {
		t.Errorf("после отвязки осталось: %+v", cfg.Interfaces)
	}
}

// TestApplyAttachRollsBackWithoutRestartOnMkdirFailure — находка 1 ревью
// задачи 7 (ветка отказа, специфичная для attach: MkdirAll каталога
// состояния), уточнённая финальным ревью ветки.
//
// Откат здесь обязан быть БЕЗ перезапуска панели. Довод тот же, которым
// уже обоснован restoreConfigOnly в самом Apply: на этом шаге панель ещё не
// потревожена — она жива на СТАРОМ конфиге, systemctl restart ещё не
// вызывался, — и её рестарт был бы не восстановлением, а лишним риском.
// Неудачный рестарт ЗДОРОВОЙ панели оставил бы оператора без консоли ровно
// там, где бездействие не оставило бы: цена ошибки несимметрична, и выбор
// между «ничего не делать» и «дёрнуть работающий демон» решается в пользу
// первого.
func TestApplyAttachRollsBackWithoutRestartOnMkdirFailure(t *testing.T) {
	env, h := applyEnv(t)
	payload, err := iface.PlanAttach(iface.AttachInput{
		ID: "awg2", Title: "awg2 (2.0)", ConfName: "awg2.conf",
	}, env)
	if err != nil {
		t.Fatal(err)
	}
	h.FailAt = "mkdir /var/lib/awg3panel/awg2"
	req := iface.Request{Version: 1, Action: iface.ActionAttach, ID: "awg2",
		CreatedAt: "2026-08-27T10:00:00Z", Attach: &payload}

	err = iface.Apply(req, env, "/etc/awg3panel/config.yaml")
	if err == nil {
		t.Fatal("ожидался отказ")
	}
	if !strings.Contains(err.Error(), "каталога состояния") {
		t.Errorf("отказ не называет настоящую причину (каталог состояния): %v", err)
	}
	if string(h.Files["/etc/awg3panel/config.yaml"]) != sampleYAML {
		t.Errorf("config.yaml не откачен:\n%s", h.Files["/etc/awg3panel/config.yaml"])
	}
	if n := countRestarts(h.Calls); n != 0 {
		t.Errorf("перезапусков %d, ожидали 0: панель на этом шаге ещё не тронута, "+
			"и дёргать здоровый демон при откате — лишний риск, а не восстановление: %v", n, h.Calls)
	}
}

// TestApplyDetachRollsBackAndRestartsOnRestartFailure — симметричный
// случай для detach: провалился шаг 5 (безусловный restart), а не только
// шаг 4 (у detach его вообще нет). FailAtOnce — иначе восстановительный
// restore-restart несёт ТО ЖЕ имя вызова, что и упавший исходный, и без
// одноразового отказа нельзя было бы отличить «оба рестарта упали» от
// «панель реально поднята обратно».
func TestApplyDetachRollsBackAndRestartsOnRestartFailure(t *testing.T) {
	env, h := applyEnv(t)
	env.Cfg.Interfaces = append(env.Cfg.Interfaces, config.Interface{
		ID: "awg2", Interface: "awg2",
		Config:  "/etc/amnezia/amneziawg/awg2.conf",
		Storage: config.Storage{State: "/var/lib/awg3panel/awg2/peers.json"},
	})
	original := mustInsert(t, sampleYAML, "awg2")
	h.Files["/etc/awg3panel/config.yaml"] = []byte(original)
	payload, err := iface.PlanDetach("awg2", env)
	if err != nil {
		t.Fatal(err)
	}
	h.FailAt = "systemctl restart awg3panel"
	h.FailAtOnce = true
	req := iface.Request{Version: 1, Action: iface.ActionDetach, ID: "awg2",
		CreatedAt: "2026-08-27T10:00:00Z", Detach: &payload}

	err = iface.Apply(req, env, "/etc/awg3panel/config.yaml")
	if err == nil {
		t.Fatal("ожидался отказ")
	}
	if strings.Contains(err.Error(), "не поднялась") {
		t.Errorf("отказ говорит, что панель не поднята обратно, хотя второй рестарт был одноразово настроен на успех: %v", err)
	}
	if string(h.Files["/etc/awg3panel/config.yaml"]) != original {
		t.Errorf("config.yaml не откачен:\n%s", h.Files["/etc/awg3panel/config.yaml"])
	}
	if n := countRestarts(h.Calls); n != 2 {
		t.Errorf("перезапусков %d, ожидали 2 (упавший исходный + восстановительный): %v", n, h.Calls)
	}
}

// TestApplyRollsBackWhenDaemonNotActiveAfterRestart — постусловие раздела
// 6А.5 спеки 2026-08-25, шаг 6 (находка 2 ревью задачи 7): systemctl
// restart может вернуть 0 и в тот же момент, когда демон секундой позже
// падает в цикл рестартов на невалидном конфиге. Без явной проверки
// is-active Apply рапортовал бы успех оператору, который в этот момент уже
// без консоли.
func TestApplyRollsBackWhenDaemonNotActiveAfterRestart(t *testing.T) {
	env, h := applyEnv(t)
	payload, err := iface.PlanAttach(iface.AttachInput{
		ID: "awg2", Title: "awg2 (2.0)", ConfName: "awg2.conf",
	}, env)
	if err != nil {
		t.Fatal(err)
	}
	h.FailAt = "systemctl is-active awg3panel"
	req := iface.Request{Version: 1, Action: iface.ActionAttach, ID: "awg2",
		CreatedAt: "2026-08-27T10:00:00Z", Attach: &payload}

	err = iface.Apply(req, env, "/etc/awg3panel/config.yaml")
	if err == nil {
		t.Fatal("ожидался отказ")
	}
	if !strings.Contains(err.Error(), "не активен") {
		t.Errorf("отказ не называет настоящую причину (демон не активен): %v", err)
	}
	if string(h.Files["/etc/awg3panel/config.yaml"]) != sampleYAML {
		t.Errorf("config.yaml не откачен после провала постусловия is-active:\n%s", h.Files["/etc/awg3panel/config.yaml"])
	}
	if n := countRestarts(h.Calls); n != 2 {
		t.Errorf("перезапусков %d, ожидали 2: исходный (после которого демон не встал) и восстановительный", n)
	}
}

// TestApplyAttachRollsBackWhenDeviceNotRespondingAfterRestart — вторая
// половина постусловия шага 6 для attach: устройство обязано отвечать на
// awg show ПОСЛЕ рестарта, отдельно от того, что оно отвечало на
// ПРЕДУСЛОВИИ (первый вызов env.R внутри повторного PlanAttach). Счётчик в
// env.R различает эти два момента: первый вызов — здоровое устройство
// (иначе Apply отказал бы уже на предусловии, и постусловие осталось бы
// непроверенным), второй и далее — устройство пропало.
func TestApplyAttachRollsBackWhenDeviceNotRespondingAfterRestart(t *testing.T) {
	env, h := applyEnv(t)
	payload, err := iface.PlanAttach(iface.AttachInput{
		ID: "awg2", Title: "awg2 (2.0)", ConfName: "awg2.conf",
	}, env)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	env.R = func(string) runtime.Runner {
		calls++
		if calls > 1 {
			return downRunner{}
		}
		return runtime.NewFake(sampleConf)
	}
	req := iface.Request{Version: 1, Action: iface.ActionAttach, ID: "awg2",
		CreatedAt: "2026-08-27T10:00:00Z", Attach: &payload}

	err = iface.Apply(req, env, "/etc/awg3panel/config.yaml")
	if err == nil {
		t.Fatal("ожидался отказ")
	}
	if !strings.Contains(err.Error(), "не отвечает") {
		t.Errorf("отказ не называет настоящую причину (устройство не отвечает): %v", err)
	}
	if string(h.Files["/etc/awg3panel/config.yaml"]) != sampleYAML {
		t.Errorf("config.yaml не откачен после провала постусловия Show:\n%s", h.Files["/etc/awg3panel/config.yaml"])
	}
	if n := countRestarts(h.Calls); n != 2 {
		t.Errorf("перезапусков %d, ожидали 2: исходный (после которого устройство не ответило) и восстановительный", n)
	}
}

// TestApplyAttachRollsBackWithoutRestartWhenConfigDoesNotLoad — круг 2
// ревью задачи 7. Постусловие ПОСЛЕ restart (is-active, blockPresent, Show)
// не ловит именно тот отказ, ради которого писалось: systemctl restart для
// Type=simple рапортует "active", едва процесс форкнулся, — демон, падающий
// на невалидном конфиге секундой позже, к моменту проверки ещё жив. Это
// гонка, а не гарантия, и проигрыш в ней стоит консоли на боевом хосте.
//
// Лечится не усилением проверки после, а порядком: конфиг обязан ЗАГРУЖАТЬСЯ
// настоящим разбором и валидацией ДО того, как потревожена работающая
// панель, — тот же ход, что уже сделан в InsertInterface (отвергает
// дубликат id до записи файла, а не после).
//
// Способ довести конфиг до незагружаемого состояния изменён финальным ревью
// ветки. Прежде тест портил сам блок (Client.AllowedIPs = ""), но с
// появлением сверки пересчитанного плана с заявкой (IMPORTANT 4) такой блок
// отсеивается РАНЬШЕ и с другим текстом — испорченное поле теперь называют
// прямо. Ветка «записанный config.yaml не грузится» от этого не стала
// лишней: она ловит то, чего сверка полей не видит по построению — файл на
// диске, разошедшийся с тем, что панель держит в памяти.
//
// Именно это здесь и воспроизводится: в config.yaml НА ДИСКЕ у awg3 стоит
// storage.backups, совпадающий с каталогом подключаемого awg2 (оператор
// правил файл руками и панель с тех пор не перезапускал), а env.Cfg — то,
// что панель прочитала при старте, — про правку ещё не знает. Предусловия и
// сверка полей проходят, текстовая вставка проходит, и только настоящий
// config.Parse отвергает результат («путь уже используется интерфейсом»).
// Ровно тот класс, ради которого проверка стоит ДО рестарта: панель, ушедшая
// в цикл падений на таком файле, оставила бы оператора без консоли.
func TestApplyAttachRollsBackWithoutRestartWhenConfigDoesNotLoad(t *testing.T) {
	env, h := applyEnv(t)
	payload, err := iface.PlanAttach(iface.AttachInput{
		ID: "awg2", Title: "awg2 (2.0)", ConfName: "awg2.conf",
	}, env)
	if err != nil {
		t.Fatal(err)
	}
	onDisk := strings.Replace(sampleYAML,
		"backups: /var/lib/awg3panel/awg3/backups",
		"backups: /var/lib/awg3panel/awg2/backups", 1)
	if onDisk == sampleYAML {
		t.Fatal("фикстура изменилась: подмена пути в sampleYAML не сработала")
	}
	h.Files["/etc/awg3panel/config.yaml"] = []byte(onDisk)

	req := iface.Request{Version: 1, Action: iface.ActionAttach, ID: "awg2",
		CreatedAt: "2026-08-27T10:00:00Z", Attach: &payload}

	err = iface.Apply(req, env, "/etc/awg3panel/config.yaml")
	if err == nil {
		t.Fatal("ожидался отказ")
	}
	if !strings.Contains(err.Error(), "не грузится") && !strings.Contains(err.Error(), "не загружается") {
		t.Errorf("отказ не называет настоящую причину (config.yaml не проходит config.Load): %v", err)
	}
	if string(h.Files["/etc/awg3panel/config.yaml"]) != onDisk {
		t.Errorf("config.yaml не откачен:\n%s", h.Files["/etc/awg3panel/config.yaml"])
	}
	// Панель ни разу не перезапускалась: она ещё жива на СТАРОМ конфиге,
	// заявка отклонена ДО того, как её тронули, — рестарт был бы лишним
	// риском для работающей консоли, а не восстановлением.
	for _, c := range h.Calls {
		if strings.HasPrefix(c, "systemctl restart") {
			t.Errorf("панель перезапускалась при незагружаемом конфиге: %v", h.Calls)
		}
	}
	if n := countRestarts(h.Calls); n != 0 {
		t.Errorf("перезапусков %d, ожидали 0", n)
	}
}

// nonUniformDetachYAML — config.yaml с двумя элементами interfaces:,
// отступленными по-разному (2 и 4 пробела): awg3 первым, awg2 вторым.
// Тот же паттерн неоднородности, что в TestInsertRejectsNonUniformIndent
// (yamlblock_test.go), но с id и путями, совпадающими с тем, что
// TestApplyDetachRefusesCleanlyOnNonUniformIndent просит отвязать.
const nonUniformDetachYAML = `listen: "10.11.0.1:8081"

interfaces:
  - id: awg3
    title: "awg3 (боевой)"
    interface: awg3
    config: /etc/amnezia/amneziawg/awg3.conf
    bin_dir: /opt/awg3/bin
    storage:
      state: /var/lib/awg3panel/awg3/peers.json
      backups: /var/lib/awg3panel/awg3/backups
      keys: /var/lib/awg3panel/awg3/keys
    - id: awg2
      title: "awg2 (2.0)"
      interface: awg2
      config: /etc/amnezia/amneziawg/awg2.conf
      bin_dir: /opt/awg2/bin
      storage:
        state: /var/lib/awg3panel/awg2/peers.json
        backups: /var/lib/awg3panel/awg2/backups
        keys: /var/lib/awg3panel/awg2/keys
`

// TestApplyDetachRefusesCleanlyOnNonUniformIndent — RemoveInterface (в
// отличие от InsertInterface) не проверяет однородность отступа элементов
// interfaces: — она определяется по ПЕРВОМУ найденному элементу, и элементы
// с другим отступом молча пропускаются циклом поиска id (yamlblock.go,
// itemStarts). На конфиге, правленом руками так, что второй элемент
// отступлен иначе первого, RemoveInterface ответила бы «интерфейса с id
// awg2 нет» на физически присутствующем элементе — диагноз, который уводит
// оператора в сторону от настоящей причины.
//
// PlanDetach предусловие не ловит: она проверяет env.Cfg.Interfaces (уже
// разобранную структуру), а не сырой текст config.yaml, поэтому Apply
// доходит до RemoveInterface и там же обязана отказать ВНЯТНО — про
// неоднородность отступа, а не про отсутствие id, — и не тронуть
// config.yaml на диске: перезапись начинается только ПОСЛЕ успешной
// хирургии текста.
func TestApplyDetachRefusesCleanlyOnNonUniformIndent(t *testing.T) {
	env, h := applyEnv(t)
	env.Cfg.Interfaces = append(env.Cfg.Interfaces, config.Interface{
		ID: "awg2", Interface: "awg2",
		Config:  "/etc/amnezia/amneziawg/awg2.conf",
		Storage: config.Storage{State: "/var/lib/awg3panel/awg2/peers.json"},
	})
	h.Files["/etc/awg3panel/config.yaml"] = []byte(nonUniformDetachYAML)

	payload, err := iface.PlanDetach("awg2", env)
	if err != nil {
		t.Fatal(err)
	}
	req := iface.Request{Version: 1, Action: iface.ActionDetach, ID: "awg2",
		CreatedAt: "2026-08-27T10:00:00Z", Detach: &payload}

	err = iface.Apply(req, env, "/etc/awg3panel/config.yaml")
	if err == nil {
		t.Fatal("ожидался отказ")
	}
	if strings.Contains(err.Error(), "нет") && !strings.Contains(err.Error(), "отступ") {
		t.Errorf("отказ выглядит как «id не найден», хотя элемент физически присутствует: %v", err)
	}
	if !strings.Contains(err.Error(), "отступ") {
		t.Errorf("отказ не называет настоящую причину (неоднородный отступ): %v", err)
	}

	// config.yaml обязан остаться нетронутым: перезапись начинается только
	// после успешной хирургии текста, а хирургия здесь как раз и отказала.
	if string(h.Files["/etc/awg3panel/config.yaml"]) != nonUniformDetachYAML {
		t.Errorf("config.yaml изменён при отказавшей хирургии:\n%s", h.Files["/etc/awg3panel/config.yaml"])
	}
	for _, c := range h.Calls {
		if c == "systemctl restart awg3panel" {
			t.Error("панель перезапускалась, хотя хирургия текста отказала до записи")
		}
	}
}

// mustInsert — хелпер: вписать в текст интерфейс с данным id.
func mustInsert(t *testing.T, text, id string) string {
	t.Helper()
	in := newIface()
	in.ID, in.Interface = id, id
	in.Config = "/etc/amnezia/amneziawg/" + id + ".conf"
	in.Storage = config.Storage{
		State:   "/var/lib/awg3panel/" + id + "/peers.json",
		Backups: "/var/lib/awg3panel/" + id + "/backups",
		Keys:    "/var/lib/awg3panel/" + id + "/keys",
	}
	out, err := iface.InsertInterface(text, in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestApplyRefusesWhenEndpointChangedSinceRequest — IMPORTANT 4 финального
// ревью ветки. Между сборкой заявки в консоли и её применением по SSH
// проходит произвольное время. Если за это время у первого интерфейса
// поменяли client.endpoint, все отказы раздела 7 спеки 2026-08-25 пройдут
// заново — ни один из них про endpoint ничего не знает, — а в config.yaml
// лягут УСТАРЕВШИЕ данные из заявки: клиенты, выпущенные с такого
// интерфейса, пойдут на не тот адрес, и ни одна проверка постусловия этого
// не увидит (постусловие смотрит на присутствие id и на живость демона).
//
// Спека требует обратного дважды: раздел 5.7 — «Расхождение — отказ с
// объяснением, что именно изменилось с момента сборки заявки», раздел 3.2 —
// «применённое обязано совпасть с показанным». До правки исполнитель
// пересчитывал план и ВЫБРАСЫВАЛ результат (`if _, err := PlanAttach(...)`).
func TestApplyRefusesWhenEndpointChangedSinceRequest(t *testing.T) {
	env, h := applyEnv(t)
	payload, err := iface.PlanAttach(iface.AttachInput{
		ID: "awg2", Title: "awg2 (2.0)", ConfName: "awg2.conf",
	}, env)
	if err != nil {
		t.Fatal(err)
	}
	// Оператор поменял публичный адрес панели руками ПОСЛЕ того, как
	// консоль собрала заявку.
	env.Cfg.Interfaces[0].Client.Endpoint = "203.0.113.99:51772"

	req := iface.Request{Version: 1, Action: iface.ActionAttach, ID: "awg2",
		CreatedAt: "2026-08-27T10:00:00Z", Attach: &payload}
	err = iface.Apply(req, env, "/etc/awg3panel/config.yaml")
	if err == nil {
		t.Fatal("устаревшая заявка применена, ожидался отказ")
	}
	if !strings.Contains(err.Error(), "endpoint") {
		t.Errorf("отказ не называет, ЧТО именно разошлось: %v", err)
	}
	if !strings.Contains(err.Error(), "203.0.113.99") {
		t.Errorf("отказ не показывает нового значения: %v", err)
	}
	if string(h.Files["/etc/awg3panel/config.yaml"]) != sampleYAML {
		t.Errorf("config.yaml изменён при отказе на предусловии:\n%s", h.Files["/etc/awg3panel/config.yaml"])
	}
	if n := countRestarts(h.Calls); n != 0 {
		t.Errorf("перезапусков %d, ожидали 0: заявка отклонена до того, как хост тронут", n)
	}
}

// TestApplyRefusesWhenListenPortChangedSinceRequest — вторая половина той
// же находки, и более коварная: порт меняется не в config.yaml панели, а в
// САМОМ .conf подключаемого интерфейса, то есть в файле, который панель
// только читает и за которым не следит вовсе. Все отказы раздела 7 такой
// .conf проходит (ListenPort на месте, устройство поднято, awg на месте) —
// расходится только выведенный endpoint.
func TestApplyRefusesWhenListenPortChangedSinceRequest(t *testing.T) {
	env, h := applyEnv(t)
	payload, err := iface.PlanAttach(iface.AttachInput{
		ID: "awg2", Title: "awg2 (2.0)", ConfName: "awg2.conf",
	}, env)
	if err != nil {
		t.Fatal(err)
	}
	h.Files["/etc/amnezia/amneziawg/awg2.conf"] = []byte(
		strings.Replace(sampleConf, "ListenPort = 3478", "ListenPort = 51820", 1))

	req := iface.Request{Version: 1, Action: iface.ActionAttach, ID: "awg2",
		CreatedAt: "2026-08-27T10:00:00Z", Attach: &payload}
	err = iface.Apply(req, env, "/etc/awg3panel/config.yaml")
	if err == nil {
		t.Fatal("заявка с устаревшим портом применена, ожидался отказ")
	}
	if !strings.Contains(err.Error(), "51820") {
		t.Errorf("отказ не показывает нового порта: %v", err)
	}
	if string(h.Files["/etc/awg3panel/config.yaml"]) != sampleYAML {
		t.Errorf("config.yaml изменён при отказе на предусловии:\n%s", h.Files["/etc/awg3panel/config.yaml"])
	}
}

// TestApplyRefusesWhenPreconditionsChangedSinceRequest — ПЕРВЫЙ шаг раздела
// 6А.5 спеки 2026-08-25 («проверить отказы раздела 7 заново»), не покрытый
// до финального ревью ветки ни одним тестом вовсе. Устройство, живое на
// момент сборки заявки, к моменту применения опущено — подключив такое,
// панель начала бы отвечать 500 по всему интерфейсу (это уже наблюдалось
// живьём). Отказ обязан назвать причину и не тронуть config.yaml.
func TestApplyRefusesWhenPreconditionsChangedSinceRequest(t *testing.T) {
	env, h := applyEnv(t)
	payload, err := iface.PlanAttach(iface.AttachInput{
		ID: "awg2", Title: "awg2 (2.0)", ConfName: "awg2.conf",
	}, env)
	if err != nil {
		t.Fatal(err)
	}
	env.R = func(string) runtime.Runner { return downRunner{} }

	req := iface.Request{Version: 1, Action: iface.ActionAttach, ID: "awg2",
		CreatedAt: "2026-08-27T10:00:00Z", Attach: &payload}
	err = iface.Apply(req, env, "/etc/awg3panel/config.yaml")
	if err == nil {
		t.Fatal("заявка на опущенное устройство применена, ожидался отказ")
	}
	if !strings.Contains(err.Error(), "предусловия изменились") {
		t.Errorf("отказ не называет, что предусловия изменились: %v", err)
	}
	if len(h.Calls) != 0 {
		t.Errorf("хост тронут при отказе на предусловии: %v", h.Calls)
	}
}

// TestApplyDetachRefusesWhenIDGoneSinceRequest — тот же первый шаг для
// detach: интерфейс исчез из config.yaml между сборкой заявки и её
// применением (например, оператор правил файл руками). Применять нечего, и
// бэкап писать не за чем.
func TestApplyDetachRefusesWhenIDGoneSinceRequest(t *testing.T) {
	env, h := applyEnv(t)
	env.Cfg.Interfaces = append(env.Cfg.Interfaces, config.Interface{
		ID: "awg2", Interface: "awg2",
		Config:  "/etc/amnezia/amneziawg/awg2.conf",
		Storage: config.Storage{State: "/var/lib/awg3panel/awg2/peers.json"},
	})
	h.Files["/etc/awg3panel/config.yaml"] = []byte(mustInsert(t, sampleYAML, "awg2"))
	payload, err := iface.PlanDetach("awg2", env)
	if err != nil {
		t.Fatal(err)
	}
	env.Cfg.Interfaces = env.Cfg.Interfaces[:1] // интерфейс убрали руками

	req := iface.Request{Version: 1, Action: iface.ActionDetach, ID: "awg2",
		CreatedAt: "2026-08-27T10:00:00Z", Detach: &payload}
	err = iface.Apply(req, env, "/etc/awg3panel/config.yaml")
	if err == nil {
		t.Fatal("заявка на исчезнувший интерфейс применена, ожидался отказ")
	}
	if !strings.Contains(err.Error(), "предусловия изменились") {
		t.Errorf("отказ не называет, что предусловия изменились: %v", err)
	}
	if len(h.Calls) != 0 {
		t.Errorf("хост тронут при отказе на предусловии: %v", h.Calls)
	}
}

// TestApplyReportsFailedRollback — ветка «ОТКАТ НЕ УДАЛСЯ», не покрытая до
// финального ревью ветки ни одним тестом (IMPORTANT 6). Это худший из
// возможных исходов применения и единственный, после которого оператор
// остаётся с ИЗМЕНЁННЫМ config.yaml на руках: текст этой ошибки — всё, что
// у него есть, чтобы понять, что произошло и откуда восстанавливаться.
// Поэтому проверяется не факт отказа, а содержание сообщения: оно обязано
// сказать, что откат не удался, и НАЗВАТЬ путь резервной копии.
//
// Сценарий: постусловие не прошло (устройство перестало отвечать после
// рестарта), Apply идёт в restore — и восстановительная запись config.yaml
// тоже отказывает. FailAtSkip = 1, потому что эта запись несёт то же имя
// вызова, что и успешная исходная.
func TestApplyReportsFailedRollback(t *testing.T) {
	env, h := applyEnv(t)
	payload, err := iface.PlanAttach(iface.AttachInput{
		ID: "awg2", Title: "awg2 (2.0)", ConfName: "awg2.conf",
	}, env)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	env.R = func(string) runtime.Runner {
		calls++
		if calls > 1 {
			return downRunner{} // устройство пропало ПОСЛЕ рестарта
		}
		return runtime.NewFake(sampleConf)
	}
	h.FailAt = "write /etc/awg3panel/config.yaml"
	h.FailAtSkip = 1 // первая (прямая) запись проходит, вторая (откат) — нет

	req := iface.Request{Version: 1, Action: iface.ActionAttach, ID: "awg2",
		CreatedAt: "2026-08-27T10:00:00Z", Attach: &payload}
	err = iface.Apply(req, env, "/etc/awg3panel/config.yaml")
	if err == nil {
		t.Fatal("ожидался отказ")
	}
	if !strings.Contains(err.Error(), "ОТКАТ НЕ УДАЛСЯ") {
		t.Errorf("оператор не узнает, что откат не сработал: %v", err)
	}
	if !strings.Contains(err.Error(), "/etc/awg3panel/config.yaml.bak-20260827T100000Z") {
		t.Errorf("отказ не называет резервной копии, из которой восстанавливаться: %v", err)
	}
	if !strings.Contains(err.Error(), "не отвечает") {
		t.Errorf("исходная причина потеряна за причиной отката: %v", err)
	}
	// Копия обязана существовать: без неё сообщение отсылало бы к файлу,
	// которого нет.
	if _, ok := h.Files["/etc/awg3panel/config.yaml.bak-20260827T100000Z"]; !ok {
		t.Error("резервной копии нет, хотя отказ на неё ссылается")
	}
}

func TestApplyRejectsStaleConfigRevision(t *testing.T) {
	env, host := applyEnv(t)
	configPath := "/etc/awg3panel/config.yaml"
	cfg, err := config.Parse(host.Files[configPath])
	if err != nil {
		t.Fatal(err)
	}
	cfg.Path = configPath
	env.Cfg = cfg
	plan, err := iface.PlanAttach(iface.AttachInput{ID: "awg2", ConfName: "awg2.conf"}, env)
	if err != nil || plan.ConfigRevision == "" {
		t.Fatalf("plan has no config revision: %v", err)
	}
	host.Files[configPath] = append(host.Files[configPath], []byte("\n# operator note\n")...)
	host.Calls = nil
	req := iface.Request{Version: iface.RequestVersion, Action: iface.ActionAttach, ID: "awg2", Attach: &plan}
	if err := iface.Apply(req, env, configPath); err == nil {
		t.Fatal("accepted a request with a stale config revision")
	}
	for _, call := range host.Calls {
		if strings.HasPrefix(call, "write ") || strings.HasPrefix(call, "systemctl ") {
			t.Fatalf("unexpected mutation: %s", call)
		}
	}
}
