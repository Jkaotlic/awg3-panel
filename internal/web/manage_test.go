//go:build !readonly

package web_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/iface"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/web"
	"golang.org/x/crypto/bcrypt"
)

// sampleManageConf — серверный конфиг ПОДКЛЮЧАЕМОГО интерфейса в тестах
// /api/manage. Значения обфускации выдуманы (CLAUDE.md: живые значения
// боевых хостов в тесты не попадают) — тот же образец по духу, что и
// sampleConf в internal/iface/plan_attach_test.go, но заведён здесь заново:
// пакеты разные (iface_test и web_test), общих тестовых фикстур между ними
// нет.
const sampleManageConf = `[Interface]
Address = 10.30.0.1/24
ListenPort = 3478
PrivateKey = cHJpdmF0ZS1rZXktZmFrZS0wMDAwMDAwMDAwMDAwMDAwMD0=
S1 = 40
S2 = 52
`

// newManageServer поднимает сервер с одним уже подключённым интерфейсом
// "awg3" и подставными iface.Host/Runner для маршрутов /api/manage:
// PlanAttach и PlanDetach читают "устройство" и .conf через iface.Host, а
// не напрямую с диска, поэтому тест не трогает ничего за пределами
// t.TempDir() и не зависит от реального /etc/amnezia/amneziawg. Подмена —
// через web.(*Server).SetIfaceEnvForTest (handlers_manage.go): состояние
// живёт на инстансе *Server, а не в пакетной переменной, поэтому очищать
// его после теста не нужно — предыдущая редакция (задача 9, круг 1) держала
// его в экспортированных пакетных var и требовала t.Cleanup; ревью указало
// на это как на шов шире необходимого.
//
// root — корень состояния панели (родитель requests/), тот же каталог, что
// iface.RequestsDir выводит из cfg.Interfaces[0].Storage.State. Третьим
// значением возвращается сам подставной хост: его журнал вызовов — то
// единственное, чем проверяется главное обещание архитектуры (демон пишет
// РОВНО один вид файлов и ничего не выполняет), см.
// TestConsoleWritesNothingButRequests.
func newManageServer(t *testing.T) (http.Handler, string, *iface.FakeHost) {
	t.Helper()
	root := t.TempDir()
	base := filepath.ToSlash(filepath.Join(root, "awg3"))

	hash, err := bcrypt.GenerateFromPassword([]byte("секрет"), 4)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Auth.User, cfg.Auth.Bcrypt = "admin", string(hash)
	cfg.Interfaces = []config.Interface{{
		ID: "awg3", Title: "awg3", Interface: "awg3",
		Config: "/etc/amnezia/amneziawg/awg3.conf", BinDir: "/opt/awg3/bin",
		Client: config.Client{Endpoint: "203.0.113.10:51772", AllowedIPs: "0.0.0.0/0"},
		Storage: config.Storage{
			State: base + "/peers.json", Backups: base + "/backups", Keys: base + "/keys",
		},
	}}

	reg := &fakeRegistry{
		metas:   []issuer.IfaceMeta{{ID: "awg3", Title: "awg3", Interface: "awg3"}},
		listers: map[string]web.PeerLister{"awg3": &fakeLister{}},
	}
	mutators := &fakeMutatorRegistry{byID: map[string]web.PeerMutator{"awg3": &fakeMutator{}}}
	server := web.NewServerWithMutator(cfg, reg, mutators)

	h := iface.NewFakeHost()
	h.Files["/etc/amnezia/amneziawg/awg2.conf"] = []byte(sampleManageConf)
	h.Files["/opt/awg2/bin/awg"] = []byte("бинарь")
	server.SetIfaceEnvForTest(h, func(string) runtime.Runner { return runtime.NewFake(sampleManageConf) })

	return server.Handler(), root, h
}

// jsonBody сериализует v в тело запроса. doAuthed (helpers_test.go) берёт
// io.Reader, а не произвольное значение, — локальный хелпер проще, чем
// заводить второй вариант doAuthed ради одного файла тестов.
func jsonBody(t *testing.T, v any) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b)
}

// TestPostRequestWritesFile — консоль ничего не выполняет: нажатие пишет
// заявку и только.
func TestPostRequestWritesFile(t *testing.T) {
	srv, root, _ := newManageServer(t)
	rec := doAuthed(t, srv, http.MethodPost, "/api/manage/requests",
		jsonBody(t, map[string]any{"action": "attach", "id": "awg2", "title": "awg2", "conf": "awg2.conf"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d: %s", rec.Code, rec.Body)
	}
	got, err := iface.List(filepath.Join(root, "requests"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Action != iface.ActionAttach {
		t.Fatalf("заявка не записана: %+v", got)
	}
}

// TestPreviewDoesNotWrite — предпросмотр обязан быть чистым чтением.
func TestPreviewDoesNotWrite(t *testing.T) {
	srv, root, _ := newManageServer(t)
	rec := doAuthed(t, srv, http.MethodGet,
		"/api/manage/preview?action=attach&id=awg2&conf=awg2.conf", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d: %s", rec.Code, rec.Body)
	}
	got, _ := iface.List(filepath.Join(root, "requests"))
	if len(got) != 0 {
		t.Error("предпросмотр записал заявку")
	}
}

// TestPreviewRefusalIsFourHundred — отказ раздела 7 обязан доходить до
// оператора текстом и кодом 4xx, а не превращаться в 500 «внутренняя
// ошибка»: причина отказа — это то, что оператор может исправить (третье
// требование сверх брифа задачи 9).
func TestPreviewRefusalIsFourHundred(t *testing.T) {
	srv, _, _ := newManageServer(t)
	rec := doAuthed(t, srv, http.MethodGet,
		"/api/manage/preview?action=attach&id=awg3&conf=awg2.conf", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("код = %d, ожидали 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "уже есть") {
		t.Errorf("причина отказа не дошла: %s", rec.Body)
	}
}

// TestDeleteRequestRejectsTraversal — имя заявки приходит из пути и
// недоверенно. Двойная защита: и здесь, и в iface.Cancel.
func TestDeleteRequestRejectsTraversal(t *testing.T) {
	srv, _, _ := newManageServer(t)
	rec := doAuthed(t, srv, http.MethodDelete, "/api/manage/requests/..%2f..%2fpasswd", nil)
	if rec.Code == http.StatusOK {
		t.Error("обход каталога принят")
	}
}

// TestPostRequestRejectsPathTraversalID — находка ревью сверх брифа задачи 9
// (пункт 1): iface.Save строит имя файла заявки из r.ID БЕЗ санитизации —
// это безопасно только потому, что единственный вызывающий (этот обработчик)
// получает ID, уже прошедший проверку внутри планировщика: PlanAttach —
// idRe, PlanDetach — поиск среди уже существующих id config.yaml (для
// постороннего id совпадения не будет). Оба пути возвращают отказ ИЗ
// s.plan() до того, как обработчик вообще доходит до iface.Save, — тест
// ловит регресс на границе HTTP, если это когда-нибудь перестанет быть так.
//
// Проверяются оба действия: attach (идёт через idRe) и detach (идёт через
// поиск по существующим интерфейсам) — у них разная линия защиты, и общего
// теста на одно только attach было бы недостаточно, чтобы поймать регресс
// во втором пути.
func TestPostRequestRejectsPathTraversalID(t *testing.T) {
	srv, root, _ := newManageServer(t)
	for _, tc := range []struct{ action, id string }{
		{"attach", "../evil"},
		{"attach", "a/b"},
		{"attach", ".."},
		{"detach", "../evil"},
		{"detach", "a/b"},
	} {
		rec := doAuthed(t, srv, http.MethodPost, "/api/manage/requests",
			jsonBody(t, map[string]any{"action": tc.action, "id": tc.id, "title": "x", "conf": "awg2.conf"}))
		if rec.Code >= 200 && rec.Code < 300 {
			t.Errorf("action=%s id=%q: код = %d, ожидали отказ", tc.action, tc.id, rec.Code)
		}
	}

	dir := filepath.Join(root, "requests")
	got, err := iface.List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("после отказов каталог заявок не пуст: %+v", got)
	}
	// Каталог мог быть создан ПУСТЫМ где-то на пути (свойство под проверкой —
	// отсутствие ФАЙЛОВ заявок, а не отсутствие самого каталога), поэтому
	// отсутствие каталога тоже допустимо — err от ReadDir в этом случае
	// игнорируется намеренно.
	if ents, err := os.ReadDir(dir); err == nil && len(ents) != 0 {
		t.Errorf("в каталоге заявок остались файлы после отказа: %v", ents)
	}
}

// TestPreviewOnEmptyInterfacesDoesNotPanic — находка ревью задачи 9, круг 2
// («мелочь того же места», что уже чинили в PlanAttach). manageEnv строит
// iface.Env из s.cfg.Interfaces[0] безусловно; гарантия «в config.yaml есть
// хотя бы один интерфейс» живёт ВЫШЕ по стеку (config.Validate при загрузке
// конфига), а не внутри самого HTTP-обработчика — тот же довод, что уже
// записан комментарием у PlanAttach про env.Cfg.Interfaces[0] и у
// iface.RequestsDir. Без защиты внутри manageEnv пустой Cfg.Interfaces даёт
// панику (index out of range) РАНЬШЕ, чем успевает сработать собственный
// отказ PlanAttach «неоткуда позаимствовать публичный адрес».
func TestPreviewOnEmptyInterfacesDoesNotPanic(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("секрет"), 4)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Auth.User, cfg.Auth.Bcrypt = "admin", string(hash)
	cfg.Interfaces = nil // ни одного интерфейса в config.yaml
	srv := web.NewServerWithMutator(cfg,
		&fakeRegistry{}, &fakeMutatorRegistry{byID: map[string]web.PeerMutator{}}).Handler()

	rec := doAuthed(t, srv, http.MethodGet,
		"/api/manage/preview?action=attach&id=awg2&conf=awg2.conf", nil)
	if rec.Code < 400 || rec.Code >= 500 {
		t.Fatalf("код = %d, ожидали отказ 4xx (например, «неоткуда позаимствовать адрес»), "+
			"а не панику и не 500", rec.Code)
	}
}

// TestConsoleWritesNothingButRequests — главное обещание архитектуры
// (спека 2026-08-25, раздел 3.1: демон панели «ничего не выполняет»),
// которое до финального ревью ветки не проверял ни один тест. Обещание было
// структурным доводом — «в handlers_manage.go нет вызовов systemctl» —
// а структурный довод перестаёт быть верным ровно в тот момент, когда
// кто-то допишет строчку.
//
// Проверяется по ЖУРНАЛУ подставного хоста, потому что журнал пишет ровно
// то, чем демон трогает машину: запись файла, создание каталога, systemctl.
// Чтение (ReadFile/Exists/DirEmpty) в журнал не попадает намеренно — читать
// консоли можно и нужно.
//
// Утверждений два, и они разные:
//   - после ЛЮБОГО GET журнал пуст: чтение обязано быть чистым чтением, и
//     это сильнее, чем «файла заявки не появилось» (прежний
//     TestPreviewDoesNotWrite смотрел только на каталог заявок и прошёл бы
//     при mkdir /var/lib, systemctl restart или записи куда угодно ещё);
//   - после POST в журнале нет ни systemctl, ни mkdir: заявка — файл, а не
//     действие; всё исполнение живёт в `awg3panel iface apply` за пределами
//     песочницы демона. Сам файл заявки пишется через os в iface.Save (свой,
//     разрешённый песочницей каталог /var/lib/awg3panel), а не через Host,
//     поэтому в журнале Host его и не должно быть.
func TestConsoleWritesNothingButRequests(t *testing.T) {
	srv, _, h := newManageServer(t)

	for _, url := range []string{
		"/api/manage/adoptable",
		"/api/manage/preview?action=attach&id=awg2&title=awg2&conf=awg2.conf",
		"/api/manage/preview?action=detach&id=awg3",
		"/api/manage/requests",
	} {
		h.Calls = nil
		doAuthed(t, srv, http.MethodGet, url, nil)
		if len(h.Calls) != 0 {
			t.Errorf("GET %s тронул хост: %v", url, h.Calls)
		}
	}

	h.Calls = nil
	rec := doAuthed(t, srv, http.MethodPost, "/api/manage/requests",
		jsonBody(t, map[string]any{"action": "attach", "id": "awg2", "title": "awg2", "conf": "awg2.conf"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d: %s", rec.Code, rec.Body)
	}
	for _, c := range h.Calls {
		if strings.HasPrefix(c, "systemctl ") || strings.HasPrefix(c, "mkdir ") {
			t.Errorf("запись заявки выполнила действие на хосте: %q (весь журнал: %v)", c, h.Calls)
		}
	}
}

// TestRequestSurvivesWebToCLISeam — сквозной круг «заявка, записанная
// HTTP-обработчиком → прочитанная iface.List → применённая iface.Apply»,
// не покрытый до финального ревью ветки (IMPORTANT 6). Шов между вебом и
// CLI держался только на общем типе iface.Request: демон СЕРИАЛИЗУЕТ
// заявку в JSON на диск, а исполнитель разбирает её ЗАНОВО, строгим
// Parse с DisallowUnknownFields, в другом процессе и, вообще говоря, в
// другой версии бинаря. Поле, потерянное или переименованное на этом
// переходе, не поймал бы ни один тест по обе стороны шва: у веба заявка
// «записана», у iface.Apply — «применена», а на боевом хосте между ними
// лежит файл.
//
// Здесь круг замкнут целиком на подставном хосте: тот же FakeHost, который
// консоль читала при сборке заявки, несёт и config.yaml, который правит
// исполнитель.
func TestRequestSurvivesWebToCLISeam(t *testing.T) {
	srv, root, h := newManageServer(t)

	// config.yaml НА ДИСКЕ описывает тот же awg3, что несёт cfg сервера, —
	// включая пути хранилища внутри t.TempDir(). Иначе корень состояния,
	// выведенный консолью (iface.StateRoot по её cfg), разошёлся бы с тем,
	// что тест подставляет исполнителю, и сверка пересчитанного плана с
	// заявкой честно отвергла бы заявку — не потому, что шов сломан.
	//
	// Строка `- id:` подписана хвостовым комментарием: ровно так её кладёт
	// install.sh, копируя deploy/config.example.yaml дословно.
	const configPath = "/etc/awg3panel/config.yaml"
	base := filepath.ToSlash(filepath.Join(root, "awg3"))
	before := `listen: "10.11.0.1:8081"

auth:
  user: "admin"
  bcrypt: "$2b$12$FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA"

interfaces:
  - id: awg3                # подпись строки — как в deploy/config.example.yaml
    title: "awg3"
    interface: awg3
    config: /etc/amnezia/amneziawg/awg3.conf
    bin_dir: /opt/awg3/bin
    client:
      endpoint: "203.0.113.10:51772"
      allowed_ips: "0.0.0.0/0"
    storage:
      state: ` + base + `/peers.json
      backups: ` + base + `/backups
      keys: ` + base + `/keys
`
	h.Files[configPath] = []byte(before)

	// 1. Консоль: нажатие «Подключить» пишет заявку и только.
	rec := doAuthed(t, srv, http.MethodPost, "/api/manage/requests",
		jsonBody(t, map[string]any{"action": "attach", "id": "awg2", "title": "awg2 (2.0)", "conf": "awg2.conf"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d: %s", rec.Code, rec.Body)
	}

	// 2. Исполнитель: читает заявку С ДИСКА тем же List, что и `awg3panel
	// iface requests`, — строгим разбором, а не структурой из памяти.
	reqs, err := iface.List(filepath.Join(root, "requests"))
	if err != nil {
		t.Fatalf("заявка, записанная вебом, не читается исполнителем: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("заявок %d, ожидали 1", len(reqs))
	}

	// 3. Применение — тем же Env, что построила бы консоль (см.
	// TestManageEnvUsesSharedRoots и TestIfaceEnvUsesSharedRoots).
	loaded := cfgOf(t, before)
	env := iface.Env{
		Cfg: loaded, ConfDir: iface.DefaultConfDir,
		StateRoot: iface.StateRoot(loaded), BinRoot: iface.DefaultBinRoot, H: h,
		R: func(string) runtime.Runner { return runtime.NewFake(sampleManageConf) },
	}
	if err := iface.Apply(reqs[0], env, configPath); err != nil {
		t.Fatalf("заявка, собранная вебом, не применяется: %v", err)
	}

	// 4. Постусловие круга: config.yaml на диске грузится настоящим
	// загрузчиком и несёт оба интерфейса, а у нового не потерян ни endpoint
	// (выведенный из .conf), ни джиттер (посеянный планировщиком).
	got := cfgOf(t, string(h.Files[configPath]))
	if len(got.Interfaces) != 2 {
		t.Fatalf("интерфейсов %d, ожидали 2:\n%s", len(got.Interfaces), h.Files[configPath])
	}
	added := got.Interfaces[1]
	if added.ID != "awg2" || added.Interface != "awg2" {
		t.Errorf("подключён не тот интерфейс: %+v", added)
	}
	if added.Client.Endpoint != "203.0.113.10:3478" {
		t.Errorf("endpoint = %q, ожидали адрес первого интерфейса с портом из .conf", added.Client.Endpoint)
	}
	if added.Client.Jc == 0 || added.Client.Jmin == 0 || added.Client.Jmax == 0 {
		t.Errorf("джиттер потерян на шве веб → CLI: %+v", added.Client)
	}
	if added.Client.PersistentKeepalive == "" {
		t.Error("persistent_keepalive потерян на шве веб → CLI")
	}
}

// cfgOf грузит текст настоящим config.Load через временный файл: проверять
// итог хирургии чем-то, кроме настоящего загрузчика, значит проверять не то,
// что панель прочитает при старте.
func cfgOf(t *testing.T, text string) *config.Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("config.yaml не грузится: %v\n%s", err, text)
	}
	return cfg
}
