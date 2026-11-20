package web_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/web"
	"golang.org/x/crypto/bcrypt"
)

type fakeLister struct {
	peers   []issuer.PeerView
	summary issuer.IfaceSummary
	err     error
}

func (f *fakeLister) List() ([]issuer.PeerView, error) { return f.peers, f.err }

func (f *fakeLister) Summary() (issuer.IfaceSummary, error) { return f.summary, f.err }

// fakeRegistry — тестовая реализация web.Registry: метаданные и листеры
// заданы напрямую, без обращения к issuer или файловой системе. Файл без
// build-тега (задача 10) — используется и полной, и readonly сборкой
// тестов, поэтому не может жить в mutate_test.go (тег !readonly).
type fakeRegistry struct {
	metas   []issuer.IfaceMeta
	listers map[string]web.PeerLister
}

func (f *fakeRegistry) Metas() []issuer.IfaceMeta { return f.metas }

func (f *fakeRegistry) Lister(id string) (web.PeerLister, bool) {
	l, ok := f.listers[id]
	return l, ok
}

// twoIfaceRegistry строит реестр с двумя интерфейсами — "awg3" (без правки
// [Interface]) и "awg31" (с разрешённой правкой) — каждый со своим фейковым
// листером, отдающим узнаваемого по имени пира. Так тесты маршрутизации
// видят, что список пришёл именно от запрошенного интерфейса, а не от
// первого попавшегося или от чужого.
func twoIfaceRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	return &fakeRegistry{
		metas: []issuer.IfaceMeta{
			{ID: "awg3", Title: "awg3", Interface: "awg3", InterfaceEdit: false},
			{ID: "awg31", Title: "awg3.1", Interface: "awg3.1", InterfaceEdit: true},
		},
		listers: map[string]web.PeerLister{
			"awg3": &fakeLister{
				peers:   []issuer.PeerView{{ID: "p1", Name: "пир-из-awg3"}},
				summary: issuer.IfaceSummary{Interface: "awg3", ListenPort: 51772, PeersTotal: 1},
			},
			"awg31": &fakeLister{peers: []issuer.PeerView{{ID: "p2", Name: "пир-из-awg31"}}},
		},
	}
}

// newTestServer строит read-only обработчик поверх заданного реестра —
// замена прежнего testServer(t, lister) (задача 10 перевела Server с
// одиночного config.Interface+PeerLister на Registry).
func newTestServer(t *testing.T, reg web.Registry) http.Handler {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("секрет"), 4)
	cfg := config.Default()
	cfg.Auth.User = "admin"
	cfg.Auth.Bcrypt = string(hash)
	return web.NewServer(cfg, reg).Handler()
}

func TestIndexServesHTML(t *testing.T) {
	h := newTestServer(t, twoIfaceRegistry(t))
	rec := doAuthed(t, h, http.MethodGet, "/", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
}

// TestIndexShowsInterfaceNameEscaped — адаптация прежней проверки под
// реестр интерфейсов (задача 10): раньше единственное имя интерфейса
// приходило в шаблон полем Interface из config.Interface, теперь — полем
// Title элемента среза Ifaces из Registry.Metas(). Смысл проверки не
// изменился: (1) шаблон действительно подставляет данные реестра, а не
// показывает статический текст — доказывается заведомо уникальной строкой
// со спецсимволами HTML; (2) html/template экранирует её при подстановке, а
// не вставляет сырой. Полноценный переключатель с data-iface — задача 11;
// здесь временный список в шапке (см. assets/index.html), который она
// заменит.
func TestIndexShowsInterfaceNameEscaped(t *testing.T) {
	title := `awg3-тест-<script>`
	reg := &fakeRegistry{
		metas:   []issuer.IfaceMeta{{ID: "awg3", Title: title, Interface: "awg3"}},
		listers: map[string]web.PeerLister{"awg3": &fakeLister{}},
	}
	h := newTestServer(t, reg)

	rec := doAuthed(t, h, http.MethodGet, "/", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d", rec.Code)
	}
	body := rec.Body.String()

	if strings.Contains(body, title) {
		t.Errorf("название интерфейса вставлено сырым, без экранирования: %q найдено в теле как есть", title)
	}
	escaped := template.HTMLEscapeString(title)
	if !strings.Contains(body, escaped) {
		t.Errorf("экранированное название интерфейса не найдено в теле: ожидали %q", escaped)
	}
	if !strings.Contains(body, "режим только чтения") {
		t.Error("не найдена плашка «режим только чтения»")
	}
}

// TestIndexRendersAllInterfaces — задача 11: переключатель интерфейсов в
// шапке рисует КАЖДЫЙ интерфейс реестра как отдельную кнопку с data-iface
// (JS находит их по этому атрибуту, а не по количеству/порядку — см.
// assets/index.html) и помечает data-edit тех, для кого правка
// [Interface] разрешена в config.yaml. Слой 2: вёрстка тестами не
// покрывается, но это ровно та логика, которая покрывается — шаблон
// действительно получает список интерфейсов и отражает его поля, а не
// рисует статическую разметку под один заранее известный интерфейс.
func TestIndexRendersAllInterfaces(t *testing.T) {
	srv := newTestServer(t, twoIfaceRegistry(t))
	rec := doAuthed(t, srv, http.MethodGet, "/", nil)
	body := rec.Body.String()
	for _, want := range []string{`data-iface="awg3"`, `data-iface="awg31"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("в разметке нет %s", want)
		}
	}
	if strings.Contains(body, "awg31") && !strings.Contains(body, `data-edit="true"`) {
		t.Fatal("интерфейс с разрешённой правкой обязан быть помечен в разметке")
	}
}

// TestIndexEmbedsSummaryThresholds — финальный fix-wave перед мержем
// feature/console-redesign: пороги «онлайн» (180 с) и «нет связи» (24 ч)
// задублированы намеренно между issuer.OnlineWindow/StaleAfter и JS-
// константами ONLINE_WINDOW/STALE_AFTER в assets/index.html (см. комментарий
// там же) — гонять их через API ради устранения дубля значило бы завести
// поля, которые никто не читает. Но до этого теста ничего не мешало им
// разъехаться незаметно: оба набора тестов (issuer и web) остались бы
// зелёными по отдельности, а плитка сводки «Без связи дольше суток» начала
// бы спорить с цветными подписями строк, которые сама же и считает. Тест
// делает Go-константы источником правды: строит ожидаемую JS-строку из них и
// требует её точного присутствия в отданной разметке — а не просто наличия
// числа 180 или 86400 где-то в файле.
func TestIndexEmbedsSummaryThresholds(t *testing.T) {
	h := newTestServer(t, twoIfaceRegistry(t))
	rec := doAuthed(t, h, http.MethodGet, "/", nil)
	body := rec.Body.String()

	want := fmt.Sprintf("const ONLINE_WINDOW = %d, STALE_AFTER = %d;",
		int(issuer.OnlineWindow.Seconds()), int(issuer.StaleAfter.Seconds()))
	if !strings.Contains(body, want) {
		t.Fatalf("в разметке нет %q — JS-пороги разошлись с issuer.OnlineWindow/issuer.StaleAfter", want)
	}
}

// --- Задача 10: маршрутизация по интерфейсам ---

func TestPeersRoutedByInterface(t *testing.T) {
	srv := newTestServer(t, twoIfaceRegistry(t))
	rec := doAuthed(t, srv, http.MethodGet, "/api/ifaces/awg31/peers", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "пир-из-awg31") {
		t.Fatalf("отдан список не того интерфейса: %s", rec.Body.String())
	}
	rec = doAuthed(t, srv, http.MethodGet, "/api/ifaces/нет-такого/peers", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("неизвестный интерфейс: код %d, ожидался 404", rec.Code)
	}
}

func TestIfacesListExposesEditFlag(t *testing.T) {
	srv := newTestServer(t, twoIfaceRegistry(t))
	rec := doAuthed(t, srv, http.MethodGet, "/api/ifaces", nil)
	var got []issuer.IfaceMeta
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].InterfaceEdit || !got[1].InterfaceEdit {
		t.Fatalf("флаги правки доехали неверно: %+v", got)
	}
}

func TestAPIPeersReturnsJSON(t *testing.T) {
	reg := &fakeRegistry{
		metas: []issuer.IfaceMeta{{ID: "awg3", Title: "awg3", Interface: "awg3"}},
		listers: map[string]web.PeerLister{"awg3": &fakeLister{peers: []issuer.PeerView{
			{ID: "abc123", Name: "мой-телефон", Address: "10.11.0.4/32", Enabled: true, LastHandshake: 1754049600},
		}}},
	}
	h := newTestServer(t, reg)
	rec := doAuthed(t, h, http.MethodGet, "/api/ifaces/awg3/peers", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d, тело: %s", rec.Code, rec.Body)
	}
	var got []issuer.PeerView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("ответ не JSON-массив: %v", err)
	}
	if len(got) != 1 || got[0].Name != "мой-телефон" {
		t.Errorf("ответ = %+v", got)
	}
}

func TestAPIPeersRequiresAuth(t *testing.T) {
	h := newTestServer(t, twoIfaceRegistry(t))
	req := httptest.NewRequest(http.MethodGet, "/api/ifaces/awg3/peers", nil)
	req.RemoteAddr = "10.11.0.2:40000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("код = %d, ожидался 401 — панель не должна отдавать данные без пароля", rec.Code)
	}
}

func TestIndexRequiresAuth(t *testing.T) {
	h := newTestServer(t, twoIfaceRegistry(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.11.0.2:40000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("код = %d, ожидался 401", rec.Code)
	}
}

func TestAPIErrorIsJSON(t *testing.T) {
	reg := &fakeRegistry{
		metas:   []issuer.IfaceMeta{{ID: "awg3", Title: "awg3", Interface: "awg3"}},
		listers: map[string]web.PeerLister{"awg3": &fakeLister{err: errors.New("конфиг не читается")}},
	}
	h := newTestServer(t, reg)
	rec := doAuthed(t, h, http.MethodGet, "/api/ifaces/awg3/peers", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("код = %d, ожидался 500", rec.Code)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("ошибка отдана не в JSON: %v (%s)", err, rec.Body)
	}
	if body.Error == "" {
		t.Error("поле error пусто")
	}
}

// TestAPIErrorHidesDetailsFromClient — защита в глубину поверх фикса в wgconf:
// тело HTTP-ответа не должно ходом ошибки уносить наружу что бы то ни было из
// исходного err.Error(), даже если он однажды снова окажется чувствительным
// (баг в issuer, в wgconf, в чём угодно ниже). Подробность — только в логе,
// клиенту — родовая формулировка. См. CLAUDE.md, п.4 (ключи и PSK не в логах,
// а тем более не в ответах, которые оседают в истории браузера).
func TestAPIErrorHidesDetailsFromClient(t *testing.T) {
	secret := "PrivateKey = zQ8mLpX2vRtNfYkBsWqAoCuHjGiEnDkVxZbTcPd9AbCd="
	reg := &fakeRegistry{
		metas: []issuer.IfaceMeta{{ID: "awg3", Title: "awg3", Interface: "awg3"}},
		listers: map[string]web.PeerLister{
			"awg3": &fakeLister{err: errors.New("разбор конфига: строка 3: " + secret)},
		},
	}
	h := newTestServer(t, reg)
	rec := doAuthed(t, h, http.MethodGet, "/api/ifaces/awg3/peers", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("код = %d, ожидался 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("тело ответа содержит подробности внутренней ошибки: %s", rec.Body)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("ошибка отдана не в JSON: %v (%s)", err, rec.Body)
	}
	if body.Error == "" {
		t.Error("поле error пусто")
	}
}

func TestUnknownPath404(t *testing.T) {
	h := newTestServer(t, twoIfaceRegistry(t))
	if rec := doAuthed(t, h, http.MethodGet, "/api/нет-такого", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("код = %d, ожидался 404", rec.Code)
	}
}

// --- Fix round 1, Important 5: защита от CSRF ---
//
// Пишущие маршруты появились в Task 13, и вместе с ними — кросс-сайтовый
// риск: POST с телом text/plain уходит из чужой формы без preflight, а
// браузер сам подставляет к нему кэшированные учётные данные Basic для
// целевого источника. Оператору достаточно с открытой панелью зайти на
// чужую страницу. Проверка живёт в middleware, то есть покрывает и те
// маршруты, которых в read-only сборке нет.

func csrfRequest(t *testing.T, h http.Handler, method, path, header, value string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(`{"name":"x"}`))
	req.RemoteAddr = "10.11.0.2:40000"
	req.SetBasicAuth("admin", "секрет")
	if header != "" {
		if value == "@same" {
			value = "http://" + req.Host
		}
		req.Header.Set(header, value)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestCrossSiteWriteIsRejected(t *testing.T) {
	h := newTestServer(t, twoIfaceRegistry(t))
	for _, c := range []struct{ name, header, value string }{
		{"чужой Origin", "Origin", "http://evil.example"},
		{"Origin: null (песочница или file://)", "Origin", "null"},
		{"Sec-Fetch-Site: cross-site", "Sec-Fetch-Site", "cross-site"},
		{"Sec-Fetch-Site: same-site (другой порт того же хоста)", "Sec-Fetch-Site", "same-site"},
	} {
		rec := csrfRequest(t, h, http.MethodPost, "/api/ifaces/awg3/peers", c.header, c.value)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: код = %d, ожидался 403 — запрос пришёл с чужой страницы", c.name, rec.Code)
			continue
		}
		// Формат тела — общий для всех ошибок API: страница разбирает ответ
		// через JSON.parse и на обычном тексте показала бы «Unexpected token»
		// вместо причины отказа.
		var body struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Errorf("%s: тело отдано не в JSON: %v (%s)", c.name, err, rec.Body)
			continue
		}
		if body.Error == "" {
			t.Errorf("%s: поле error пусто — причина отказа до пользователя не дойдёт", c.name)
		}
	}
}

func TestSameOriginWriteIsNotRejected(t *testing.T) {
	h := newTestServer(t, twoIfaceRegistry(t))
	for _, c := range []struct{ name, header, value string }{
		{"Origin совпадает с Host", "Origin", "@same"},
		{"Sec-Fetch-Site: same-origin", "Sec-Fetch-Site", "same-origin"},
		{"Sec-Fetch-Site: none (ввод в адресной строке)", "Sec-Fetch-Site", "none"},
		// Ни Origin, ни Sec-Fetch-* — не браузер (curl, скрипт). Такой клиент
		// не носит с собой чужих учётных данных, значит и CSRF-вектором не
		// является; отказ здесь сломал бы работу с панелью из терминала.
		{"без заголовков источника", "", ""},
	} {
		rec := csrfRequest(t, h, http.MethodPost, "/api/ifaces/awg3/peers", c.header, c.value)
		if rec.Code == http.StatusForbidden {
			t.Errorf("%s: запрос отклонён как кросс-сайтовый, хотя он свой", c.name)
		}
	}
}

// TestCrossSiteReadIsAllowed фиксирует границу защиты: GET не меняет
// состояние, а прочитать ответ чужая страница всё равно не сможет — CORS не
// разрешён ни одному источнику. Блокировать чтения значило бы сломать саму
// страницу панели без выигрыша.
func TestCrossSiteReadIsAllowed(t *testing.T) {
	h := newTestServer(t, twoIfaceRegistry(t))
	rec := csrfRequest(t, h, http.MethodGet, "/api/ifaces/awg3/peers", "Origin", "http://evil.example")
	if rec.Code != http.StatusOK {
		t.Errorf("код = %d, ожидался 200: чтения не должны отвергаться", rec.Code)
	}
}

func TestNoCacheHeadersOnAPI(t *testing.T) {
	h := newTestServer(t, twoIfaceRegistry(t))
	rec := doAuthed(t, h, http.MethodGet, "/api/ifaces/awg3/peers", nil)
	if rec.Header().Get("Cache-Control") == "" {
		t.Error("нет Cache-Control — браузер закеширует список пиров")
	}
}

// --- Задача 4: сводка по интерфейсу ---

func TestSummaryОтдаётСводкуЗапрошенногоИнтерфейса(t *testing.T) {
	h := newTestServer(t, twoIfaceRegistry(t))
	rec := doAuthed(t, h, http.MethodGet, "/api/ifaces/awg3/summary", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, тело %s", rec.Code, rec.Body.String())
	}
	var got issuer.IfaceSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("разбор ответа: %v", err)
	}
	if got.Interface != "awg3" || got.ListenPort != 51772 {
		t.Errorf("сводка пришла не от запрошенного интерфейса: %+v", got)
	}
}

func TestSummaryНеизвестныйИнтерфейс(t *testing.T) {
	h := newTestServer(t, twoIfaceRegistry(t))
	rec := doAuthed(t, h, http.MethodGet, "/api/ifaces/неттакого/summary", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("код %d, ожидалось 404", rec.Code)
	}
}

// --- Задача 5 (спека 2026-08-25, раздел 5.6): предупреждение о несоответствии профиля мимикрии порту ---

// TestIndexShowsMimicryWarnContainer — файл без тега readonly, значит
// компилируется и проверяется В ОБЕИХ сборках. Предупреждение о
// несоответствии — ЧТЕНИЕ сводки, а не элемент управления (в отличие от
// селекторов профиля у кнопки «Сгенерировать I1», которые — часть
// мутирующей консоли и живут внутри гейта not .ReadOnly), поэтому его
// контейнер обязан присутствовать в разметке read-only сборки так же, как в
// полной. Текст внутрь кладёт скрипт из ответа /summary во время
// выполнения — здесь проверяется только сам контейнер: это единственное,
// что видно в шаблоне без исполнения JS.
func TestIndexShowsMimicryWarnContainer(t *testing.T) {
	rec := doAuthed(t, newTestServer(t, twoIfaceRegistry(t)), http.MethodGet, "/", nil)
	if !strings.Contains(rec.Body.String(), `id="mimicrywarn"`) {
		t.Error("в разметке нет контейнера предупреждения о несоответствии профиля мимикрии рядом со #srvline")
	}
}

// TestProxyRewrittenHostTrustsSecFetchSite — панель за двумя прокси
// (main → nl2, 07.09.2026): внешний Caddy подменяет Host под SNI
// внутреннего, и Origin браузера (https://nl2.panel.example.com)
// перестаёт совпадать с Host запроса (panel.example.net), хотя
// страница и API — один источник. Sec-Fetch-Site ставит сам браузер
// (forbidden header, скрипт его не подделает) относительно адреса, который
// ОН запрашивал, поэтому при его наличии он и решает; Origin остаётся
// запасным путём для клиентов без Sec-Fetch-*.
func TestProxyRewrittenHostTrustsSecFetchSite(t *testing.T) {
	h := newTestServer(t, twoIfaceRegistry(t))
	req := httptest.NewRequest(http.MethodPost, "/api/ifaces/awg3/peers", strings.NewReader(`{"name":"x"}`))
	req.RemoteAddr = "10.11.0.2:40000"
	req.SetBasicAuth("admin", "секрет")
	req.Header.Set("Origin", "https://nl2.panel.example.com")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("запрос с Sec-Fetch-Site: same-origin отклонён из-за подменённого прокси Host: %s", rec.Body)
	}

	// Обратная сторона: совпавший Origin не спасает, если браузер сам
	// говорит, что запрос кросс-сайтовый.
	req = httptest.NewRequest(http.MethodPost, "/api/ifaces/awg3/peers", strings.NewReader(`{"name":"x"}`))
	req.RemoteAddr = "10.11.0.2:40000"
	req.SetBasicAuth("admin", "секрет")
	req.Header.Set("Origin", "http://"+req.Host)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("код = %d, ожидался 403: браузер пометил запрос как cross-site", rec.Code)
	}
}

func TestIndexПоказываетConfigWarnings(t *testing.T) {
	h := newTestServer(t, twoIfaceRegistry(t))
	body := doAuthed(t, h, http.MethodGet, "/", nil).Body.String()
	for _, want := range []string{`id="ifacewarn"`, "config_warnings"} {
		if !strings.Contains(body, want) {
			t.Errorf("в разметке нет %q", want)
		}
	}
}
