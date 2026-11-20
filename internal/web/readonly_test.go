//go:build readonly

package web_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/web"
)

// Компиляционное доказательство того, ради чего существует раздел 12.1
// спеки: в read-only сборке web.PeerMutator и web.MutatorRegistry не имеют
// НИ ОДНОГО метода — пустая структура удовлетворяет обоим. Значит в бинаре
// нет ни Add, ни Remove, ни Update, ни Rotate, ни SetDefaults — вызывать
// нечего, а не «выключено флагом».
//
// Эта строка и есть гейт: в полной сборке PeerMutator и MutatorRegistry
// требуют методов, и файл просто НЕ СКОМПИЛИРУЕТСЯ, если кто-нибудь снимет
// тег readonly или начнёт объявлять мутации вне тега. Проверка времени
// выполнения такого доказать не может — отсутствие символа не наблюдаемо
// изнутри программы.
var _ web.PeerMutator = struct{}{}
var _ web.MutatorRegistry = struct{}{}

// Этап A (раздел 12.1 спеки): бинарь физически не умеет писать.
func TestReadOnlyBuildHasNoMutationRoutes(t *testing.T) {
	if !web.ReadOnlyBuild {
		t.Fatal("сборка с тегом readonly не помечена как read-only")
	}
	h := newTestServer(t, twoIfaceRegistry(t))
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/ifaces/awg3/peers"},
		{http.MethodDelete, "/api/ifaces/awg3/peers/abc123"},
		{http.MethodPost, "/api/ifaces/awg3/peers/abc123/disable"},
		{http.MethodPost, "/api/ifaces/awg3/peers/abc123/enable"},
		// Выдача конфига и QR регистрируется тем же registerMutations и в
		// read-only сборке обязана отсутствовать наравне с мутациями:
		// клиентский .conf содержит приватный ключ пира.
		{http.MethodGet, "/api/ifaces/awg3/peers/abc123/config"},
		{http.MethodGet, "/api/ifaces/awg3/peers/abc123/qr"},
		// Ссылка vpn:// несёт тот же приватный ключ (спека 2026-10-29, раздел 6).
		{http.MethodGet, "/api/ifaces/awg3/peers/abc123/vpnuri"},
		{http.MethodGet, "/api/ifaces/awg3/peers/abc123/vpnqr"},
	} {
		rec := doAuthed(t, h, c.method, c.path, strings.NewReader(`{"name":"x"}`))
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: код = %d, ожидался 404/405 — обработчика не должно существовать",
				c.method, c.path, rec.Code)
		}
	}
}

// TestReadonlyBuildHasNoEditRoutes — задача 10 (правка пира, ротация,
// умолчания): три новых маршрута обязаны отсутствовать в read-only сборке
// наравне со старыми. PATCH — без завершающего слэша (поправка 1
// контролёра к брифу: DELETE и PATCH различаются как образцы net/http по
// методу, а не по слэшу).
func TestReadonlyBuildHasNoEditRoutes(t *testing.T) {
	srv := newTestServer(t, twoIfaceRegistry(t))
	for _, c := range []struct{ method, path string }{
		{http.MethodPatch, "/api/ifaces/awg3/peers/abc123"},
		{http.MethodPost, "/api/ifaces/awg3/peers/abc123/rotate"},
		{http.MethodPut, "/api/ifaces/awg3/defaults"},
	} {
		rec := doAuthed(t, srv, c.method, c.path, strings.NewReader("{}"))
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: код %d — в read-only сборке маршрута быть не должно", c.method, c.path, rec.Code)
		}
	}
}

// Сводка — чтение, и в read-only сборке она обязана быть: такая панель
// показывает состояние сервера, она просто ничего не меняет.
func TestReadOnlySummaryДоступна(t *testing.T) {
	h := newTestServer(t, twoIfaceRegistry(t))
	rec := doAuthed(t, h, http.MethodGet, "/api/ifaces/awg3/summary", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d в read-only сборке, ожидалось 200", rec.Code)
	}
}

func TestReadOnlyIndexShowsBadge(t *testing.T) {
	rec := doAuthed(t, newTestServer(t, twoIfaceRegistry(t)), http.MethodGet, "/", nil)
	if !strings.Contains(rec.Body.String(), "только чтения") {
		t.Error("страница не сообщает, что панель в режиме только чтения")
	}
	// Разметка тоже не должна предлагать того, чего бинарь не умеет:
	// кнопка, дающая 404, — это не «панель только для чтения», это баг.
	// "/peers/" (со слэшем) заменяет прежний литерал "/api/peers/" (задача 11
	// перевела JS на динамическую сборку пути через api()/apiURL()) — см.
	// тот же комментарий в TestFullBuildIndexHasActionControls.
	for _, forbidden := range []string{"Добавить", "Действия", "/peers/"} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Errorf("в read-only разметке есть элемент управления мутацией: %q", forbidden)
		}
	}
}

// TestReadonlyBuildHasNoInterfaceParamsRoute — задача 9. Генератор комплекта
// параметров обфускации ничего не применяет, но и в read-only сборке ему
// делать нечего: такая панель — окно наблюдателя, а не рабочее место
// оператора, поднимающего новый туннель. Маршрут висит в registerMutations
// по тому же рассуждению, что и /generate/jitter, и в этой сборке его нет.
func TestReadonlyBuildHasNoInterfaceParamsRoute(t *testing.T) {
	srv := newTestServer(t, twoIfaceRegistry(t))
	rec := doAuthed(t, srv, http.MethodGet, "/api/ifaces/awg3/generate/interface-params", nil)
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("код %d — в read-only сборке маршрута быть не должно", rec.Code)
	}
}

// TestReadonlyBuildHasNoSignatureRoute — задача 3 (спека 2026-08-24):
// генератор I1 ничего не применяет и не читает состояние интерфейса, но и
// в read-only сборке ему делать нечего — то же рассуждение, что и у
// TestReadonlyBuildHasNoInterfaceParamsRoute: маршрут висит в
// registerMutations, а read-only панель — окно наблюдателя.
func TestReadonlyBuildHasNoSignatureRoute(t *testing.T) {
	srv := newTestServer(t, twoIfaceRegistry(t))
	rec := doAuthed(t, srv, http.MethodPost, "/api/ifaces/awg3/generate/signature", nil)
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("код %d — в read-only сборке маршрута быть не должно", rec.Code)
	}
}

// TestReadOnlyIndexHasNoNewInterfaceTab — обратная сторона
// TestFullBuildIndexHasNewInterfaceTab: кнопка, ведущая на маршрут, которого
// в бинаре нет, — это не «панель только для чтения», это баг (то же
// рассуждение, что и у TestReadOnlyIndexShowsBadge).
func TestReadOnlyIndexHasNoNewInterfaceTab(t *testing.T) {
	rec := doAuthed(t, newTestServer(t, twoIfaceRegistry(t)), http.MethodGet, "/", nil)
	for _, forbidden := range []string{"newiface", "Новый интерфейс", "/generate/interface-params"} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Errorf("в read-only разметке есть элемент генератора: %q", forbidden)
		}
	}
}

// TestReadOnlyIndexHasNoManageTab — обратная сторона TestIndexHasManageTab
// (задача 10, manage_ui_test.go, тег !readonly): вкладка «Интерфейсы»
// пишет заявки через маршруты /api/manage/…, зарегистрированные только в
// registerManage (handlers_manage.go, тег !readonly) — в read-only бинаре
// их нет физически, и кнопка, ведущая на такой маршрут, была бы багом (то
// же рассуждение, что у TestReadOnlyIndexHasNoNewInterfaceTab выше).
//
// Проверка по рендеренному тексту вкладки (">Интерфейсы<"), а не по голой
// подстроке «Интерфейсы»: слово встречается и в русскоязычных комментариях
// общего скрипта (typeof-guard на loadManageTab, который существует в
// обеих сборках намеренно — см. index.html) — эти комментарии никогда не
// видны оператору и не означают наличия функциональности, а бинарный тест
// проверяет ровно то, что видит браузер.
func TestReadOnlyIndexHasNoManageTab(t *testing.T) {
	rec := doAuthed(t, newTestServer(t, twoIfaceRegistry(t)), http.MethodGet, "/", nil)
	body := rec.Body.String()
	// id="pending" — полоса неприменённых заявок. Отдельная от вкладки
	// подстрока намеренно: полоса живёт в СВОЁМ гейте not .ReadOnly, выше по
	// разметке, и наполняется GET /api/manage/requests — маршрутом, которого
	// в read-only бинаре нет. Прежний список её не проверял, то есть гейт
	// полосы держался ни на чём: убери его кто-нибудь — и read-only панель
	// начала бы раз в несколько секунд стучаться в несуществующий маршрут,
	// а в консоли браузера копились бы 404 (находка «мелочи» финального
	// ревью ветки).
	for _, forbidden := range []string{`data-tab="manage"`, ">Интерфейсы<", "/api/manage/adoptable", `id="pending"`} {
		if strings.Contains(body, forbidden) {
			t.Errorf("в read-only разметке есть элемент вкладки «Интерфейсы»: %q", forbidden)
		}
	}
}

// TestReadOnlyIndexHasNoMimicryProfileSelectors — обратная сторона
// TestFullBuildIndexHasMimicryProfileSelectors (задача 5, спека 2026-08-25):
// селекторы профиля мимикрии — элементы управления кнопки «Сгенерировать
// I1», а не чтение, и живут внутри гейта not .ReadOnly вместе с самой
// кнопкой и формами, к которым она приложена. В отличие от
// TestIndexShowsMimicryWarnContainer (server_test.go) — та проверяет
// предупреждение о несоответствии, которое ЧТЕНИЕ и обязано присутствовать
// в обеих сборках, — этим двум селекторам в read-only разметке делать
// нечего: маршрут generate/signature в этой сборке отсутствует
// (TestReadonlyBuildHasNoSignatureRoute выше), и кнопка рядом с ними тоже.
func TestReadOnlyIndexHasNoMimicryProfileSelectors(t *testing.T) {
	rec := doAuthed(t, newTestServer(t, twoIfaceRegistry(t)), http.MethodGet, "/", nil)
	for _, forbidden := range []string{"editi1profile", "defaultsi1profile"} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Errorf("в read-only разметке есть селектор профиля мимикрии: %q", forbidden)
		}
	}
}
