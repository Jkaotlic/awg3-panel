//go:build !readonly

// Задача 10: вкладка «Интерфейсы» и полоса неприменённых заявок в веб-
// консоли. Оба теста проверяют ОТДАННУЮ РАЗМЕТКУ — по идиоме, уже принятой в
// пакете (TestIndexRendersAllInterfaces, TestIndexEmbedsSummaryThresholds в
// server_test.go; TestConfirmByNameNeverFailsSilently в confirm_test.go), а
// не поведение в браузере: слой 2 (UI) по CLAUDE.md — вёрстка тестами не
// покрывается, но логика (какая функция что зовёт) покрывается.
package web_test

import (
	"net/http"
	"strings"
	"testing"
)

// TestIndexHasManageTab — вкладка существует только в полной сборке.
func TestIndexHasManageTab(t *testing.T) {
	body := doAuthed(t, newTestServerWithMutator(t, &fakeMutator{}), http.MethodGet, "/", nil).Body.String()
	if !strings.Contains(body, `data-tab="manage"`) {
		t.Error("нет вкладки «Интерфейсы»")
	}
}

// TestManageActionsConfirmByName — отвязка и удаление интерфейса обязаны
// подтверждаться той же функцией, что и необратимые действия над пирами.
// Иначе правило «случайно нажать нельзя» будет действовать в одной части
// консоли и не действовать в другой — а цена промаха здесь ВЫШЕ: исчезает
// не один пир, а весь интерфейс со всеми выданными с него конфигами.
//
// Проверяется НЕ наличие confirmByName в разметке — она там уже есть, её
// зовут удаление и ротация пира, и такой тест был бы зелен до начала
// работы. Проверяется, что её зовёт ИМЕННО обработчик действий над
// интерфейсом, и что рядом не заведено второе, более слабое подтверждение.
func TestManageActionsConfirmByName(t *testing.T) {
	body := doAuthed(t, newTestServerWithMutator(t, &fakeMutator{}), http.MethodGet, "/", nil).Body.String()

	i := strings.Index(body, "window.manageAction")
	if i < 0 {
		t.Fatal("нет обработчика действий над интерфейсом")
	}
	end := strings.Index(body[i:], "\n};")
	if end < 0 {
		t.Fatal("не удалось выделить тело manageAction")
	}
	if !strings.Contains(body[i:i+end], "confirmByName(") {
		t.Error("действия над интерфейсом не подтверждаются вводом имени")
	}
	if strings.Contains(body, "if (!confirm(") || strings.Contains(body, "window.confirm(") {
		t.Error("заведено второе, более слабое подтверждение")
	}
}

// --- Круг ревью 2 ---

// TestAdoptableFetchChecksResponseOk — GET /api/manage/adoptable отвечает
// 500 с телом {"error":"текст"} при отказе (см. registerManage,
// handlers_manage.go). Прежняя разметка деструктурировала тело сразу
// (`const { conf } = await fetch(...).then(r => r.json())`) без проверки
// r.ok: при отказе conf становился undefined, исключение не бросалось, и
// оператор видел «нет свободных .conf» — тот же текст, что и при настоящем
// пустом списке. Тот же класс дефекта, что уже стоил отдельной сессии
// отладки (см. комментарий у confirmByName про «peer-<12 hex>»): отказ
// сервера маскируется под штатное пустое состояние, и отличить их нельзя.
//
// Проверяется источник, а не поведение в браузере (headless-браузера в
// пакете нет): блок, обращающийся к /api/manage/adoptable, обязан
// проверять r.ok до использования тела ответа — как это уже делает сосед,
// обработчик формы adopt чуть ниже по файлу.
func TestAdoptableFetchChecksResponseOk(t *testing.T) {
	body := doAuthed(t, newTestServerWithMutator(t, &fakeMutator{}), http.MethodGet, "/", nil).Body.String()

	i := strings.Index(body, `fetch("/api/manage/adoptable"`)
	if i < 0 {
		t.Fatal("не нашли обращение к /api/manage/adoptable")
	}
	end := strings.Index(body[i:], "} catch")
	if end < 0 {
		t.Fatal("не удалось выделить блок загрузки /api/manage/adoptable")
	}
	if !strings.Contains(body[i:i+end], ".ok") {
		t.Error("ответ /api/manage/adoptable используется без проверки r.ok — отказ сервера маскируется под «нет свободных .conf»")
	}
}

// TestManageActionHasNoDeadDeleteBranch — manageAction нёс тернарник,
// обещающий «УДАЛЕНИЕ интерфейса: приватные ключи всех его пиров исчезнут
// навсегда» для любого action, кроме "detach". Бэкенд знает только attach
// и detach (knownActions, internal/iface/request.go) — удаление интерфейса
// это план Б, которого ещё нет физически. Путь был недостижим из разметки
// (кнопки на него не было), но код обещал разрушительное действие, которого
// не существует, а сам тернарник хрупок: третье действие, добавленное без
// правки этой ветки, показало бы оператору текст про уничтожение ключей за
// что-нибудь безобидное. Заготовок под ещё не написанный бэкенд в этом
// репозитории не заводят — план Б принесёт свою ветку сам, когда появится.
func TestManageActionHasNoDeadDeleteBranch(t *testing.T) {
	body := doAuthed(t, newTestServerWithMutator(t, &fakeMutator{}), http.MethodGet, "/", nil).Body.String()
	if strings.Contains(body, "УДАЛЕНИЕ интерфейса") {
		t.Error("в manageAction осталась ветка про удаление интерфейса — бэкенд такого действия не умеет")
	}
}

// TestManageActionShowsServerErrorReason — POST /api/manage/requests
// отвечает {"error":"текст, который оператор может исправить"} на отказ
// (writeError, statusFor — те же сентинелы, что классифицируют ошибки
// мутаций пира). Прежняя manageAction глушила эту причину фиксированной
// строкой «не удалось записать заявку», хотя сосед — обработчик формы
// adopt чуть ниже — эту же причину уже разбирает правильно. Одно и то же
// поведение в двух местах одного файла обязано быть одним кодом, а не
// двумя разными пересказами.
func TestManageActionShowsServerErrorReason(t *testing.T) {
	body := doAuthed(t, newTestServerWithMutator(t, &fakeMutator{}), http.MethodGet, "/", nil).Body.String()

	i := strings.Index(body, "window.manageAction")
	if i < 0 {
		t.Fatal("нет обработчика действий над интерфейсом")
	}
	end := strings.Index(body[i:], "\n};")
	if end < 0 {
		t.Fatal("не удалось выделить тело manageAction")
	}
	block := body[i : i+end]
	if strings.Contains(block, `"не удалось записать заявку"`) {
		t.Error("manageAction всё ещё глушит причину отказа фиксированной строкой")
	}
	if !strings.Contains(block, ".error") {
		t.Error("manageAction не разбирает {\"error\":...} из ответа сервера")
	}
}

// TestConfirmByNamePromptIsNeutral — confirmByName теперь общая для пиров и
// интерфейсов (см. TestManageActionsConfirmByName выше), а приглашение
// prompt() всё ещё было зашито под пиров: при отвязке интерфейса оператор
// увидел бы «Введите имя пира для подтверждения: awg2» — бессмысленную
// фразу, не совпадающую с тем, что у него на самом деле спрашивают.
func TestConfirmByNamePromptIsNeutral(t *testing.T) {
	body := doAuthed(t, newTestServerWithMutator(t, &fakeMutator{}), http.MethodGet, "/", nil).Body.String()
	if strings.Contains(body, "имя пира для подтверждения") {
		t.Error("приглашение confirmByName всё ещё говорит «имя пира», хотя функция общая для пиров и интерфейсов")
	}
}

// TestPendingBannerLivesOutsideManageTab — полоса неприменённых заявок
// раньше лежала внутри <section data-tab="manage">, то есть показывалась,
// только если оператор уже открыл вкладку «Интерфейсы». Спека 2026-08-25,
// раздел 9, описывает её как полосу СВЕРХУ консоли безусловно: смысл в
// том, чтобы человек, зашедший в панель по любому другому поводу, всё
// равно увидел, что его ждёт неприменённая заявка.
func TestPendingBannerLivesOutsideManageTab(t *testing.T) {
	body := doAuthed(t, newTestServerWithMutator(t, &fakeMutator{}), http.MethodGet, "/", nil).Body.String()

	pendingAt := strings.Index(body, `id="pending"`)
	sectionAt := strings.Index(body, `<section data-tab="manage"`)
	if pendingAt < 0 {
		t.Fatal("не нашли полосу #pending")
	}
	if sectionAt < 0 {
		t.Fatal("не нашли секцию вкладки «Интерфейсы»")
	}
	if pendingAt > sectionAt {
		t.Error("#pending лежит внутри секции вкладки «Интерфейсы» — полоса не покажется, пока человек не откроет вкладку")
	}
}
