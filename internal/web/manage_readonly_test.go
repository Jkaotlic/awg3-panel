//go:build readonly

package web_test

import (
	"net/http"
	"testing"
)

// TestManageRoutesAbsentInReadonly — гейт сборки (задача 9). Заявки на
// подключение/отвязку интерфейса читают устройство и .conf через iface.Host
// и пишут файл заявки на диск — панель в режиме только чтения не вправе
// даже ПЛАНИРОВАТЬ такую правку. Маршрутов /api/manage в этой сборке не
// должно быть вовсе, а не «должны отвечать 403»: отсутствие — физическое
// свойство бинаря (handlers_manage.go целиком под тегом !readonly, см. её
// комментарий), а не решение времени выполнения, — тот же гейт, что уже
// стоит для мутаций пиров в readonly_test.go.
func TestManageRoutesAbsentInReadonly(t *testing.T) {
	h := newTestServer(t, twoIfaceRegistry(t))
	rec := doAuthed(t, h, http.MethodGet, "/api/manage/adoptable", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("код = %d, ожидали 404: маршрутов manage в этой сборке быть не должно", rec.Code)
	}
}
