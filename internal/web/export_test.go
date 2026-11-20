//go:build !readonly

package web

import (
	"github.com/Jkaotlic/awg3-panel/internal/iface"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
)

// Файл существует ради ОДНОГО правила: тестовый шов не компилируется в
// боевой бинарь. `package web` + суффикс `_test.go` — это единственная в Go
// форма, дающая внешнему тесту (`package web_test`) доступ к внутренностям
// пакета, не оставляя ни строчки этого доступа в собранной панели.
//
// Находка «мелочи» финального ревью ветки: SetIfaceEnvForTest была объявлена
// в обычном handlers_manage.go, то есть метод, подменяющий Host и фабрику
// Runner маршрутов /api/manage, попадал в боевой awg3panel. Никто его там не
// звал — но экспортированный метод, способный подменить весь доступ панели к
// файловой системе и к awg, в бинаре, стоящем на боевом VPS, существовать не
// должен вовсе: «его никто не вызывает» — это про сегодняшний код, а не про
// свойство сборки.
//
// Тег !readonly — по той же причине, по какой им помечен сам
// handlers_manage.go: в read-only сборке поле Server.ifaceEnv имеет ДРУГОЙ
// тип (manage_readonly.go: `func()`), и этот файл там не собрался бы.

// SetIfaceEnvForTest подставляет Host и фабрику Runner для маршрутов
// /api/manage. Вызывает её только manage_test.go: продакшен (cmd/awg3panel)
// получает настоящий iface.NewOSHost()/runtime.NewExec из manageEnv — тот
// же исполнитель, что увидит реальный /etc/amnezia/amneziawg на боевом
// хосте.
func (s *Server) SetIfaceEnvForTest(h iface.Host, r func(binDir string) runtime.Runner) {
	s.ifaceEnv = func() (iface.Host, func(string) runtime.Runner) { return h, r }
}
