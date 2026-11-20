//go:build !readonly

// Файл — маршруты /api/manage, которыми веб-консоль СОБИРАЕТ заявки на
// подключение (attach) и отвязку (detach) интерфейса (спека 2026-08-25,
// раздел 3). Ни один обработчик здесь не трогает живое устройство и не
// переписывает [Interface] серверного конфига: правила 1 и 2 CLAUDE.md
// остаются в силе буквально — awg setconf не вызывается ниоткуда, а .conf
// только читается через iface.PlanAttach/PlanDetach. Применяет заявку
// отдельная подкоманда CLI по SSH вне песочницы демона
// (cmd/awg3panel/cli_iface.go, тег !readonly) — между нажатием в консоли и
// изменением хоста стоит явный запуск человеком, и он видит одно и то же
// дважды (предпросмотр здесь и describe() там).
package web

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/iface"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
)

// Собственных констант с корнями `/etc/amnezia/amneziawg` и `/opt` здесь
// БОЛЬШЕ НЕТ — они живут в internal/iface (DefaultConfDir/DefaultBinRoot),
// одним объявлением на весь бинарь. Прежняя пара констант в этом файле
// дублировала литералы исполнителя (cmd/awg3panel/cli_iface.go), и согласие
// двух объявлений держалось только на том, что строки написаны одинаково:
// весь смысл пере-проверки предусловий в исполнителе (шаг 1 раздела 6А.5
// спеки 2026-08-25) в том, что он смотрит на ТО ЖЕ, на что смотрела
// консоль — иначе она собирает заявку по одному хосту, а он применяет её к
// другому (находка IMPORTANT 5 финального ревью ветки).

// ifaceEnvOverride переопределяет Host и фабрику Runner маршрутов
// /api/manage. nil в продакшене — manageEnv собирает настоящий
// iface.NewOSHost()/runtime.NewExec сама; ненулевое значение способен
// задать только SetIfaceEnvForTest ниже, а вызывает её только
// manage_test.go. Функциональный тип, а не интерфейс с методами: поле
// Server.ifaceEnv (server.go) обязано существовать под тем же именем и в
// readonly-сборке (см. manage_readonly.go) — то же решение, что уже несёт
// MutatorRegistry/PeerMutator, и по той же причине.
//
// Находка ревью задачи 9, круг 2: раньше здесь стояли экспортированные
// пакетные var (IfaceHostFactory/IfaceRunnerFactory) — глобальное
// изменяемое состояние пакета web, доступное на запись любому импортёру, а
// не только тестам. Поле на *Server сужает шов до одного инстанса; ни один
// вызывающий конструктор (cmd/awg3panel, весь прочий набор web-тестов) его
// не трогает и не обязан о нём знать.
type ifaceEnvOverride func() (iface.Host, func(string) runtime.Runner)

// Метода, ЗАПОЛНЯЮЩЕГО это поле, в боевом файле больше нет: он живёт в
// export_test.go (`package web`, суффикс _test.go — компилируется только под
// go test). Прежде SetIfaceEnvForTest была объявлена здесь и попадала в
// боевой бинарь: экспортированный метод, способный подменить весь доступ
// панели к файловой системе и к awg, не должен существовать в сборке,
// стоящей на боевом VPS, — «его никто не вызывает» описывает сегодняшний
// код, а не свойство сборки (находка «мелочи» финального ревью ветки).

// manageEnv строит окружение планировщика из конфига сервера. Побочных
// действий не совершает: демон панели только СОБИРАЕТ заявку, выполняет её
// подкоманда CLI вне песочницы (спека 2026-08-25, раздел 3).
//
// Все три пути (корень состояния и два корня раскладки) берутся из
// internal/iface, а не вычисляются здесь: iface.StateRoot переживает пустой
// s.cfg.Interfaces сама и возвращает "" вместо паники по индексу — гарантия
// «в config.yaml есть хотя бы один интерфейс» живёт ВЫШЕ по стеку
// (config.Validate при загрузке), а не внутри HTTP-обработчика (находка
// ревью задачи 9, круг 2). PlanAttach и PlanDetach пустой StateRoot
// переживают корректно: первый явно проверяет длину и отказывает сам,
// второй просто не находит id ни среди нуля интерфейсов.
func (s *Server) manageEnv() iface.Env {
	h, r := iface.Host(iface.NewOSHost()), func(binDir string) runtime.Runner { return runtime.NewExec(binDir) }
	if s.ifaceEnv != nil {
		h, r = s.ifaceEnv()
	}
	return iface.Env{
		Cfg: s.cfg, ConfDir: iface.DefaultConfDir,
		StateRoot: iface.StateRoot(s.cfg), BinRoot: iface.DefaultBinRoot, H: h, R: r,
	}
}

type manageRequestBody struct {
	Action string `json:"action"`
	ID     string `json:"id"`
	Title  string `json:"title"`
	Conf   string `json:"conf"`
}

// plan — общая часть предпросмотра и записи заявки: обе строят ОДНУ И ТУ ЖЕ
// заявку, и расхождение между показанным и записанным было бы ровно тем,
// от чего схема с заявкой защищает.
//
// Отказ планировщика оборачивается issuer.ErrInvalidInput, а не уходит как
// есть: statusFor (handlers_mutate.go) классифицирует ошибки по этому же
// набору сентинелов, и без обёртки причина отказа PlanAttach/PlanDetach
// превратилась бы в 500 «внутренняя ошибка» — оператор не увидел бы текста,
// который сам мог бы исправить (третье требование сверх брифа задачи 9).
//
// Заодно это единственная точка, через которую b.ID попадает в записываемую
// заявку: PlanAttach отказывает на id, не прошедшем idRe (буквы, цифры,
// дефис), а PlanDetach отказывает, если id не совпадает ни с одним уже
// сконфигурированным интерфейсом, — до iface.Save (POST-обработчик ниже)
// дело доходит только после одной из этих двух проверок. Отдельной
// санитизации b.ID здесь поэтому нет: она была бы третьей копией той же
// проверки, расходящейся при следующей правке (см. TestPostRequestRejects-
// PathTraversalID в manage_test.go).
func (s *Server) plan(b manageRequestBody) (iface.Request, error) {
	r := iface.Request{
		Version: iface.RequestVersion, CreatedAt: time.Now().UTC().Format(time.RFC3339),
		CreatedBy: s.cfg.Auth.User, ID: b.ID,
	}
	switch iface.Action(b.Action) {
	case iface.ActionAttach:
		p, err := iface.PlanAttach(iface.AttachInput{ID: b.ID, Title: b.Title, ConfName: b.Conf}, s.manageEnv())
		if err != nil {
			return iface.Request{}, fmt.Errorf("%w: %s", issuer.ErrInvalidInput, err)
		}
		r.Action, r.Attach = iface.ActionAttach, &p
	case iface.ActionDetach:
		p, err := iface.PlanDetach(b.ID, s.manageEnv())
		if err != nil {
			return iface.Request{}, fmt.Errorf("%w: %s", issuer.ErrInvalidInput, err)
		}
		r.Action, r.Detach = iface.ActionDetach, &p
	default:
		return iface.Request{}, fmt.Errorf("%w: неизвестное действие %q", issuer.ErrInvalidInput, b.Action)
	}
	return r, nil
}

// registerManage отдаёт маршруты /api/manage/…. Префикс отдельный от
// /api/ifaces/, а не .../manage/ вложенным в него: второй столкнулся бы с
// интерфейсом, чей id — "manage" (idRe допускает такое имя как валидный
// slug).
func (s *Server) registerManage(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/manage/adoptable", func(w http.ResponseWriter, r *http.Request) {
		names, err := iface.Adoptable(iface.DefaultConfDir, s.cfg)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"conf": names})
	})

	mux.HandleFunc("GET /api/manage/preview", func(w http.ResponseWriter, r *http.Request) {
		req, err := s.plan(manageRequestBody{
			Action: r.URL.Query().Get("action"), ID: r.URL.Query().Get("id"),
			Title: r.URL.Query().Get("title"), Conf: r.URL.Query().Get("conf"),
		})
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, req)
	})

	mux.HandleFunc("POST /api/manage/requests", func(w http.ResponseWriter, r *http.Request) {
		var b manageRequestBody
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&b); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		req, err := s.plan(b)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		dir, err := iface.RequestsDir(s.cfg)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		name, err := iface.Save(dir, req)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		log.Printf("записана заявка %s (%s %s)", name, req.Action, req.ID)
		writeJSON(w, http.StatusOK, map[string]any{"name": name})
	})

	mux.HandleFunc("GET /api/manage/requests", func(w http.ResponseWriter, r *http.Request) {
		dir, err := iface.RequestsDir(s.cfg)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		reqs, err := iface.List(dir)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"requests": reqs})
	})

	mux.HandleFunc("DELETE /api/manage/requests/{name}", func(w http.ResponseWriter, r *http.Request) {
		dir, err := iface.RequestsDir(s.cfg)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		// Имя приходит из пути и недоверенно. Проверка внутри iface.Cancel —
		// вторая линия защиты сверх той, что уже стоит в plan() при записи
		// (idRe/поиск по существующим id внутри PlanAttach/PlanDetach): обход
		// каталога — то, о чём нельзя забыть ровно один раз.
		if err := iface.Cancel(dir, r.PathValue("name")); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
