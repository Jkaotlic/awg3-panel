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
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sync"
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

var attachConfigName = regexp.MustCompile(`^[A-Za-z0-9_+=.][A-Za-z0-9_+=.-]{0,14}\.conf$`)
var manageID = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

func validAttachConfigName(name string) bool {
	return attachConfigName.MatchString(name) && name != "..conf" && name != "...conf"
}

// plan builds the request without changing the host.
func (s *Server) plan(b manageRequestBody) (iface.Request, error) {
	r := iface.Request{
		Version: iface.RequestVersion, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		CreatedBy: s.cfg.Auth.User, ID: b.ID,
	}
	switch iface.Action(b.Action) {
	case iface.ActionAttach:
		if !manageID.MatchString(b.ID) {
			return iface.Request{}, fmt.Errorf("%w: id должен содержать 1–32 строчных латинских букв, цифр или дефисов", issuer.ErrInvalidInput)
		}
		if !validAttachConfigName(b.Conf) {
			return iface.Request{}, fmt.Errorf("%w: выберите имя файла .conf из каталога конфигов", issuer.ErrInvalidInput)
		}
		for _, existing := range s.cfg.Interfaces {
			if existing.ID == b.ID {
				return iface.Request{}, fmt.Errorf("%w: интерфейс с таким id уже есть", issuer.ErrInvalidInput)
			}
		}
		p, err := iface.PlanAttach(iface.AttachInput{ID: b.ID, Title: b.Title, ConfName: b.Conf}, s.manageEnv())
		if err != nil {
			return iface.Request{}, err
		}
		r.Action, r.Attach, r.ConfigRevision = iface.ActionAttach, &p, p.ConfigRevision
	case iface.ActionDetach:
		for _, existing := range s.cfg.Interfaces {
			if existing.ID == b.ID {
				p, err := iface.PlanDetach(b.ID, s.manageEnv())
				if err != nil {
					return iface.Request{}, err
				}
				r.Action, r.Detach, r.ConfigRevision = iface.ActionDetach, &p, p.ConfigRevision
				return r, nil
			}
		}
		return iface.Request{}, issuer.ErrNotFound
	default:
		return iface.Request{}, fmt.Errorf("%w: неизвестное действие", issuer.ErrInvalidInput)
	}
	return r, nil
}

// sameManagePlan ignores the timestamp and the jitter generated during revalidation.
func sameManagePlan(preview, current iface.Request) bool {
	current.CreatedAt = preview.CreatedAt
	if preview.Attach != nil && current.Attach != nil {
		current.Attach.Block.Client.Jc = preview.Attach.Block.Client.Jc
		current.Attach.Block.Client.Jmin = preview.Attach.Block.Client.Jmin
		current.Attach.Block.Client.Jmax = preview.Attach.Block.Client.Jmax
	}
	return reflect.DeepEqual(preview, current)
}

func (s *Server) registerManage(mux *http.ServeMux) {
	const previewTTL = 5 * time.Minute
	const maxPreviews = 128
	type preview struct {
		input   manageRequestBody
		request iface.Request
		expires time.Time
	}
	var mu sync.Mutex
	pending := make(map[string]preview)
	mux.HandleFunc("GET /api/manage/adoptable", func(w http.ResponseWriter, r *http.Request) {
		names, err := iface.Adoptable(iface.DefaultConfDir, s.cfg)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"conf": names})
	})

	mux.HandleFunc("GET /api/manage/preview", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Cache-Control", "no-store")
			return
		}
		q := r.URL.Query()
		input := manageRequestBody{
			Action: q.Get("action"), ID: q.Get("id"),
			Title: q.Get("title"), Conf: q.Get("conf"),
		}
		req, err := s.plan(input)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		token := rand.Text()
		now := time.Now()
		mu.Lock()
		for key, p := range pending {
			if !now.Before(p.expires) {
				delete(pending, key)
			}
		}
		if len(pending) >= maxPreviews {
			mu.Unlock()
			writeError(w, http.StatusTooManyRequests, errors.New("слишком много активных предпросмотров"))
			return
		}
		pending[token] = preview{input: input, request: req, expires: now.Add(previewTTL)}
		mu.Unlock()
		writeJSON(w, http.StatusOK, struct {
			iface.Request
			Token string `json:"preview_token"`
		}{req, token})
	})

	mux.HandleFunc("POST /api/manage/requests", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Token string `json:"preview_token"`
		}
		if err := decodeJSONObject(w, r, 4096, &body); err != nil {
			writeJSONRequestError(w, err)
			return
		}
		mu.Lock()
		p, ok := pending[body.Token]
		delete(pending, body.Token)
		mu.Unlock()
		if !ok || !time.Now().Before(p.expires) {
			writeError(w, http.StatusConflict, errors.New("предпросмотр недействителен, создайте его заново"))
			return
		}
		current, err := s.plan(p.input)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		if !sameManagePlan(p.request, current) {
			writeError(w, http.StatusConflict, errors.New("состояние интерфейса изменилось, создайте предпросмотр заново"))
			return
		}
		req := p.request
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
		name := r.PathValue("name")
		if !filepath.IsLocal(name) || filepath.Base(name) != name || filepath.Ext(name) != ".json" {
			writeError(w, http.StatusBadRequest, errors.New("недопустимое имя заявки"))
			return
		}
		if err := iface.Cancel(dir, name); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeError(w, http.StatusNotFound, errors.New("заявка не найдена"))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
