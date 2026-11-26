//go:build !readonly

package web

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"reflect"
	"strings"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/store"
)

// PeerMutator — операции, меняющие серверный конфиг или умолчания
// интерфейса. В сборке с тегом readonly этот файл не компилируется, и
// обработчиков мутаций в бинаре нет.
type PeerMutator interface {
	Add(name string) (*issuer.Issued, error)
	Update(id string, patch issuer.PeerPatch) error
	Rotate(id string) (*issuer.Issued, error)
	Remove(id string) error
	Disable(id string) error
	Enable(id string) error
	ConfigFor(id string) (filename string, body string, err error)
	ConfigWithoutCPSFor(id string) (filename string, body string, err error)
	PeerMimicryFor(id string) (issuer.PeerMimicry, error)
	QRFor(id string) ([]byte, error)
	// VPNURIFor/VPNQRFor — ссылка импорта AmneziaVPN и её QR (спека
	// 2026-10-29, раздел 6).
	VPNURIFor(id string) (string, error)
	VPNQRFor(id string) ([]byte, error)
	Defaults() store.Defaults
	SetDefaults(d store.Defaults) error
}

// MutatorRegistry — то, что нужно пишущей части сервера: найти PeerMutator
// конкретного интерфейса по id. Отдельный от Registry интерфейс по той же
// причине, по которой issuer.Registry разводит Lister и Mutator (см. её
// комментарий, internal/issuer/registry.go): в read-only сборке этот
// интерфейс пуст (см. handlers_mutate_readonly.go) — отдавать пишущий
// объект в такой сборке физически нечем.
type MutatorRegistry interface {
	Mutator(id string) (PeerMutator, bool)
}

const ReadOnlyBuild = false

func NewServerWithMutator(cfg *config.Config, reg Registry, m MutatorRegistry) *Server {
	s := NewServer(cfg, reg)
	if isNilMutatorRegistry(m) {
		// Интерфейс, внутри которого лежит nil-указатель конкретного типа,
		// САМ не равен nil: без этой проверки страница объявила бы панель
		// пишущей (ReadOnly вычисляется как s.mutators == nil), маршруты
		// зарегистрировались бы, и первый же вызов уронил бы обработчик по
		// nil-указателю где-то внутри реализации MutatorRegistry. Лучше
		// честно работать в режиме только чтения, чем врать в разметке и
		// падать на первой мутации (та же находка ревью Task 11, что и
		// раньше защищала одиночный PeerMutator, — здесь она защищает
		// реестр, который пришёл на его место).
		log.Print("реестр мутаторов не задан — панель работает в режиме только чтения")
		return s
	}
	s.mutators = m
	return s
}

// isNilMutatorRegistry отличает «реестра мутаторов нет» от «реестр есть» в
// том числе для типизированного nil. reflect здесь — единственный способ:
// сравнение интерфейса с nil на такое значение отвечает false.
func isNilMutatorRegistry(m MutatorRegistry) bool {
	if m == nil {
		return true
	}
	v := reflect.ValueOf(m)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return v.IsNil()
	}
	return false
}

// issuerMutatorRegistry оборачивает *issuer.Registry в MutatorRegistry —
// тот же повод, что у issuerRegistry в server.go: issuer.Registry.Mutator
// возвращает *issuer.Service, а не web.PeerMutator.
type issuerMutatorRegistry struct{ reg *issuer.Registry }

// AdaptMutators оборачивает *issuer.Registry в MutatorRegistry. Существует
// только в этой сборке (как и NewServerWithMutator): в read-only сборке
// подставлять мутаторы физически некуда.
func AdaptMutators(reg *issuer.Registry) MutatorRegistry { return issuerMutatorRegistry{reg} }

func (a issuerMutatorRegistry) Mutator(id string) (PeerMutator, bool) {
	s, ok := a.reg.Mutator(id)
	if !ok {
		return nil, false
	}
	return s, true
}

func (s *Server) registerMutations(mux *http.ServeMux) {
	if s.mutators == nil {
		return
	}
	mux.HandleFunc("POST /api/ifaces/{iface}/peers", s.handleAdd)
	// PATCH БЕЗ завершающего слэша (поправка 1 контролёра к брифу задачи 10):
	// в net/http образец включает метод, поэтому "DELETE /x" и "PATCH /x" —
	// разные образцы и не конфликтуют, завершающий слэш здесь не нужен.
	mux.HandleFunc("PATCH /api/ifaces/{iface}/peers/{id}", s.handlePatch)
	mux.HandleFunc("POST /api/ifaces/{iface}/peers/{id}/rotate", s.handleRotate)
	mux.HandleFunc("DELETE /api/ifaces/{iface}/peers/{id}", s.handleRemove)
	mux.HandleFunc("POST /api/ifaces/{iface}/peers/{id}/disable", s.handleDisable)
	mux.HandleFunc("POST /api/ifaces/{iface}/peers/{id}/enable", s.handleEnable)
	mux.HandleFunc("GET /api/ifaces/{iface}/peers/{id}/config", s.handleConfig)
	mux.HandleFunc("GET /api/ifaces/{iface}/peers/{id}/config-no-cps", s.handleConfigWithoutCPS)
	mux.HandleFunc("GET /api/ifaces/{iface}/peers/{id}/mimicry", s.handlePeerMimicry)
	mux.HandleFunc("GET /api/ifaces/{iface}/peers/{id}/qr", s.handleQR)
	mux.HandleFunc("GET /api/ifaces/{iface}/peers/{id}/vpnuri", s.handleVPNURI)
	mux.HandleFunc("GET /api/ifaces/{iface}/peers/{id}/vpnqr", s.handleVPNQR)
	mux.HandleFunc("GET /api/ifaces/{iface}/defaults", s.handleGetDefaults)
	mux.HandleFunc("PUT /api/ifaces/{iface}/defaults", s.handlePutDefaults)
	mux.HandleFunc("POST /api/ifaces/{iface}/generate/jitter", s.handleGenerateJitter)
	mux.HandleFunc("POST /api/ifaces/{iface}/generate/signature", s.handleGenerateSignature)
	mux.HandleFunc("GET /api/ifaces/{iface}/generate/interface-params", s.handleGenerateInterfaceParams)
	mux.HandleFunc("POST /api/ifaces/{iface}/generate/obfuscation-draft", s.handleObfuscationDraft)
	// registerManage — задача 9: маршруты /api/manage, которыми консоль
	// собирает заявки на подключение/отвязку интерфейса (handlers_manage.go).
	// Последней строкой: та же граница «эта сборка умеет больше, чем
	// смотреть», что и у остальных маршрутов этой функции — s.mutators == nil
	// выше уже отсёк read-only панель до этой точки.
	s.registerManage(mux)
}

// mutatorFor находит мутатора интерфейса по id из пути; при отсутствии сам
// пишет 404 — тот же приём, что и listerFor в server.go (неизвестный
// интерфейс это ошибка запроса, а не повод паниковать или молча взять
// первый попавшийся).
func (s *Server) mutatorFor(w http.ResponseWriter, r *http.Request) (PeerMutator, bool) {
	m, ok := s.mutators.Mutator(r.PathValue("iface"))
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("интерфейс %q не найден", r.PathValue("iface")))
		return nil, false
	}
	return m, true
}

// statusFor переводит класс ошибки сервиса в HTTP-код. Только 4xx доносят до
// клиента текст (см. writeError), поэтому классифицировать обязан вызывающий:
// «не найдено» и «некорректный ввод» описывают запрос пользователя, всё
// остальное — внутренности сервера, и наружу от них уходит только код.
//
// issuer.ErrNoPrivateKey отдельного case не требует: она объявлена как
// fmt.Errorf("%w: ...", ErrNotFound) (internal/issuer/keys.go), поэтому
// errors.Is(err, issuer.ErrNotFound) уже ловит её через цепочку Unwrap.
//
// issuer.ErrStateConflict (находка финального ревью, I4) — тоже 4xx: это
// расхождение peers.json с сервером, обнаруженное ДО применения мутации
// (checkRotateStateMatchesServer), а не внутренний сбой. 409 — по смыслу
// «состояние конфликтует»: запрос сам по себе корректен, но выполнить его
// сейчас нельзя, не потеряв метаданные пира. Раньше эта ошибка шла под
// issuer.ErrPostcondition (default-ветка, 500), и writeError стирала текст
// в «внутренняя ошибка» — оператор не видел причину.
func statusFor(err error) int {
	switch {
	case errors.Is(err, issuer.ErrInvalidInput):
		return http.StatusBadRequest
	case errors.Is(err, issuer.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, issuer.ErrStateConflict):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func (s *Server) handleAdd(w http.ResponseWriter, r *http.Request) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSONObject(w, r, 4096, &body); err != nil {
		writeJSONRequestError(w, err)
		return
	}
	issued, err := m.Add(body.Name)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":            issued.ID,
		"name":          issued.Name,
		"address":       issued.Address,
		"config":        issued.Config,
		"qr_png_base64": base64.StdEncoding.EncodeToString(issued.QRPNG),
	})
}

// handlePatch правит имя, адрес и/или клиентские оверрайды уже выпущенного
// пира. Тело декодируется прямо в issuer.PeerPatch: её указатели различают
// «поле не прислали» и «поле прислали как пустое» (например,
// {"overrides":{"dns":""}} — явно пустой DNS, а не отсутствие DNS), и это
// различие обязано дойти до Update как есть — сюда оно доходит просто тем,
// что json.Decoder не трогает поля, отсутствующие в теле запроса.
func (s *Server) handlePatch(w http.ResponseWriter, r *http.Request) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	var patch issuer.PeerPatch
	if err := decodeJSONObject(w, r, 16384, &patch); err != nil {
		writeJSONRequestError(w, err)
		return
	}
	if err := m.Update(r.PathValue("id"), patch); err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleRotate выдаёт пиру новую пару ключей и PSK и возвращает готовый
// клиентский конфиг вместе с QR — тем же способом, что и выпуск нового пира
// (handleAdd): старый конфиг у клиента уже не работает после ротации, и
// оператору нужно немедленно чем-то его заменить, а не отдельным запросом
// за конфигом.
func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	issued, err := m.Rotate(r.PathValue("id"))
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":            issued.ID,
		"name":          issued.Name,
		"address":       issued.Address,
		"config":        issued.Config,
		"qr_png_base64": base64.StdEncoding.EncodeToString(issued.QRPNG),
	})
}

func (s *Server) simpleAction(w http.ResponseWriter, r *http.Request, fn func(PeerMutator, string) error) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	if err := fn(m, r.PathValue("id")); err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleRemove(w http.ResponseWriter, r *http.Request) {
	s.simpleAction(w, r, func(m PeerMutator, id string) error { return m.Remove(id) })
}

func (s *Server) handleDisable(w http.ResponseWriter, r *http.Request) {
	s.simpleAction(w, r, func(m PeerMutator, id string) error { return m.Disable(id) })
}

func (s *Server) handleEnable(w http.ResponseWriter, r *http.Request) {
	s.simpleAction(w, r, func(m PeerMutator, id string) error { return m.Enable(id) })
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	s.serveClientConfig(w, r, false)
}

func (s *Server) handleConfigWithoutCPS(w http.ResponseWriter, r *http.Request) {
	s.serveClientConfig(w, r, true)
}

func (s *Server) serveClientConfig(w http.ResponseWriter, r *http.Request, withoutCPS bool) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	configFor := m.ConfigFor
	if withoutCPS {
		configFor = m.ConfigWithoutCPSFor
	}
	name, body, err := configFor(r.PathValue("id"))
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeClientConfig(w, name, body)
}

func writeClientConfig(w http.ResponseWriter, name, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeFilename(name)+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(body))
}

func (s *Server) handlePeerMimicry(w http.ResponseWriter, r *http.Request) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	status, err := m.PeerMimicryFor(r.PathValue("id"))
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleQR(w http.ResponseWriter, r *http.Request) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	png, err := m.QRFor(r.PathValue("id"))
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(png)
}

// handleVPNURI отдаёт ссылку vpn:// текстом. В ней приватный ключ клиента —
// no-store, как у .conf.
func (s *Server) handleVPNURI(w http.ResponseWriter, r *http.Request) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	uri, err := m.VPNURIFor(r.PathValue("id"))
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(uri))
}

func (s *Server) handleVPNQR(w http.ResponseWriter, r *http.Request) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	png, err := m.VPNQRFor(r.PathValue("id"))
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(png)
}

// handleGetDefaults отдаёт умолчания интерфейса как есть. m.Defaults() —
// это issuer.(*Service).Defaults(), которая сама берёт мьютекс сервиса
// (поправка 3 задачи 10, internal/issuer/service.go): этот обработчик — тот
// самый первый вызывающий СНАРУЖИ пакета issuer, ради которого мьютекс туда
// и добавлен, и здесь его брать заново не нужно и нечем — Service.mu не
// экспортирован.
func (s *Server) handleGetDefaults(w http.ResponseWriter, r *http.Request) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, m.Defaults())
}

func (s *Server) handlePutDefaults(w http.ResponseWriter, r *http.Request) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	var d store.Defaults
	if err := decodeJSONObject(w, r, 16384, &d); err != nil {
		writeJSONRequestError(w, err)
		return
	}
	if err := m.SetDefaults(d); err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleGenerateJitter выдаёт случайную тройку Jc/Jmin/Jmax в диапазонах
// issuer.GenerateJitter и ничего не пишет ни в defaults.json, ни в оверрайды
// пира — сохранение остаётся отдельным явным действием оператора (PUT
// /defaults или PATCH пира), у которого есть шанс посмотреть на результат
// перед тем, как он ляжет на диск. Живёт в registerMutations осознанно:
// read-only зрителю незачем дёргать генератор параметров обфускации, а
// registerMutations — уже существующая граница «эта сборка умеет больше,
// чем смотреть» (то же рассуждение, что и у остальных маршрутов файла).
func (s *Server) handleGenerateJitter(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.mutatorFor(w, r); !ok {
		return
	}
	j, err := issuer.GenerateJitter(rand.Reader)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, j)
}

// parseExplicitProfile разбирает СЫРУЮ строку профиля мимикрии, пришедшую
// явно от оператора: JSON-поле "profile" тела POST .../generate/signature
// или query-параметр ?profile= у GET .../generate/interface-params (раздел
// 5.5 и раздел 7 спеки 2026-08-25). Обе точки входа разбираются здесь одной
// функцией, чтобы правила разбора не могли разойтись между маршрутами.
//
// Пустая строка (после TrimSpace) — "профиль не указан явно": has=false,
// err=nil, и это разбирается ЗДЕСЬ, а не отдаётся issuer.ValidProfile —
// она сама пустую строку не распознаёт (см. её комментарий) и ответила бы
// тем же "не найдено", что и на опечатке, а вызывающему коду нужно различать
// эти два случая: на "не указано" он отвечает выводом профиля (по порту или
// умолчанию), на "указано неверно" — 400.
//
// Регистр нормализуется здесь (strings.ToLower), а не в issuer.ValidProfile:
// она сознательно регистрозависима — приведение регистра объявлено делом
// HTTP-границы, а не типа. Поэтому "QUIC" в запросе обязано сработать так
// же, как "quic".
func parseExplicitProfile(raw string) (p issuer.MimicryProfile, has bool, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false, nil
	}
	p, ok := issuer.ValidProfile(strings.ToLower(raw))
	if !ok {
		return "", false, fmt.Errorf("%w: неизвестный профиль мимикрии %q — профили и порты: %s",
			issuer.ErrInvalidInput, raw, issuer.ProfilePortHints())
	}
	return p, true, nil
}

// decodeSignatureProfileBody читает необязательное тело
// {"profile":"quic|dns|stun|sip"} маршрута generate/signature. Отсутствие тела
// ЦЕЛИКОМ (io.EOF от пустого r.Body — так шлёт панель, когда оператор не
// выбрал профиль сам) — НЕ ошибка: раздел 5.5 спеки прямо делает тело
// необязательным. Ошибкой остаётся тело, которое есть, но не разбирается
// как JSON.
func decodeSignatureProfileBody(w http.ResponseWriter, r *http.Request) (string, bool) {
	var body struct {
		Profile string `json:"profile"`
	}
	if err := decodeJSONObject(w, r, 256, &body); err != nil {
		if errors.Is(err, io.EOF) {
			return "", true
		}
		writeJSONRequestError(w, err)
		return "", false
	}
	return body.Profile, true
}

// handleGenerateSignature выдаёт готовый сигнатурный пакет (поле I1) и, как
// и handleGenerateJitter рядом, ничего не пишет ни в defaults.json, ни в
// оверрайды пира — сохранение остаётся отдельным явным действием оператора.
//
// Профиль мимикрии — раздел 5.5 спеки 2026-08-25: явное значение оператора
// (тело запроса) имеет приоритет; без него профиль выводится из порта
// живого интерфейса (issuer.ProfileForPort через тот же Summary(), что
// показывает консоль, — s.listerFor). Если порт ничему не соответствует и
// профиль не указан — честная ошибка с портом и списком допустимых
// профилей (issuer.ProfilePortHints), а НЕ выдуманный профиль: DNS-пакет на
// порту, для которого он не предназначен, не прячет туннель, а выделяет
// его (раздел 1 спеки).
//
// Поле I1 ОДНОСТОРОННЕЕ: README amneziawg-go говорит «no need to specify it
// on both sides». В отличие от S/H-параметров и ключа защиты заголовка,
// которые двусторонние и требуют синхронной правки сервера, I1 можно выдать
// клиенту уже РАБОТАЮЩЕГО интерфейса, ничего не трогая на сервере и никого
// не отключая, — поэтому маршрут и кнопка имеют смысл не только для нового
// интерфейса, но и для awg3/awg31 в боевой эксплуатации.
func (s *Server) handleGenerateSignature(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.mutatorFor(w, r); !ok {
		return
	}
	raw, ok := decodeSignatureProfileBody(w, r)
	if !ok {
		return
	}
	profile, has, err := parseExplicitProfile(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !has {
		l, ok := s.listerFor(w, r)
		if !ok {
			return
		}
		sum, err := l.Summary()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		profile, ok = issuer.ProfileForPort(sum.ListenPort)
		if !ok {
			writeError(w, http.StatusBadRequest, fmt.Errorf(
				"%w: порт %d не соответствует ни одному профилю мимикрии — укажите профиль явно (%s)",
				issuer.ErrInvalidInput, sum.ListenPort, issuer.ProfilePortHints()))
			return
		}
	}
	i1, err := issuer.GenerateSignatureFor(rand.Reader, profile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"i1": i1, "profile": profile})
}

// handleGenerateInterfaceParams печатает комплект параметров обфускации для
// НОВОГО интерфейса и не применяет из него ничего.
//
// У мутатора не вызывается НИ ОДИН метод (то же верно и для соседнего
// handleGenerateJitter, и только для них двоих во всём файле). Вызов
// mutatorFor здесь — не подготовка к записи: он нужен ровно для того, чтобы
// обращение к несуществующему интерфейсу получило 404 вместо бодрого ответа
// (страж — TestGenerateInterfaceParamsMissingOnUnknownInterface). Ни
// серверный конфиг, ни peers.json, ни defaults.json на этом пути не
// открываются даже на чтение — постусловие «на диск ничего не записано»
// проверяется тестом TestГенераторИнтерфейсаНичегоНеПишетНаДиск по снимку
// всего каталога состояния интерфейса до и после запроса.
//
// Применить сгенерированное панель не может по построению: правило 2
// репозитория запрещает существование кода, способного изменить серверный
// [Interface], и у issuer.InterfaceParams нет ни одного метода, кроме
// рендера в строку (страж — issuer.TestInterfaceParamsНеУмеетПрименяться).
// Оператор вставляет блок в конфиг нового сервера руками.
//
// В registerMutations — по тому же рассуждению, что и handleGenerateJitter:
// read-only панель это окно наблюдателя, и генератор параметров для нового
// туннеля ей не нужен.
//
// GET, а не POST: запрос ничего не меняет ни на сервере, ни в состоянии
// панели, и повторный вызов отличается от первого только новыми случайными
// числами.
//
// server_block считается здесь, а не в браузере: формат строк секции
// [Interface] обязан существовать в ОДНОМ месте (issuer.ServerBlock), иначе
// вторая копия в JS однажды разойдётся с первой — и разойдётся молча, потому
// что текст останется правдоподобным на вид.
//
// Профиль мимикрии (раздел 7 спеки 2026-08-25): необязательный ?profile=
// разбирается той же parseExplicitProfile, что и тело generate/signature —
// нормализация регистра и текст ошибки на опечатку те же самые. Но вывод
// "профиль не указан" здесь ДРУГОЙ: у совершенно нового интерфейса, для
// которого этот комплект собирается, живого порта ещё нет и взять неоткуда
// (в отличие от generate/signature, где {iface} в пути — уже существующий,
// работающий интерфейс, и его порт читает Summary()). Обращаться к
// Summary() ЭТОГО {iface} здесь было бы не только концептуально неверно
// (правка чужого, не создаваемого интерфейса не должна определять профиль
// для другого, ещё не существующего), но и нарушило бы задокументированное
// постусловие ниже — ни один файл состояния {iface} этот маршрут не трогает
// даже на чтение. Поэтому при опущенном ?profile= используется MimicryQUIC
// (задача 5 спеки 2026-08-25, раздел 5.7 брифа) — решение контроллера, не
// вывод из чего-либо: у совершенно нового интерфейса живого порта ещё нет,
// выводить профиль неоткуда, а 443 — лучшая рекомендация из наших же (раздел
// 10.2 спеки: там живёт весь QUIC-трафик, и гигабайты никого не удивляют, но
// см. оговорку про декодируемость QUIC Initial в README, раздел «Профили
// мимикрии I1» — рекомендация всё равно в силе, порт перевешивает). Ровно
// так собран боевой эталон конфигурации.
//
// Профиль передаётся в issuer.GenerateInterfaceParams ОДНИМ параметром, а не
// подставляется в ответ поверх независимо сгенерированного I1: до находки
// финального ревью ветки mimicry-profiles GenerateInterfaceParams сама
// решала за вызывающего (собирала DNS-пакет безусловно), а этот обработчик
// каждый раз перегенерировал I1 нужным профилем поверх — первая генерация
// уходила в мусор на каждом запросе. Теперь ListenPort и I1 заполняет один и
// тот же вызов одним профилем — они не могут разойтись, потому что берутся
// из одного источника, а не синхронизируются вручную двумя строками ниже.
func (s *Server) handleGenerateInterfaceParams(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.mutatorFor(w, r); !ok {
		return
	}
	profile, has, err := parseExplicitProfile(r.URL.Query().Get("profile"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !has {
		profile = issuer.MimicryQUIC
	}
	p, err := issuer.GenerateInterfaceParams(rand.Reader, profile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// client_jitter продублирован рядом с params.jitter намеренно: в JSON он
	// стоит на одном уровне с server_block и тем показывает, что это ВТОРАЯ
	// половина комплекта — та, что уезжает клиенту, а не в серверный
	// [Interface]. Сервер о Jc/Jmin/Jmax не знает вовсе (см. issuer.Jitter).
	writeJSON(w, http.StatusOK, map[string]any{
		"params":          p,
		"server_block":    p.ServerBlock(),
		"client_jitter":   p.Jitter,
		"mimicry_profile": profile,
		"mimicry_port":    p.ListenPort, // тот же профиль и тот же вызов, что заполнил p.ListenPort — расхождения быть не может.
	})
}

func (s *Server) handleObfuscationDraft(w http.ResponseWriter, r *http.Request) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	var options struct {
		issuer.DraftOptions
		SourcePeer string `json:"source_peer,omitempty"`
	}
	if err := decodeJSONObject(w, r, 4096, &options); err != nil {
		writeJSONRequestError(w, err)
		return
	}
	var draft issuer.ObfuscationDraft
	var err error
	if options.SourcePeer != "" {
		var profile string
		_, profile, err = m.ConfigFor(options.SourcePeer)
		if err == nil {
			draft, err = issuer.GenerateDraftFromPeer(rand.Reader, profile)
		}
	} else {
		draft, err = issuer.GenerateObfuscationDraft(rand.Reader, options.DraftOptions)
	}
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, draft)
}

// safeFilename оставляет в имени только [A-Za-z0-9._-]. Штатно сюда приходит
// slug из store ([a-z0-9-]) плюс ".conf", но peers.json — обычный файл на
// диске, который правят руками, а заголовок ответа не место для доверия к
// его содержимому: кавычка ломает разбор filename, а точки и слэши уводят
// сохранение файла не туда, куда рассчитывает пользователь.
func safeFilename(name string) string {
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.', r == '-', r == '_':
			return r
		}
		return '-'
	}, strings.TrimSpace(name))
	if out == "" || out == "." || out == ".." {
		return "peer.conf"
	}
	return out
}
