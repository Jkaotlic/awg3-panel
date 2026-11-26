package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
)

//go:embed assets/index.html
var assets embed.FS

// PeerLister — то, что read-only части сервера нужно от ОДНОГО интерфейса:
// список его пиров и сводка по нему. Оба метода — чтение; узкий интерфейс
// позволяет тестировать HTTP без файловой системы.
type PeerLister interface {
	List() ([]issuer.PeerView, error)
	Summary() (issuer.IfaceSummary, error)
}

// Registry — то, что нужно read-only части сервера от РЕЕСТРА интерфейсов:
// перечислить их и найти листер по id. Задача 10 переводит сервер с одного
// заранее выбранного интерфейса (config.Interface) на реестр — маршруты
// получают префикс /api/ifaces/{iface}/, а обработчик сам решает, какой
// интерфейс обслуживать, по сегменту пути.
type Registry interface {
	Metas() []issuer.IfaceMeta
	Lister(id string) (PeerLister, bool)
}

type Server struct {
	cfg  *config.Config
	reg  Registry
	auth *Auth
	tpl  *template.Template
	// mutators заполняется только в сборке без тега readonly (см.
	// handlers_mutate.go/handlers_mutate_readonly.go).
	mutators MutatorRegistry
	junkTune *junkTuneHTTP
	// ifaceEnv — тестовая подмена Host/Runner маршрутов /api/manage (задача
	// 9, находка ревью круга 2): раньше подмена шла через экспортированные
	// пакетные var — глобальное изменяемое состояние, доступное на запись
	// любому импортёру пакета, а не только тестам. Поле на *Server сужает
	// шов до одного инстанса, тем же приёмом, что и mutators выше: nil в
	// продакшене (manageEnv, handlers_manage.go, собирает окружение сама),
	// заполняется только SetIfaceEnvForTest (тот же файл), которую вызывает
	// только manage_test.go. Тип объявлен по сборкам, как и MutatorRegistry
	// выше и по той же причине — поле обязано быть валидным в обеих сборках,
	// не утаскивая internal/iface и internal/runtime в readonly (см.
	// handlers_manage.go / manage_readonly.go).
	ifaceEnv ifaceEnvOverride
}

func NewServer(cfg *config.Config, reg Registry) *Server {
	tpl := template.Must(template.ParseFS(assets, "assets/index.html"))
	return &Server{
		cfg:  cfg,
		reg:  reg,
		auth: NewAuth(cfg.Auth.User, cfg.Auth.Bcrypt),
		tpl:  tpl,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /api/ifaces", s.handleIfaces)
	mux.HandleFunc("GET /api/ifaces/{iface}/peers", s.handleListPeers)
	mux.HandleFunc("GET /api/ifaces/{iface}/summary", s.handleSummary)
	s.registerMutations(mux) // в сборке readonly — пустая функция
	s.registerJunkTune(mux)
	// sameOriginOnly снаружи авторизации: кросс-сайтовый запрос не должен
	// доходить ни до проверки пароля (лишний bcrypt и лишняя запись в счётчик
	// неудач), ни тем более до обработчика. securityHeaders — ещё снаружи:
	// заголовки защиты положены и отказам (401/403), а не только успешным
	// ответам.
	return securityHeaders(sameOriginOnly(s.auth.Middleware(mux)))
}

// Only the HTML handler can enable scripts, using a per-response nonce.
const contentSecurityPolicy = "default-src 'none'; " +
	"style-src 'unsafe-inline'; " +
	"img-src 'self' data: blob:; " +
	"connect-src 'self'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'none'; " +
	"form-action 'self'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "script-src 'none'; "+contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// sameOriginOnly отклоняет ПИШУЩИЕ запросы, пришедшие со страницы чужого
// источника (CSRF). Панель аутентифицируется Basic-авторизацией, а её браузер
// подставляет кэшированные учётные данные к любому запросу на этот источник —
// включая тот, что инициировала чужая вкладка. POST с телом text/plain
// уходит из чужой формы вообще без preflight, так что на CORS полагаться
// нельзя: он ограничивает чтение ОТВЕТА, а не отправку запроса, а мутации
// ответ и не нужен.
//
// Решение при ПОЛНОМ отсутствии заголовков источника — пропускать. Обоснование:
//   - браузер, способный быть орудием CSRF, всегда шлёт Origin на
//     кросс-оригинальные POST (это часть Fetch с 2016 года) и Sec-Fetch-Site
//     (с 2020-го); отсутствие обоих означает, что клиент не браузер — curl или
//     скрипт, — а он не носит с собой чужих ambient-учёток и потому не
//     является CSRF-вектором вовсе;
//   - отказ в этом случае сломал бы работу с панелью из терминала, то есть
//     заблокировал бы единственного администратора ради риска, которого в
//     этом сценарии нет. Тот же приоритет, что и в auth.go: ложная блокировка
//     легитимного пользователя — реальный ущерб, а не гипотетический.
//
// Чтение пропускается, кроме предпросмотра, который резервирует токен.
//
// Проверка стоит СНАРУЖИ маршрутизации по интерфейсам (задача 10): она не
// заглядывает в путь глубже метода, поэтому кросс-сайтовый POST отклоняется
// одинаково для любого /api/ifaces/{iface}/... — включая несуществующий
// iface, до которого обработчик всё равно не добрался бы.
func sameOriginOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (isReadMethod(r.Method) && r.URL.Path != "/api/manage/preview") || isSameOrigin(r) {
			next.ServeHTTP(w, r)
			return
		}
		// Формат тела — тот же, что у всех прочих ошибок API ({"error": ...}):
		// хелпер страницы разбирает ответ через JSON.parse и на обычном тексте
		// показал бы «Unexpected token» вместо причины. writeJSON, а не
		// writeError, — чтобы не логировать одно и то же дважды: строка ниже
		// информативнее, в ней есть метод и путь.
		log.Printf("отклонён кросс-сайтовый запрос %s %q", r.Method, redactLog(r.URL.Path))
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "запрос отклонён: он инициирован страницей стороннего сайта",
		})
	})
}

func isReadMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func isSameOrigin(r *http.Request) bool {
	// Sec-Fetch-Site решает ПЕРВЫМ, когда он есть (07.09.2026): его ставит сам
	// браузер относительно адреса, который ОН запрашивал, и скрипт его не
	// подделает (forbidden header). Сравнение Origin с r.Host этого свойства
	// не имеет за прокси: цепочка main → nl2 подменяет Host под SNI
	// внутреннего Caddy, и Origin страницы (nl2.panel.example.com)
	// перестаёт совпадать с Host (panel.example.net) — панель
	// отвергала КАЖДУЮ мутацию из консоли как кросс-сайтовую. Origin остаётся
	// запасным критерием для клиентов без Sec-Fetch-* (браузеры до 2020 года).
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "":
		// нет заголовка — решает Origin ниже
	default:
		return false // cross-site, same-site
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" {
			return false // в том числе Origin: null — песочница или file://
		}
		return strings.EqualFold(u.Host, r.Host)
	}
	return true // ни Origin, ни Sec-Fetch-Site — не браузер, см. комментарий к sameOriginOnly
}

// После SIGTERM обработчик мутации может ждать несколько последовательных
// exec-вызовов: снимки устройства, syncconf, проверку результата и при
// необходимости повторные вызовы для отката. Остановка должна дать этому
// циклу завершиться до принудительной остановки systemd (TimeoutStopSec=150s).
const shutdownTimeout = 120 * time.Second

// Срок записи HTTP-ответа оставляет запас сверх бюджета завершения мутации,
// чтобы клиент мог получить результат после проверки устройства или отката.
const writeTimeout = 125 * time.Second

func (s *Server) ListenAndServe() error {
	// SIGTERM приходит от systemd при stop и restart — то есть ровно тогда,
	// когда администратор обновляет панель, возможно, в момент мутации.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	log.Printf("слушаю http://%s (интерфейсы: %s)", s.cfg.Listen, ifaceIDList(s.reg.Metas()))
	return s.serve(ctx, ln)
}

// ifaceIDList печатает id всех обслуживаемых интерфейсов через запятую — для
// строки старта в логе. Раньше здесь было единственное имя интерфейса
// (s.iface.Interface), пока сервер обслуживал ровно один; задача 10
// перевела его на реестр, обслуживающий их все одновременно.
func ifaceIDList(metas []issuer.IfaceMeta) string {
	ids := make([]string, 0, len(metas))
	for _, m := range metas {
		ids = append(ids, m.ID)
	}
	return strings.Join(ids, ", ")
}

// serve обслуживает ln до отмены ctx, после чего даёт уже начатым запросам
// доработать до конца (graceful shutdown) и только затем возвращает
// управление. Отделено от ListenAndServe, чтобы это поведение можно было
// проверить тестом на реальном сокете, не завися ни от сигналов, ни от
// адреса из конфига.
func (s *Server) serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		tuneDone := s.stopJunkTune()
		log.Printf("получен сигнал остановки: доканчиваю начатые запросы (не дольше %s)", shutdownTimeout)
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			// Единственный способ сюда попасть — истёкший shutdownTimeout:
			// обработчик не завершился за отведённое время. Молчать нельзя —
			// это как раз тот случай, когда мутация могла остаться незавершённой.
			return fmt.Errorf("остановка сервера: %w", err)
		}
		<-errc // Serve уже вернул ErrServerClosed, забираем, чтобы не оставлять горутину
		if tuneDone != nil {
			select {
			case <-tuneDone:
			case <-sctx.Done():
				return fmt.Errorf("панель остановлена: восстановление тестового туннеля не завершилось")
			}
		}
		log.Print("сервер остановлен")
		return nil
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	nonce := rand.Text()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "script-src 'nonce-"+nonce+"'; "+contentSecurityPolicy)
	tuneIface, tunePeer := s.junkTuneBinding()
	data := struct {
		Ifaces        []issuer.IfaceMeta
		ReadOnly      bool
		Nonce         string
		JunkTuneIface string
		JunkTunePeer  string
	}{s.reg.Metas(), s.mutators == nil, nonce, tuneIface, tunePeer}
	if err := s.tpl.Execute(w, data); err != nil {
		log.Printf("шаблон: %v", err)
	}
}

func (s *Server) handleIfaces(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.reg.Metas())
}

// listerFor находит листер интерфейса по id из пути; при отсутствии сам
// пишет 404 клиенту, а не паникует и не молчаливо выбирает первый интерфейс
// — тот же id мог означать интерфейс, который просто не сконфигурирован.
func (s *Server) listerFor(w http.ResponseWriter, r *http.Request) (PeerLister, bool) {
	l, ok := s.reg.Lister(r.PathValue("iface"))
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("интерфейс %q не найден", r.PathValue("iface")))
		return nil, false
	}
	return l, true
}

func (s *Server) handleListPeers(w http.ResponseWriter, r *http.Request) {
	l, ok := s.listerFor(w, r)
	if !ok {
		return
	}
	peers, err := l.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, peers)
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	l, ok := s.listerFor(w, r)
	if !ok {
		return
	}
	sum, err := l.Summary()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

// issuerRegistry оборачивает *issuer.Registry в Registry. Присвоить его
// напрямую нельзя: issuer.Registry.Lister возвращает *issuer.Service, а не
// web.PeerLister — в Go у методов с разными сигнатурами разные типы, даже
// если *issuer.Service фактически реализует PeerLister.
type issuerRegistry struct{ reg *issuer.Registry }

// Adapt оборачивает *issuer.Registry в Registry — единственный способ
// свести issuer.Registry.Lister (отдаёт *issuer.Service) к web.Registry.Lister
// (отдаёт web.PeerLister). Живёт в web, а не в issuer и не в cmd: cmd не
// должен знать про интерфейсы web (иначе пакеты образовали бы цикл смыслов
// туда-обратно), а issuer не должен знать про web вовсе.
func Adapt(reg *issuer.Registry) Registry { return issuerRegistry{reg} }

func (a issuerRegistry) Metas() []issuer.IfaceMeta { return a.reg.Metas() }

func (a issuerRegistry) Lister(id string) (PeerLister, bool) {
	s, ok := a.reg.Lister(id)
	if !ok {
		return nil, false
	}
	return s, true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("ответ: %v", err)
	}
}

// writeError логирует полную ошибку (для диагностики администратором) и
// решает, что из неё показать клиенту, по КЛАССУ кода:
//
//   - 4xx — ошибка запроса: пустое имя, кривой JSON, неизвестный id. Её текст
//     описывает то, что прислал сам пользователь, и без него он не поймёт,
//     что исправить. Тексты 4xx сочиняются здесь и в issuer (ErrInvalidInput,
//     ErrNotFound) целиком — ни ключей, ни PSK, ни путей в них нет.
//   - 5xx — внутренняя ошибка: наружу уходит только родовая формулировка.
//     Тело ответа оседает в истории браузера и промежуточных инструментах, а
//     цепочка err на пути мутации проходит через wgconf, issuer и runtime —
//     если туда однажды снова попадёт строка конфига с ключом (ровно это
//     чинили в Task 11), она не должна уйти клиенту через этот путь.
//
// Классификацию делает вызывающий (см. statusFor в handlers_mutate.go):
// сюда ошибка приходит уже с решённым кодом.
func writeError(w http.ResponseWriter, code int, err error) {
	log.Printf("ошибка %d: %s", code, redactLog(err.Error()))
	msg := "внутренняя ошибка"
	if code >= 400 && code < 500 {
		msg = redactLog(err.Error())
	}
	writeJSON(w, code, map[string]string{"error": msg})
}

var (
	namedSecret = regexp.MustCompile(`(?i)\b(private[_ -]?key|preshared[_ -]?key|psk(?:_key)?|client_priv_key|headerprotectionkey|password|bcrypt|preview_token)\b["']?[ \t]*[:=][ \t]*("[^"\r\n]*"|'[^'\r\n]*'|[^ \t\r\n;,]+)`)
	keyLike     = regexp.MustCompile(`[A-Za-z0-9+/=_-]{40,}`)
)

func redactLog(message string) string {
	message = namedSecret.ReplaceAllString(message, "${1}=[скрыто]")
	return keyLike.ReplaceAllString(message, "[скрыто]")
}
