// Package web — HTTP-слой панели: маршрутизация, аутентификация, шаблоны.
// Про формат конфига AWG здесь не знают ничего.
package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	failWindow  = 5 * time.Minute
	maxFailures = 5
	blockFor    = 15 * time.Minute
	failDelay   = time.Second
	// okTTL — сколько помнится ВЕРНЫЙ пароль: bcrypt с cost 12 стоит ~250 мс
	// CPU на каждый запрос, а консоль опрашивает сводку и список каждые 10 с
	// по каждому интерфейсу — на однопроцессорной VPS это постоянная
	// нагрузка ради повторной проверки того же самого пароля. Помнится не
	// пароль, а SHA-256 пары user:pass; неверный пароль кэш не трогает.
	okTTL = 5 * time.Minute
)

type Auth struct {
	user string
	hash []byte

	// Now и Sleep подменяются в тестах, чтобы не ждать реального времени.
	Now   func() time.Time
	Sleep func(time.Duration)
	// Compare — bcrypt-сверка; подменяется в тестах, чтобы посчитать вызовы.
	Compare func(hash, pass []byte) error

	mu      sync.Mutex
	fails   map[string][]time.Time
	blocked map[string]time.Time
	// ok — дайджест верной пары user:pass → момент, до которого ей верить
	// без bcrypt. Единственный пользователь → не больше одной живой записи.
	ok map[[32]byte]time.Time
}

func NewAuth(user, bcryptHash string) *Auth {
	return &Auth{
		user:    user,
		hash:    []byte(bcryptHash),
		Now:     time.Now,
		Sleep:   time.Sleep,
		Compare: bcrypt.CompareHashAndPassword,
		fails:   map[string][]time.Time{},
		blocked: map[string]time.Time{},
		ok:      map[[32]byte]time.Time{},
	}
}

func HashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), 12)
	return string(b), err
}

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr := clientAddr(r)
		// isBlocked — без побочного эффекта на счётчик: вызывается на КАЖДЫЙ запрос,
		// включая те, что окажутся успешными, поэтому не должен ничего "резервировать"
		// (round 1 делал именно так через reserveAttempt — это и вызвало регрессию:
		// несколько параллельных запросов с ВЕРНЫМ паролем успевали разделить между
		// собой чужой лимит и получить ложный 429, пока bcrypt ещё не завершился ни
		// у одного из них).
		if a.isBlocked(addr) {
			http.Error(w, "слишком много неудачных попыток, попробуйте позже", http.StatusTooManyRequests)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || !a.check(user, pass) {
			// Запись неудачи — только на пути ОТКАЗА (см. recordFailure).
			a.recordFailure(addr)
			// Sleep — вне мьютекса: секундная задержка одного адреса не должна
			// сериализовать запросы остальных (иначе это самострел, а не защита).
			a.Sleep(failDelay)
			w.Header().Set("WWW-Authenticate", `Basic realm="awg3-panel", charset="UTF-8"`)
			http.Error(w, "требуется авторизация", http.StatusUnauthorized)
			return
		}
		a.clear(addr)
		next.ServeHTTP(w, r)
	})
}

func (a *Auth) check(user, pass string) bool {
	// Имя сверяем в постоянное время, пароль — bcrypt (он и так постоянного времени).
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(a.user)) == 1
	digest := sha256.Sum256([]byte(user + "\x00" + pass))
	if userOK && a.cachedOK(digest) {
		return true
	}
	passOK := a.Compare(a.hash, []byte(pass)) == nil
	if userOK && passOK {
		a.remember(digest)
	}
	return userOK && passOK
}

func (a *Auth) cachedOK(d [32]byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	until, ok := a.ok[d]
	if !ok {
		return false
	}
	if !a.Now().Before(until) {
		delete(a.ok, d)
		return false
	}
	return true
}

func (a *Auth) remember(d [32]byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Одна живая запись: смена пароля (новый хеш = новый процесс) и так
	// сбрасывает кэш, а старый дайджест держать незачем.
	for k := range a.ok {
		delete(a.ok, k)
	}
	a.ok[d] = a.Now().Add(okTTL)
}

// isBlocked проверяет блокировку под мьютексом и НЕ трогает счётчик попыток —
// ни добавить метку, ни продлить, ни выставить блок она не может. Вызывается на
// КАЖДЫЙ входящий запрос, успешный и неуспешный одинаково, и именно поэтому обязана
// быть настолько «пустой»: round 1 держал эту же проверку внутри reserveAttempt,
// которая попутно засчитывала попытку любому запросу, включая те, что окажутся
// с ВЕРНЫМ паролем — несколько параллельных запросов успевали разделить между
// собой чужой лимит и получить ложный 429, пока bcrypt ещё не завершился ни у
// одного из них (см. отчёт, "Fix round 2", живое воспроизведение 10 прогонов из
// 10). Здесь же попутно вызывается sweepStale — это не противоречит "без
// побочного эффекта на счётчик": sweepStale лишь удаляет уже истёкшие записи,
// она не заводит новых и не продлевает существующие.
func (a *Auth) isBlocked(addr string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.Now()
	a.sweepStale(now)

	until, ok := a.blocked[addr]
	return ok && now.Before(until)
}

// recordFailure вызывается ТОЛЬКО с пути отказа (неверные креденшелы или их
// отсутствие) — успешный вход сюда вообще не заходит. Под ОДНИМ взятием мьютекса:
// отбрасывает протухшие отметки для addr, дописывает текущую и тут же решает, не
// пора ли выставить блокировку. Атомарность связки "запись + решение" — то, ради
// чего затевался round 1, терять её нельзя.
//
// ОСОЗНАННЫЙ КОМПРОМИСС (не забытая проверка, а сознательный выбор для этой модели
// угроз): поскольку счёт теперь ведётся только на пути отказа, а не на входе в
// обработчик, как было в round 1, — пачка из N параллельных НЕВЕРНЫХ попыток с
// одного адреса может почти вся пройти isBlocked ДО того, как первая из них
// допишется сюда. То есть блокировка срабатывает не строго на maxFailures-й
// попытке, а где-то в диапазоне [maxFailures, maxFailures+N) — мягкая граница
// вместо жёсткой. Для этой панели это несущественно: она слушает единственный
// адрес ВНУТРИ туннеля AmneziaWG, снаружи порта не существует вовсе, значит
// атакующий уже внутри VPN — а каждая его попытка, лишняя или нет, всё равно
// стоит полной bcrypt-проверки (cost=12). Десяток лишних догадок ничего не меняют.
// Зато ложная блокировка ЕДИНСТВЕННОГО легитимного пользователя, открывшего
// несколько вкладок панели одновременно с ВЕРНЫМ паролем, — реальный ущерб, и
// round 1 воспроизвёл его живьём (10 прогонов из 10, легитимные параллельные
// запросы получали 429). Если когда-нибудь захочется вернуть жёсткую границу
// "ровно maxFailures" — единственный способ сделать это в точности назад означает
// снова засчитывать попытку ДО проверки пароля, а это и есть регрессия round 1.
// Не наступать на неё повторно, не подумав дважды.
func (a *Auth) recordFailure(addr string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.Now()
	kept := a.fails[addr][:0]
	for _, t := range a.fails[addr] {
		if now.Sub(t) < failWindow {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	a.fails[addr] = kept
	if len(kept) >= maxFailures {
		a.blocked[addr] = now.Add(blockFor)
	}
}

// sweepStale чистит карты от записей ЛЮБЫХ адресов, чьи данные полностью протухли:
// истёкшая блокировка или неудачи старше failWindow. Вызывается на каждую
// попытку (внутри isBlocked, которая отрабатывает на любой входящий запрос),
// поэтому карты не растут неограниченно, даже если адрес, оставивший одну-четыре
// неудачи, больше никогда не вернётся — без этого единственной защитой от роста
// была бы граница AllowedIPs /32 на пира в WireGuard, а код не должен молча
// полагаться на инвариант, который обеспечивается снаружи.
func (a *Auth) sweepStale(now time.Time) {
	for addr, until := range a.blocked {
		if !now.Before(until) {
			delete(a.blocked, addr)
			delete(a.fails, addr)
		}
	}
	for addr, times := range a.fails {
		if _, blocked := a.blocked[addr]; blocked {
			continue
		}
		stale := true
		for _, t := range times {
			if now.Sub(t) < failWindow {
				stale = false
				break
			}
		}
		if stale {
			delete(a.fails, addr)
		}
	}
}

// clear снимает и накопленные неудачи, и блокировку: верный пароль — доказательство,
// что адресом владеет легитимный пользователь, поэтому весь счётчик сбрасывается,
// даже если он успел достичь порога из-за резервирования параллельных попыток.
func (a *Auth) clear(addr string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.fails, addr)
	delete(a.blocked, addr)
}

// clientAddr берёт адрес соединения. X-Forwarded-For сознательно игнорируется:
// панель слушает только адрес туннеля, обратного прокси перед ней нет,
// а доверять этому заголовку значит дать обойти блокировку одной строкой.
func clientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
