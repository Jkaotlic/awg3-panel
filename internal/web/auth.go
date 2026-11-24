// Package web — HTTP-слой панели: маршрутизация, аутентификация, шаблоны.
// Про формат конфига AWG здесь не знают ничего.
package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	failWindow  = 5 * time.Minute
	maxFailures = 5
	blockFor    = 15 * time.Minute
	failDelay   = time.Second
	bcryptSlots = 2
	blockRetry  = 30 * time.Second
	// okTTL — сколько помнится ВЕРНЫЙ пароль после последнего запроса:
	// bcrypt с cost 12 стоит ~250 мс
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
	checks  chan struct{}

	mu      sync.Mutex
	fails   map[string][]time.Time
	blocked map[string]addressBlock
	// ok — дайджест верной пары user:pass → момент, до которого ей верить
	// без bcrypt. Единственный пользователь → не больше одной живой записи.
	ok map[[32]byte]time.Time
}

type addressBlock struct {
	until     time.Time
	nextCheck time.Time
}

func NewAuth(user, bcryptHash string) *Auth {
	return &Auth{
		user:    user,
		hash:    []byte(bcryptHash),
		Now:     time.Now,
		Sleep:   time.Sleep,
		Compare: bcrypt.CompareHashAndPassword,
		checks:  make(chan struct{}, bcryptSlots),
		fails:   map[string][]time.Time{},
		blocked: map[string]addressBlock{},
		ok:      map[[32]byte]time.Time{},
	}
}

func HashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), 12)
	return string(b), err
}

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			writeAuthChallenge(w)
			return
		}
		addr := clientAddr(r)
		digest := sha256.Sum256([]byte(user + "\x00" + pass))
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(a.user)) == 1
		// Прокси объединяет несколько клиентов одним адресом. Уже проверенная
		// пара проходит блокировку адреса, сохраняя лимит для других паролей.
		if userOK && a.cachedOK(digest) {
			next.ServeHTTP(w, r)
			return
		}
		if a.checkBlocked(addr, false) {
			writeAuthBlocked(w)
			return
		}
		select {
		case a.checks <- struct{}{}:
		case <-r.Context().Done():
			return
		}
		// Пока запрос ждал bcrypt, предыдущая проверка могла заблокировать адрес.
		if a.checkBlocked(addr, true) {
			<-a.checks
			writeAuthBlocked(w)
			return
		}
		ok = a.check(userOK, digest, pass)
		if !ok {
			// Запись неудачи — только на пути ОТКАЗА (см. recordFailure).
			a.recordFailure(addr)
			<-a.checks
			// Sleep — вне мьютекса: секундная задержка одного адреса не должна
			// сериализовать запросы остальных (иначе это самострел, а не защита).
			a.Sleep(failDelay)
			writeAuthChallenge(w)
			return
		}
		a.clear(addr)
		<-a.checks
		next.ServeHTTP(w, r)
	})
}

func writeAuthChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="awg3-panel", charset="UTF-8"`)
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "требуется авторизация"})
}

func writeAuthBlocked(w http.ResponseWriter) {
	w.Header().Set("Retry-After", strconv.Itoa(int(blockRetry/time.Second)))
	writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "слишком много неудачных попыток, попробуйте позже"})
}

func (a *Auth) check(userOK bool, digest [32]byte, pass string) bool {
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
	now := a.Now()
	if !now.Before(until) {
		delete(a.ok, d)
		return false
	}
	a.ok[d] = now.Add(okTTL)
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

// checkBlocked allows one password verification per retry interval for a
// blocked address. The permit is reserved only after acquiring a bcrypt slot.
func (a *Auth) checkBlocked(addr string, reserve bool) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.Now()
	a.sweepStale(now)
	block, ok := a.blocked[addr]
	if !ok {
		return false
	}
	if now.Before(block.nextCheck) {
		return true
	}
	if reserve {
		block.nextCheck = now.Add(blockRetry)
		a.blocked[addr] = block
	}
	return false
}

// recordFailure вызывается после проверки неверных учётных данных.
// Запрос на challenge счётчика не касается. Под одним взятием мьютекса:
// отбрасывает протухшие отметки для addr, дописывает текущую и тут же решает, не
// пора ли выставить блокировку. Атомарность связки "запись + решение" — то, ради
// чего затевался round 1, терять её нельзя.
//
// Одновременно проверяется не больше bcryptSlots паролей. Уже начатые
// проверки могут закончиться после выставления блокировки.
func (a *Auth) recordFailure(addr string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.Now()
	if block, ok := a.blocked[addr]; ok && now.Before(block.until) {
		return
	}
	kept := a.fails[addr][:0]
	for _, t := range a.fails[addr] {
		if now.Sub(t) < failWindow {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	a.fails[addr] = kept
	if len(kept) >= maxFailures {
		a.blocked[addr] = addressBlock{until: now.Add(blockFor), nextCheck: now.Add(blockRetry)}
	}
}

// sweepStale чистит карты от записей ЛЮБЫХ адресов, чьи данные полностью протухли:
// истёкшая блокировка или неудачи старше failWindow. Вызывается на каждую
// попытку (внутри checkBlocked, которая отрабатывает на любой входящий запрос),
// поэтому карты не растут неограниченно, даже если адрес, оставивший одну-четыре
// неудачи, больше никогда не вернётся — без этого единственной защитой от роста
// была бы граница AllowedIPs /32 на пира в WireGuard, а код не должен молча
// полагаться на инвариант, который обеспечивается снаружи.
func (a *Auth) sweepStale(now time.Time) {
	for addr, block := range a.blocked {
		if !now.Before(block.until) {
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
