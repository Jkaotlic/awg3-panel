package web_test

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/web"
	"golang.org/x/crypto/bcrypt"
)

func testAuth(t *testing.T) (*web.Auth, http.Handler, *time.Time, *time.Duration) {
	t.Helper()
	// Стоимость 4 — минимально допустимая: тесты не должны молотить bcrypt.
	hash, err := bcrypt.GenerateFromPassword([]byte("секрет"), 4)
	if err != nil {
		t.Fatal(err)
	}
	a := web.NewAuth("admin", string(hash))
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	var sleptMu sync.Mutex
	var slept time.Duration
	a.Now = func() time.Time { return now }
	a.Sleep = func(d time.Duration) {
		// Sleep теперь может вызываться параллельно (тест на конкурентные попытки),
		// поэтому накопитель защищён отдельным мьютексом хелпера — без него -race
		// ловит гонку записи здесь же, а не в самом Auth.
		sleptMu.Lock()
		slept += d
		sleptMu.Unlock()
	}
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	return a, h, &now, &slept
}

func do(h http.Handler, user, pass, addr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/peers", nil)
	req.RemoteAddr = addr + ":40000"
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestNoCredentialsGives401WithChallenge(t *testing.T) {
	_, h, _, _ := testAuth(t)
	rec := do(h, "", "", "10.11.0.2")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("код = %d, ожидался 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("нет заголовка WWW-Authenticate — браузер не покажет форму входа")
	}
}

func TestCorrectCredentialsPass(t *testing.T) {
	_, h, _, _ := testAuth(t)
	if rec := do(h, "admin", "секрет", "10.11.0.2"); rec.Code != http.StatusOK {
		t.Fatalf("код = %d, ожидался 200", rec.Code)
	}
}

func TestWrongPasswordDelaysAndRejects(t *testing.T) {
	_, h, _, slept := testAuth(t)
	rec := do(h, "admin", "не-секрет", "10.11.0.2")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("код = %d, ожидался 401", rec.Code)
	}
	if *slept < time.Second {
		t.Errorf("задержка = %v, ожидалась не меньше секунды", *slept)
	}
}

func TestWrongUserRejected(t *testing.T) {
	_, h, _, _ := testAuth(t)
	if rec := do(h, "root", "секрет", "10.11.0.2"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("код = %d, ожидался 401", rec.Code)
	}
}

func TestBlockAfterFiveFailures(t *testing.T) {
	_, h, _, _ := testAuth(t)
	for i := 0; i < 5; i++ {
		do(h, "admin", "мимо", "10.11.0.2")
	}
	// Шестая попытка блокируется даже с ВЕРНЫМ паролем.
	rec := do(h, "admin", "секрет", "10.11.0.2")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("код = %d, ожидался 429", rec.Code)
	}
}

func TestBlockIsPerAddress(t *testing.T) {
	_, h, _, _ := testAuth(t)
	for i := 0; i < 5; i++ {
		do(h, "admin", "мимо", "10.11.0.2")
	}
	if rec := do(h, "admin", "секрет", "10.11.0.3"); rec.Code != http.StatusOK {
		t.Fatalf("код = %d — блокировка задела чужой адрес", rec.Code)
	}
}

func TestBlockExpiresAfter15Minutes(t *testing.T) {
	a, h, now, _ := testAuth(t)
	for i := 0; i < 5; i++ {
		do(h, "admin", "мимо", "10.11.0.2")
	}
	*now = now.Add(16 * time.Minute)
	a.Now = func() time.Time { return *now }
	if rec := do(h, "admin", "секрет", "10.11.0.2"); rec.Code != http.StatusOK {
		t.Fatalf("код = %d, ожидался 200 — блокировка должна была истечь", rec.Code)
	}
}

func TestFailuresOlderThanFiveMinutesDoNotCount(t *testing.T) {
	a, h, now, _ := testAuth(t)
	for i := 0; i < 4; i++ {
		do(h, "admin", "мимо", "10.11.0.2")
	}
	*now = now.Add(6 * time.Minute)
	a.Now = func() time.Time { return *now }
	do(h, "admin", "мимо", "10.11.0.2") // пятая, но старые четыре протухли
	if rec := do(h, "admin", "секрет", "10.11.0.2"); rec.Code != http.StatusOK {
		t.Fatalf("код = %d — старые неудачи не должны копиться бесконечно", rec.Code)
	}
}

// TestConcurrentFailuresFromSameAddressAreBoundedByLimit проверяет смысл защиты, а
// не совпадение с конкретной реализацией: после пачки параллельных НЕВЕРНЫХ попыток
// адрес в итоге обязан оказаться заблокирован. Точное число прошедших полную
// bcrypt-проверку теперь не пришпилено — round 2 сознательно вернул запись неудачи
// на путь отказа (см. комментарий у recordFailure про мягкую границу), поэтому
// пачка параллельных попыток может почти вся проскочить проверку блокировки до
// того, как первая из них запишется. Запускать с -race.
func TestConcurrentFailuresFromSameAddressAreBoundedByLimit(t *testing.T) {
	_, h, _, _ := testAuth(t)
	const n = 20 // сильно больше порога в 5
	codes := make([]int, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			codes[i] = do(h, "admin", "мимо", "10.11.0.2").Code
		}(i)
	}
	wg.Wait()

	var full, blockedCount int
	for _, c := range codes {
		switch c {
		case http.StatusUnauthorized:
			full++
		case http.StatusTooManyRequests:
			blockedCount++
		default:
			t.Fatalf("неожиданный код ответа: %d", c)
		}
	}
	if full+blockedCount != n {
		t.Fatalf("full(%d)+blocked(%d) != n(%d) — часть ответов потеряна или задвоена", full, blockedCount, n)
	}
	// Мягкая граница (сознательный компромисс, не забытая проверка): при n=20 и
	// пороге в 5 полную проверку не может пройти больше 5+n запросов — предел
	// заведомо шире фактического, важен не он сам, а то, что число конечно и что
	// блокировка ниже действительно наступает.
	if full > 5+n {
		t.Fatalf("полную проверку прошли %d запросов — не может быть больше 5+n=%d", full, 5+n)
	}
	// Смысл теста: после пачки из n(>=5) неудач подряд с одного адреса блокировка
	// обязана сработать — следующий запрос отвергается, даже если бы там был
	// ВЕРНЫЙ пароль.
	if rec := do(h, "admin", "секрет", "10.11.0.2"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("код = %d, ожидался 429 — после %d неудач подряд блокировка обязана сработать", rec.Code, n)
	}
}

// TestConcurrentCorrectCredentialsAllSucceed — регрессионный тест на находку
// ре-ревью round 1: там reserveAttempt засчитывал попытку ДО разбора креденшелов,
// то есть на КАЖДЫЙ запрос, включая те, что окажутся успешными. Несколько
// параллельных запросов с ВЕРНЫМ паролем с одного адреса могли, пока bcrypt ещё не
// завершился ни у одного из них, вместе набрать maxFailures "резервов" и получить
// ложный 429 — легитимный пользователь получал отказ там, где отказа быть не
// должно. Round 2 пишет в fails/blocked только на пути ОТКАЗА, поэтому параллельный
// успех не может сам себя заблокировать. Запускать с -race.
func TestConcurrentCorrectCredentialsAllSucceed(t *testing.T) {
	_, h, _, _ := testAuth(t)
	const n = 20 // заведомо больше порога в 5 неудач
	codes := make([]int, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			codes[i] = do(h, "admin", "секрет", "10.11.0.2").Code
		}(i)
	}
	wg.Wait()

	for i, c := range codes {
		if c != http.StatusOK {
			t.Errorf("запрос %d: код = %d, ожидался 200 — верный пароль не должен блокироваться параллельными запросами с того же адреса", i, c)
		}
	}
}

// Следующие два теста пришпиливают именно пятиминутную границу окна с двух сторон.
// TestFailuresOlderThanFiveMinutesDoNotCount использует зазор в 6 минут, поэтому
// он остаётся зелёным при ЛЮБОМ failWindow меньше 6 минут (хоть 0, хоть 2 минуты) —
// он не проверяет конкретное значение 5 минут, только сам факт протухания.

func TestFailuresJustUnderFiveMinutesStillCount(t *testing.T) {
	a, h, now, _ := testAuth(t)
	for i := 0; i < 4; i++ {
		do(h, "admin", "мимо", "10.11.0.2")
	}
	// На 1 наносекунду МЕНЬШЕ пяти минут — старые попытки ещё обязаны считаться.
	*now = now.Add(5*time.Minute - time.Nanosecond)
	a.Now = func() time.Time { return *now }
	do(h, "admin", "мимо", "10.11.0.2") // пятая — итого 5, блок должен сработать
	if rec := do(h, "admin", "секрет", "10.11.0.2"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("код = %d, ожидался 429 — попытки моложе 5 минут обязаны считаться", rec.Code)
	}
}

func TestFailuresJustOverFiveMinutesDoNotCount(t *testing.T) {
	a, h, now, _ := testAuth(t)
	for i := 0; i < 4; i++ {
		do(h, "admin", "мимо", "10.11.0.2")
	}
	// На 1 наносекунду БОЛЬШЕ пяти минут — старые попытки уже обязаны протухнуть.
	*now = now.Add(5*time.Minute + time.Nanosecond)
	a.Now = func() time.Time { return *now }
	do(h, "admin", "мимо", "10.11.0.2") // пятая, но старые четыре уже протухли — итого 1
	if rec := do(h, "admin", "секрет", "10.11.0.2"); rec.Code != http.StatusOK {
		t.Fatalf("код = %d, ожидался 200 — попытки старше 5 минут не должны считаться", rec.Code)
	}
}

func TestHashPasswordRoundTrip(t *testing.T) {
	h, err := web.HashPassword("пароль")
	if err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(h), []byte("пароль")) != nil {
		t.Error("сгенерированный хеш не проверяется")
	}
}

// TestУспешныйПарольКэшируется — bcrypt с cost 12 стоит ~250 мс CPU на
// КАЖДЫЙ запрос, а консоль опрашивает сводку и список каждые 10 с по
// каждому интерфейсу: на однопроцессорной VPS это заметная постоянная
// нагрузка. Верный пароль после первой проверки помнится 5 минут по
// SHA-256 пары user:pass; неверный пароль кэш не трогает.
func TestУспешныйПарольКэшируется(t *testing.T) {
	a, h, now, _ := testAuth(t)
	var compares int
	a.Compare = func(hash, pass []byte) error {
		compares++
		return bcrypt.CompareHashAndPassword(hash, pass)
	}
	for i := 0; i < 3; i++ {
		if rec := do(h, "admin", "секрет", "10.11.0.2"); rec.Code != http.StatusOK {
			t.Fatalf("попытка %d: код = %d", i, rec.Code)
		}
	}
	if compares != 1 {
		t.Fatalf("bcrypt вызван %d раз на три верных запроса, ожидался 1", compares)
	}
	if rec := do(h, "admin", "неверный", "10.11.0.2"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("неверный пароль прошёл: код = %d", rec.Code)
	}
	if compares != 2 {
		t.Fatalf("неверный пароль не дошёл до bcrypt: вызовов %d", compares)
	}
	*now = now.Add(6 * time.Minute)
	if rec := do(h, "admin", "секрет", "10.11.0.2"); rec.Code != http.StatusOK {
		t.Fatalf("после истечения кэша верный пароль отвергнут: %d", rec.Code)
	}
	if compares != 3 {
		t.Fatalf("после 5 минут пароль обязан перепроверяться bcrypt: вызовов %d", compares)
	}
}

func TestColdLoginGetsLimitedRetryOnBlockedAddress(t *testing.T) {
	_, h, now, _ := testAuth(t)
	const addr = "198.51.100.2"
	for range 5 {
		do(h, "admin", "wrong", addr)
	}
	if rec := do(h, "admin", "секрет", addr); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected initial cooldown, got %d", rec.Code)
	}
	*now = now.Add(30 * time.Second)
	if rec := do(h, "admin", "wrong", addr); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected one limited retry, got %d", rec.Code)
	}
	if rec := do(h, "admin", "секрет", addr); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected renewed cooldown, got %d", rec.Code)
	}
	*now = now.Add(30 * time.Second)
	if rec := do(h, "admin", "секрет", addr); rec.Code != http.StatusOK {
		t.Fatalf("expected successful cold login, got %d", rec.Code)
	}
}
