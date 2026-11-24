package web

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMissingCredentialsDoNotConsumePasswordAttempts(t *testing.T) {
	a := NewAuth("admin", "unused")
	a.Sleep = func(time.Duration) {}
	a.Compare = func(_, pass []byte) error {
		if string(pass) == "correct" {
			return nil
		}
		return errors.New("wrong password")
	}
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i <= maxFailures; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("запрос без пароля: код %d, ожидается 401 с challenge", rec.Code)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.SetBasicAuth("admin", "correct")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("верный пароль после запросов без пароля: код %d", rec.Code)
	}
}

func TestWriteErrorRedactsKeysInLog(t *testing.T) {
	var out bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(previous) })

	privateKey := strings.Repeat("a", 43) + "="
	psk := "broken-secret"
	err := errors.New("не удалось применить: PrivateKey = " + privateKey + "; PresharedKey = " + psk)
	writeError(httptest.NewRecorder(), http.StatusInternalServerError, err)
	got := out.String()
	if strings.Contains(got, privateKey) || strings.Contains(got, psk) || !strings.Contains(got, "не удалось применить") {
		t.Fatal("журнал должен сохранить причину ошибки и скрыть оба ключа")
	}
}

func TestWriteErrorRedactsErrorDetails(t *testing.T) {
	sensitive := "test-only-value"
	rec := httptest.NewRecorder()
	writeError(rec, http.StatusBadRequest, errors.New("некорректный параметр: password = "+sensitive))
	if strings.Contains(rec.Body.String(), sensitive) || !strings.Contains(rec.Body.String(), "некорректный параметр") {
		t.Fatal("ответ 400 должен содержать безопасное описание ошибки")
	}
}

func TestAuthLimitsConcurrentBcryptChecks(t *testing.T) {
	a := NewAuth("admin", "unused")
	a.Sleep = func(time.Duration) {}
	entered := make(chan struct{}, 10)
	release := make(chan struct{})
	a.Compare = func(_, _ []byte) error {
		entered <- struct{}{}
		<-release
		return errors.New("wrong password")
	}
	h := a.Middleware(http.NotFoundHandler())
	var workers sync.WaitGroup
	defer workers.Wait()
	defer close(release)
	for range 10 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.SetBasicAuth("admin", "wrong")
			h.ServeHTTP(httptest.NewRecorder(), r)
		}()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("проверка пароля не запустилась")
		}
	}
	select {
	case <-entered:
		t.Fatal("запущено больше двух параллельных проверок")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestCachedAdminRemainsAvailableDuringSharedAddressBlock(t *testing.T) {
	a := NewAuth("admin", "unused")
	a.Sleep = func(time.Duration) {}
	now := time.Now()
	a.Now = func() time.Time { return now }
	a.Compare = func(_, pass []byte) error {
		if string(pass) == "correct" {
			return nil
		}
		return errors.New("wrong password")
	}
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	try := func(pass string) int {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.SetBasicAuth("admin", pass)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	if got := try("correct"); got != http.StatusOK {
		t.Fatalf("вход администратора: %d", got)
	}
	for range maxFailures {
		if got := try("wrong"); got != http.StatusUnauthorized {
			t.Fatalf("неверный пароль до лимита: %d", got)
		}
		if got := try("correct"); got != http.StatusOK {
			t.Fatalf("запрос авторизованного администратора: %d", got)
		}
	}
	if got := try("wrong"); got != http.StatusTooManyRequests {
		t.Fatalf("опрос панели обнулил счётчик неверных паролей: %d", got)
	}
	for range 2 {
		now = now.Add(4 * time.Minute)
		if got := try("correct"); got != http.StatusOK {
			t.Fatalf("опрос авторизованного администратора во время блокировки: %d", got)
		}
	}
}
