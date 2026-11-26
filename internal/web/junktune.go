//go:build !readonly

package web

import (
	"context"
	"crypto/rand"
	"net/http"
	"sync"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/junktune"
)

type JunkTuneRunner interface {
	Run(context.Context, func(junktune.Result)) (junktune.Result, error)
}

type junkTuneHTTP struct {
	iface, peer string
	runner      JunkTuneRunner
	check       func(context.Context) ([32]byte, error)
	apply       func(context.Context, issuer.Jitter, [32]byte) error

	mu       sync.Mutex
	closed   bool
	applying bool
	job      *junkTuneJob
}

type junkTuneJob struct {
	junkTuneStatus
	fingerprint [32]byte
	cancel      context.CancelFunc
	done        chan struct{}
}

type junkTuneStatus struct {
	ID      string          `json:"id"`
	Running bool            `json:"running"`
	Error   string          `json:"error,omitempty"`
	Result  junktune.Result `json:"result"`
}

// EnableJunkTune binds the optional runner to one peer before serving HTTP.
// check validates the binding and fingerprints the configuration being tested.
func (s *Server) EnableJunkTune(iface, peer string, runner JunkTuneRunner,
	check func(context.Context) ([32]byte, error),
	apply func(context.Context, issuer.Jitter, [32]byte) error,
) {
	s.junkTune = &junkTuneHTTP{iface: iface, peer: peer, runner: runner, check: check, apply: apply}
}

func (s *Server) junkTuneBinding() (string, string) {
	if s.junkTune == nil || s.mutators == nil {
		return "", ""
	}
	return s.junkTune.iface, s.junkTune.peer
}

func (s *Server) registerJunkTune(mux *http.ServeMux) {
	iface, _ := s.junkTuneBinding()
	if iface == "" {
		return
	}
	const path = "/api/ifaces/{iface}/peers/{id}/junktune"
	mux.HandleFunc("GET "+path, s.junkTuneStatus)
	mux.HandleFunc("POST "+path, s.startJunkTune)
	mux.HandleFunc("POST "+path+"/cancel", s.cancelJunkTune)
	mux.HandleFunc("POST "+path+"/apply", s.applyJunkTune)
}

func (s *Server) tunePeer(w http.ResponseWriter, r *http.Request) (PeerMutator, bool) {
	iface, peer := s.junkTuneBinding()
	if iface != r.PathValue("iface") || peer != r.PathValue("id") {
		http.NotFound(w, r)
		return nil, false
	}
	return s.mutatorFor(w, r)
}

func (s *Server) junkTuneStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.tunePeer(w, r); !ok {
		return
	}
	tune := s.junkTune
	tune.mu.Lock()
	defer tune.mu.Unlock()
	if tune.job == nil {
		writeJSON(w, http.StatusOK, junkTuneStatus{})
		return
	}
	writeJSON(w, http.StatusOK, tune.job.junkTuneStatus)
}

func (s *Server) startJunkTune(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.tunePeer(w, r); !ok {
		return
	}
	tune := s.junkTune
	tune.mu.Lock()
	defer tune.mu.Unlock()
	if tune.closed || tune.applying || tune.job != nil && tune.job.Running {
		junkTuneConflict(w, "Автоподбор уже выполняется или панель останавливается")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	job := &junkTuneJob{
		junkTuneStatus: junkTuneStatus{ID: rand.Text(), Running: true},
		cancel:         cancel,
		done:           make(chan struct{}),
	}
	tune.job = job
	go tune.run(ctx, job)
	writeJSON(w, http.StatusAccepted, job.junkTuneStatus)
}

func (t *junkTuneHTTP) run(ctx context.Context, job *junkTuneJob) {
	defer job.cancel()
	var result junktune.Result
	fingerprint, err := t.check(ctx)
	var message string
	if err != nil {
		message = "Проверка привязки не прошла. Сверьте тестовый профиль с конфигом пира и доступность AWG Manager."
	} else {
		result, err = t.runner.Run(ctx, func(partial junktune.Result) {
			t.mu.Lock()
			defer t.mu.Unlock()
			job.Result = copyJunkTuneResult(partial)
		})
	}
	switch err {
	case nil:
	case context.Canceled:
		message = "Подбор отменён."
	case context.DeadlineExceeded:
		message = "Подбор остановлен по тайм-ауту."
	default:
		if message == "" {
			message = "Подбор прервался. Проверьте состояние тестового туннеля и повторите. Незавершённый сеанс восстанавливается перед новым прогоном."
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	job.fingerprint = fingerprint
	job.Running, job.Error = false, message
	if len(result.Attempts) > 0 || message == "" {
		job.Result = copyJunkTuneResult(result)
	}
	close(job.done)
}

func copyJunkTuneResult(from junktune.Result) junktune.Result {
	out := from
	out.Attempts = append([]junktune.Attempt(nil), from.Attempts...)
	if from.Best != nil {
		best := *from.Best
		out.Best = &best
	}
	return out
}

func (s *Server) cancelJunkTune(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.tunePeer(w, r); !ok {
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := decodeJSONObject(w, r, 1024, &body); err != nil {
		writeJSONRequestError(w, err)
		return
	}
	tune := s.junkTune
	tune.mu.Lock()
	defer tune.mu.Unlock()
	if job := tune.job; job == nil || job.ID != body.ID || !job.Running {
		junkTuneConflict(w, "Активная попытка не найдена")
		return
	}
	tune.job.cancel()
	writeJSON(w, http.StatusAccepted, tune.job.junkTuneStatus)
}

func (s *Server) applyJunkTune(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.tunePeer(w, r); !ok {
		return
	}
	var body struct {
		ID      string `json:"id"`
		Attempt *int   `json:"attempt"`
	}
	if err := decodeJSONObject(w, r, 1024, &body); err != nil {
		writeJSONRequestError(w, err)
		return
	}
	tune := s.junkTune
	tune.mu.Lock()
	job := tune.job
	if tune.closed || tune.applying || job == nil || job.ID != body.ID || job.Running || job.Error != "" {
		tune.mu.Unlock()
		junkTuneConflict(w, "Для применения нужен актуальный завершённый подбор")
		return
	}
	if body.Attempt == nil || *body.Attempt < 0 || *body.Attempt >= len(job.Result.Attempts) ||
		job.Result.Attempts[*body.Attempt].Successes == 0 {
		tune.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Выберите попытку с успешными прогонами"})
		return
	}
	jitter := job.Result.Attempts[*body.Attempt].Jitter
	fingerprint := job.fingerprint
	tune.applying = true
	tune.mu.Unlock()
	defer func() {
		tune.mu.Lock()
		tune.applying = false
		tune.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := tune.apply(ctx, jitter, fingerprint); err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func junkTuneConflict(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusConflict, map[string]string{"error": msg})
}

func (s *Server) stopJunkTune() <-chan struct{} {
	if s.junkTune == nil {
		return nil
	}
	tune := s.junkTune
	tune.mu.Lock()
	defer tune.mu.Unlock()
	tune.closed = true
	if tune.job == nil {
		return nil
	}
	tune.job.cancel()
	return tune.job.done
}
