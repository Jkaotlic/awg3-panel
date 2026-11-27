//go:build !readonly

package web

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/junktune"
)

type JunkTuneRunner interface {
	Run(context.Context, func(junktune.Result)) (junktune.Result, error)
	FindJunk(context.Context, junktune.Options, func(junktune.Result)) (junktune.Result, error)
}

// JunkTuneProfile identifies the unchanged parts of a measurement and the
// stored peer values that applying it is allowed to replace.
type JunkTuneProfile struct {
	Fingerprint [32]byte
	Parameters  junktune.Parameters
}

func (p JunkTuneProfile) saved(params junktune.Parameters, full bool) JunkTuneProfile {
	p.Parameters.Jitter = params.Jitter
	if full {
		p.Parameters.CPS = params.CPS
	}
	return p
}

type junkTuneHTTP struct {
	iface, peer string
	runner      JunkTuneRunner
	check       func(context.Context, bool) (JunkTuneProfile, error)
	apply       func(context.Context, junktune.Parameters, bool, JunkTuneProfile) error
	preview     func(context.Context, junktune.Parameters, bool, JunkTuneProfile) (string, string, error)

	mu       sync.Mutex
	closed   bool
	applying bool
	job      *junkTuneJob
}

type junkTuneJob struct {
	junkTuneStatus
	profile JunkTuneProfile
	cancel  context.CancelFunc
	done    chan struct{}
}

type junkTuneStatus struct {
	ID       string            `json:"id"`
	Running  bool              `json:"running"`
	Error    string            `json:"error,omitempty"`
	Result   junktune.Result   `json:"result"`
	Options  *junktune.Options `json:"options,omitempty"`
	CanApply bool              `json:"can_apply,omitempty"`
	Applied  *int              `json:"applied,omitempty"`
}

// EnableJunkTune binds the optional runner to one peer before serving HTTP.
// check validates the binding and fingerprints the configuration being tested.
func (s *Server) EnableJunkTune(iface, peer string, runner JunkTuneRunner,
	check func(context.Context, bool) (JunkTuneProfile, error),
	apply func(context.Context, junktune.Parameters, bool, JunkTuneProfile) error,
	preview func(context.Context, junktune.Parameters, bool, JunkTuneProfile) (string, string, error),
) {
	s.junkTune = &junkTuneHTTP{iface: iface, peer: peer, runner: runner, check: check, apply: apply, preview: preview}
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
	mux.HandleFunc("GET "+path+"/export", s.exportJunkTune)
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
	var status junkTuneStatus
	if tune.job != nil {
		status = copyJunkTuneStatus(tune.job.junkTuneStatus)
	}
	tune.mu.Unlock()
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) startJunkTune(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.tunePeer(w, r); !ok {
		return
	}
	var options *junktune.Options
	if r.Body != nil && r.Body != http.NoBody {
		var request junktune.Options
		if err := decodeJSONObject(w, r, 4096, &request); err != nil {
			if !errors.Is(err, io.EOF) {
				writeJSONRequestError(w, err)
				return
			}
		} else {
			normalized, err := junktune.NormalizeOptions(request)
			if err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			options = &normalized
		}
	}
	tune := s.junkTune
	tune.mu.Lock()
	if tune.closed || tune.applying || tune.job != nil && tune.job.Running {
		tune.mu.Unlock()
		junkTuneConflict(w, "Автоподбор уже выполняется или панель останавливается")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	job := &junkTuneJob{
		junkTuneStatus: junkTuneStatus{ID: rand.Text(), Running: true, Options: options},
		cancel:         cancel,
		done:           make(chan struct{}),
	}
	tune.job = job
	status := copyJunkTuneStatus(job.junkTuneStatus)
	go tune.run(ctx, job)
	tune.mu.Unlock()
	writeJSON(w, http.StatusAccepted, status)
}

func (t *junkTuneHTTP) run(ctx context.Context, job *junkTuneJob) {
	defer job.cancel()
	var result junktune.Result
	profile, err := t.check(ctx, job.Options != nil)
	bound := err == nil
	var message string
	if err != nil {
		message = "Проверка привязки не прошла. Сверьте тестовый профиль с конфигом пира и доступность AWG Manager."
	} else {
		progress := func(partial junktune.Result) {
			t.mu.Lock()
			defer t.mu.Unlock()
			job.Result = copyJunkTuneResult(partial)
		}
		if job.Options == nil {
			result, err = t.runner.Run(ctx, progress)
		} else {
			result, err = t.runner.FindJunk(ctx, *job.Options, progress)
		}
	}
	canceled := errors.Is(err, context.Canceled) && !errors.Is(err, junktune.ErrRestore)
	timedOut := errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, junktune.ErrRestore)
	switch {
	case err == nil:
	case canceled:
		message = "Подбор отменён."
	case timedOut:
		message = "Подбор остановлен по тайм-ауту."
	default:
		if message == "" {
			message = "Подбор прервался. Проверьте состояние тестового туннеля и повторите. Незавершённый сеанс восстанавливается перед новым прогоном."
		}
	}
	var applied *int
	if err == nil && ctx.Err() == nil && job.Options != nil && job.Options.AutoApply &&
		result.Best != nil && *result.Best >= 0 && *result.Best < len(result.Attempts) {
		index := *result.Best
		attempt := result.Attempts[index]
		params := junktune.Parameters{Jitter: attempt.Jitter, CPS: attempt.CPS}
		applyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		applyErr := t.apply(applyCtx, params, true, profile)
		cancel()
		if applyErr == nil {
			applied = &index
			profile = profile.saved(params, true)
		} else {
			message = "Подбор завершён. Автоматическое сохранение не удалось."
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	job.profile = profile
	job.Running, job.Error = false, message
	job.CanApply = bound && (err == nil || canceled && job.Options != nil)
	job.Applied = applied
	if len(result.Attempts) > 0 || message == "" {
		job.Result = copyJunkTuneResult(result)
	}
	close(job.done)
}

func copyJunkTuneStatus(from junkTuneStatus) junkTuneStatus {
	out := from
	out.Result = copyJunkTuneResult(from.Result)
	if from.Options != nil {
		opts := *from.Options
		out.Options = &opts
	}
	if from.Applied != nil {
		applied := *from.Applied
		out.Applied = &applied
	}
	return out
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
	job := tune.job
	if job == nil || job.ID != body.ID || !job.Running {
		tune.mu.Unlock()
		junkTuneConflict(w, "Активная попытка не найдена")
		return
	}
	job.cancel()
	status := copyJunkTuneStatus(job.junkTuneStatus)
	tune.mu.Unlock()
	writeJSON(w, http.StatusAccepted, status)
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
	if tune.closed || tune.applying || job == nil || job.ID != body.ID || job.Running || !job.CanApply {
		tune.mu.Unlock()
		junkTuneConflict(w, "Для применения нужен актуальный завершённый подбор")
		return
	}
	if body.Attempt == nil || *body.Attempt < 0 || *body.Attempt >= len(job.Result.Attempts) {
		tune.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Выберите попытку с успешными прогонами"})
		return
	}
	attempt := job.Result.Attempts[*body.Attempt]
	full := job.Options != nil
	if attempt.Successes == 0 || full && attempt.Runs != 3 {
		tune.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Выберите завершённую попытку с успешными прогонами"})
		return
	}
	params := junktune.Parameters{Jitter: attempt.Jitter, CPS: attempt.CPS}
	profile := job.profile
	tune.applying = true
	tune.mu.Unlock()
	defer func() {
		tune.mu.Lock()
		tune.applying = false
		tune.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := tune.apply(ctx, params, full, profile); err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	tune.mu.Lock()
	job.profile = profile.saved(params, full)
	job.Applied = body.Attempt
	tune.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) exportJunkTune(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.tunePeer(w, r); !ok {
		return
	}
	index, err := strconv.Atoi(r.URL.Query().Get("attempt"))
	if err != nil || index < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Укажите номер попытки"})
		return
	}
	tune := s.junkTune
	tune.mu.Lock()
	job := tune.job
	if job == nil || job.ID != r.URL.Query().Get("id") || job.Running || !job.CanApply {
		tune.mu.Unlock()
		junkTuneConflict(w, "Для выгрузки нужен актуальный завершённый подбор")
		return
	}
	full := job.Options != nil
	if index >= len(job.Result.Attempts) || job.Result.Attempts[index].Successes == 0 ||
		full && job.Result.Attempts[index].Runs != 3 {
		tune.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Выберите завершённую попытку с успешными прогонами"})
		return
	}
	attempt, profile := job.Result.Attempts[index], job.profile
	tune.mu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	params := junktune.Parameters{Jitter: attempt.Jitter, CPS: attempt.CPS}
	name, body, err := tune.preview(ctx, params, full, profile)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeClientConfig(w, name, body)
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
