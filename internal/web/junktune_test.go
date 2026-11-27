//go:build !readonly

package web_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/junktune"
	"github.com/Jkaotlic/awg3-panel/internal/web"
	"golang.org/x/crypto/bcrypt"
)

type tuneRunner struct {
	entered chan struct{}
	release chan struct{}
	options junktune.Options
	applied junktune.Parameters
}

func (r *tuneRunner) FindJunk(ctx context.Context, opts junktune.Options, progress func(junktune.Result)) (junktune.Result, error) {
	r.options = opts
	result, err := r.Run(ctx, progress)
	if err == nil {
		result.Attempts[1].CPS = [5]string{"<r 21>", "<r 29>"}
		result.Attempts[1].Profile = opts.Profile
	}
	return result, err
}

func (r *tuneRunner) Run(ctx context.Context, progress func(junktune.Result)) (junktune.Result, error) {
	first := junktune.Attempt{Runs: 2, Successes: 0, Jitter: issuer.Jitter{Jc: 4, Jmin: 80, Jmax: 300}}
	second := junktune.Attempt{Runs: 3, Successes: 3, MedianMS: 55, Jitter: issuer.Jitter{Jc: 7, Jmin: 70, Jmax: 490}}
	progress(junktune.Result{Attempts: []junktune.Attempt{first}})
	close(r.entered)
	select {
	case <-ctx.Done():
		return junktune.Result{}, ctx.Err()
	case <-r.release:
		best := 1
		return junktune.Result{Attempts: []junktune.Attempt{first, second}, Best: &best}, nil
	}
}

const tunePath = "/api/ifaces/awg3/peers/lab/junktune"

func tunerFixture(t *testing.T) (*web.Server, *fakeMutator, *tuneRunner, *[32]byte) {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("секрет"), bcrypt.MinCost)
	cfg := config.Default()
	cfg.Auth.User, cfg.Auth.Bcrypt = "admin", string(hash)
	reg := &fakeRegistry{
		metas:   []issuer.IfaceMeta{{ID: "awg3", Title: "test", Interface: "awg3"}},
		listers: map[string]web.PeerLister{"awg3": &fakeLister{}},
	}
	m := &fakeMutator{}
	server := web.NewServerWithMutator(cfg, reg, &fakeMutatorRegistry{byID: map[string]web.PeerMutator{"awg3": m}})
	runner := &tuneRunner{entered: make(chan struct{}), release: make(chan struct{})}
	digest := sha256.Sum256([]byte("test config"))
	var stored junktune.Parameters
	profile := func() web.JunkTuneProfile { return web.JunkTuneProfile{Fingerprint: digest, Parameters: stored} }
	server.EnableJunkTune("awg3", "lab", runner, func(context.Context, bool) (web.JunkTuneProfile, error) { return profile(), nil },
		func(_ context.Context, parameters junktune.Parameters, full bool, expected web.JunkTuneProfile) error {
			if profile() != expected {
				return fmt.Errorf("%w: профиль изменился", issuer.ErrStateConflict)
			}
			if err := m.Update("lab", issuer.PeerPatch{Jitter: &parameters.Jitter}); err != nil {
				return err
			}
			stored.Jitter = parameters.Jitter
			if full {
				runner.applied = parameters
				stored.CPS = parameters.CPS
			}
			return nil
		}, func(_ context.Context, parameters junktune.Parameters, full bool, expected web.JunkTuneProfile) (string, string, error) {
			if !full || profile() != expected || parameters.CPS[1] != "<r 29>" {
				return "", "", issuer.ErrStateConflict
			}
			return "lab-attempt.conf", "I2 = <r 29>\n", nil
		})
	return server, m, runner, &digest
}

func TestFindJunkHTTPUsesSelectedProfileAndSavesMeasuredCPS(t *testing.T) {
	s, _, runner, _ := tunerFixture(t)
	handler := s.Handler()
	wrong := doAuthed(t, handler, http.MethodPost, tunePath, strings.NewReader(`{"profile":"unknown"}`))
	if wrong.Code != http.StatusBadRequest {
		t.Fatalf("invalid profile accepted: %d", wrong.Code)
	}
	start := doAuthed(t, handler, http.MethodPost, tunePath, strings.NewReader(`{"profile":"dns","host_preset":"custom","domains":"example.com","max_attempts":5,"threshold_pct":90}`))
	var state struct {
		ID       string
		Running  bool
		CanApply bool `json:"can_apply"`
	}
	if err := json.Unmarshal(start.Body.Bytes(), &state); err != nil || start.Code != http.StatusAccepted || state.ID == "" {
		t.Fatalf("start: %d %s", start.Code, start.Body)
	}
	select {
	case <-runner.entered:
	case <-time.After(time.Second):
		t.Fatal("find-junk did not start")
	}
	if runner.options.Profile != "dns" || runner.options.Domains != "example.com" ||
		runner.options.MaxAttempts != 5 || runner.options.ThresholdPct != 90 {
		t.Fatalf("wrong search options: %+v", runner.options)
	}
	close(runner.release)
	deadline := time.Now().Add(time.Second)
	for state.Running && time.Now().Before(deadline) {
		rec := doAuthed(t, handler, http.MethodGet, tunePath, nil)
		if err := json.Unmarshal(rec.Body.Bytes(), &state); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	if state.Running || !state.CanApply {
		t.Fatal("completed results were not available")
	}
	exported := doAuthed(t, handler, http.MethodGet, tunePath+"/export?id="+state.ID+"&attempt=1", nil)
	if exported.Code != http.StatusOK || exported.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(exported.Body.String(), "I2 = <r 29>") || runner.applied != (junktune.Parameters{}) {
		t.Fatalf("export should render only the selected candidate: %d %s", exported.Code, exported.Body)
	}
	body := strings.NewReader(`{"id":"` + state.ID + `","attempt":1}`)
	if rec := doAuthed(t, handler, http.MethodPost, tunePath+"/apply", body); rec.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body)
	}
	if runner.applied.CPS != ([5]string{"<r 21>", "<r 29>"}) {
		t.Fatalf("measured CPS did not reach the save callback: %+v", runner.applied)
	}
}

func TestFindJunkAutoSavesOnlyAfterFinishing(t *testing.T) {
	s, _, runner, _ := tunerFixture(t)
	handler := s.Handler()
	start := doAuthed(t, handler, http.MethodPost, tunePath, strings.NewReader(`{"profile":"dns","auto_apply":true}`))
	if start.Code != http.StatusAccepted {
		t.Fatalf("start: %d %s", start.Code, start.Body)
	}
	select {
	case <-runner.entered:
	case <-time.After(time.Second):
		t.Fatal("find-junk did not start")
	}
	if runner.applied != (junktune.Parameters{}) {
		t.Fatal("auto-apply ran before the result")
	}
	close(runner.release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		rec := doAuthed(t, handler, http.MethodGet, tunePath, nil)
		var state struct {
			Running bool
			Applied *int
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &state); err != nil {
			t.Fatal(err)
		}
		if !state.Running {
			if state.Applied == nil || *state.Applied != 1 || runner.applied.CPS[1] != "<r 29>" {
				t.Fatalf("selected CPS was not saved: %s", rec.Body)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("find-junk did not finish")
}

func TestJunkTuneReportsAndAppliesOnlyMeasuredBoundPeer(t *testing.T) {
	s, m, runner, digest := tunerFixture(t)
	handler := s.Handler()
	other := strings.Replace(tunePath, "/lab/", "/another/", 1)
	if rec := doAuthed(t, handler, http.MethodPost, other, nil); rec.Code != 404 {
		t.Fatalf("unbound peer can start a job: %d", rec.Code)
	}
	start := doAuthed(t, handler, http.MethodPost, tunePath, nil)
	if start.Code != http.StatusAccepted {
		t.Fatalf("start: %d %s", start.Code, start.Body)
	}
	var status struct {
		ID      string          `json:"id"`
		Running bool            `json:"running"`
		Result  junktune.Result `json:"result"`
		Error   string          `json:"error"`
	}
	if err := json.Unmarshal(start.Body.Bytes(), &status); err != nil || status.ID == "" {
		t.Fatalf("missing job ID: %v", err)
	}
	select {
	case <-runner.entered:
	case <-time.After(time.Second):
		t.Fatal("job did not start")
	}
	if rec := doAuthed(t, handler, http.MethodPost, tunePath, nil); rec.Code != http.StatusConflict {
		t.Fatalf("second job: %d", rec.Code)
	}
	if rec := doAuthed(t, handler, http.MethodPost, tunePath+"/apply", strings.NewReader(`{"id":"`+status.ID+`","attempt":0}`)); rec.Code != http.StatusConflict {
		t.Fatalf("applied while running: %d", rec.Code)
	}
	close(runner.release)
	deadline := time.Now().Add(time.Second)
	for {
		rec := doAuthed(t, handler, http.MethodGet, tunePath, nil)
		if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if !status.Running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("job did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	if status.Error != "" || status.Result.Best == nil || *status.Result.Best != 1 || len(status.Result.Attempts) != 2 {
		t.Fatalf("unexpected result: %+v", status)
	}
	for _, request := range []string{`{"id":"old","attempt":1}`, `{"id":"` + status.ID + `","attempt":0}`, `{"id":"` + status.ID + `"}`} {
		if rec := doAuthed(t, handler, http.MethodPost, tunePath+"/apply", strings.NewReader(request)); rec.Code < 400 {
			t.Fatalf("invalid selection applied: %s", request)
		}
	}
	saved := *digest
	*digest = sha256.Sum256([]byte("changed config"))
	apply := `{"id":"` + status.ID + `","attempt":1}`
	if rec := doAuthed(t, handler, http.MethodPost, tunePath+"/apply", strings.NewReader(apply)); rec.Code != http.StatusConflict {
		t.Fatalf("applied stale result: %d", rec.Code)
	}
	*digest = saved
	if rec := doAuthed(t, handler, http.MethodPost, tunePath+"/apply", strings.NewReader(apply)); rec.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body)
	}
	if j := m.lastPatch.Jitter; j == nil || j.Jc != 7 || m.lastPatch.Overrides != nil || m.lastPatch.Name != nil || m.lastPatch.Address != nil {
		t.Fatalf("wrong patch: %+v", m.lastPatch)
	}
}

func TestJunkTuneCancelsOnlyMatchingJob(t *testing.T) {
	s, m, runner, _ := tunerFixture(t)
	handler := s.Handler()
	start := doAuthed(t, handler, http.MethodPost, tunePath, nil)
	var status struct {
		ID      string
		Running bool
		Error   string
	}
	if err := json.Unmarshal(start.Body.Bytes(), &status); err != nil || !status.Running || status.ID == "" {
		t.Fatalf("start: %d %s", start.Code, start.Body)
	}
	select {
	case <-runner.entered:
	case <-time.After(time.Second):
		t.Fatal("job did not start")
	}
	if rec := doAuthed(t, handler, http.MethodPost, tunePath+"/cancel", strings.NewReader(`{"id":"old"}`)); rec.Code != http.StatusConflict {
		t.Fatalf("cancelled a different job: %d", rec.Code)
	}
	if rec := doAuthed(t, handler, http.MethodPost, tunePath+"/cancel", strings.NewReader(`{"id":"`+status.ID+`"}`)); rec.Code != http.StatusAccepted {
		t.Fatalf("cancel: %d %s", rec.Code, rec.Body)
	}
	deadline := time.Now().Add(time.Second)
	for status.Running && time.Now().Before(deadline) {
		rec := doAuthed(t, handler, http.MethodGet, tunePath, nil)
		if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	if status.Running || status.Error != "Подбор отменён." || m.lastPatch.Jitter != nil {
		t.Fatalf("cancel did not settle without an apply: %+v", status)
	}
}

type wrappedErrRunner struct {
	err error
}

func (r wrappedErrRunner) Run(context.Context, func(junktune.Result)) (junktune.Result, error) {
	return junktune.Result{}, r.err
}

func (r wrappedErrRunner) FindJunk(context.Context, junktune.Options, func(junktune.Result)) (junktune.Result, error) {
	return junktune.Result{}, r.err
}

func TestJunkTuneHandlesWrappedContextErrorsAndChunkedEmptyBody(t *testing.T) {
	cases := []struct {
		name         string
		err          error
		optionsBody  string
		wantMessage  string
		wantCanApply bool
	}{
		{
			name:         "wrapped-cancel-findjunk",
			err:          fmt.Errorf("probe: %w", context.Canceled),
			optionsBody:  `{"profile":"dns"}`,
			wantMessage:  "Подбор отменён.",
			wantCanApply: true,
		},
		{
			name:         "wrapped-deadline",
			err:          fmt.Errorf("start: %w", context.DeadlineExceeded),
			optionsBody:  `{"profile":"dns"}`,
			wantMessage:  "Подбор остановлен по тайм-ауту.",
			wantCanApply: false,
		},
		{
			name:         "cancel-with-restore-error",
			err:          fmt.Errorf("%w: %w", junktune.ErrRestore, context.Canceled),
			optionsBody:  `{"profile":"dns"}`,
			wantMessage:  "Подбор прервался. Проверьте состояние тестового туннеля и повторите. Незавершённый сеанс восстанавливается перед новым прогоном.",
			wantCanApply: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _, _ := tunerFixture(t)
			s.EnableJunkTune("awg3", "lab", wrappedErrRunner{err: tc.err},
				func(context.Context, bool) (web.JunkTuneProfile, error) { return web.JunkTuneProfile{}, nil },
				func(context.Context, junktune.Parameters, bool, web.JunkTuneProfile) error { return nil },
				func(context.Context, junktune.Parameters, bool, web.JunkTuneProfile) (string, string, error) { return "", "", nil },
			)
			handler := s.Handler()
			start := doAuthed(t, handler, http.MethodPost, tunePath, strings.NewReader(tc.optionsBody))
			if start.Code != http.StatusAccepted {
				t.Fatalf("start: %d %s", start.Code, start.Body)
			}
			var status struct {
				Running  bool
				Error    string
				CanApply bool `json:"can_apply"`
			}
			status.Running = true
			deadline := time.Now().Add(time.Second)
			for status.Running && time.Now().Before(deadline) {
				rec := doAuthed(t, handler, http.MethodGet, tunePath, nil)
				if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
					t.Fatal(err)
				}
				time.Sleep(time.Millisecond)
			}
			if status.Running || status.Error != tc.wantMessage || status.CanApply != tc.wantCanApply {
				t.Fatalf("got %+v, want error=%q can_apply=%v", status, tc.wantMessage, tc.wantCanApply)
			}
		})
	}

	// Chunked empty body (ContentLength == -1, 0 bytes) should start a jitter-only run.
	s, _, runner, _ := tunerFixture(t)
	handler := s.Handler()
	rec := doAuthed(t, handler, http.MethodPost, tunePath, io.NopCloser(strings.NewReader("")))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("chunked empty body rejected: %d %s", rec.Code, rec.Body)
	}
	close(runner.release)
}
