//go:build !readonly

package web_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
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
	server.EnableJunkTune("awg3", "lab", runner, func(context.Context) ([32]byte, error) { return digest, nil },
		func(_ context.Context, jitter issuer.Jitter, expected [32]byte) error {
			if digest != expected {
				return fmt.Errorf("%w: профиль изменился", issuer.ErrStateConflict)
			}
			return m.Update("lab", issuer.PeerPatch{Jitter: &jitter})
		})
	return server, m, runner, &digest
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
