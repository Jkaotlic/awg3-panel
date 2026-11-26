package junktune

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/filelock"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
)

var testControl = issuer.Jitter{Jc: 5, Jmin: 65, Jmax: 330}

type fakeRouter struct {
	state     Snapshot
	calls     []string
	probes    int
	measure   func(*fakeRouter, context.Context) (Measurement, error)
	snapshot  func(*fakeRouter) Snapshot
	stopError error
}

func testRouter() *fakeRouter {
	return &fakeRouter{state: Snapshot{
		Jitter: testControl, MTU: 1280,
		Endpoint: "198.51.100.1:3478", LocalAddress: "203.0.113.9/32",
		ServerPublicKey: "test-server-key",
	}}
}

func (r *fakeRouter) Snapshot(ctx context.Context) (Snapshot, error) {
	if r.snapshot != nil {
		return r.snapshot(r), ctx.Err()
	}
	return r.state, ctx.Err()
}

func (r *fakeRouter) SetJitter(ctx context.Context, j issuer.Jitter) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.calls = append(r.calls, "set")
	if r.state.Running || r.state.Enabled {
		return errors.New("jitter update while running")
	}
	r.state.Jitter = j
	return nil
}

func (r *fakeRouter) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.calls = append(r.calls, "start")
	if r.state.Running || r.state.Enabled {
		return errors.New("duplicate start")
	}
	r.state.Running, r.state.Enabled = true, true
	return nil
}

func (r *fakeRouter) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.calls = append(r.calls, "stop")
	if r.stopError != nil {
		return r.stopError
	}
	r.state.Running, r.state.Enabled = false, false
	return nil
}

func (r *fakeRouter) Probe(ctx context.Context) (Measurement, error) {
	r.probes++
	r.calls = append(r.calls, "probe")
	if !r.state.Running || !r.state.Enabled {
		return Measurement{}, errors.New("probe while stopped")
	}
	if r.measure != nil {
		return r.measure(r, ctx)
	}
	return Measurement{Success: true, Latency: 20 * time.Millisecond}, nil
}

func TestRunMeasuresUniqueCandidatesAndRestoresControl(t *testing.T) {
	r := testRouter()
	path := filepath.Join(t.TempDir(), "pending.json")
	var progress []Result
	got, err := New(r, path).Run(context.Background(), func(p Result) {
		progress = append(progress, p)
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Best == nil || *got.Best != 0 || len(got.Attempts) != 4 {
		t.Fatalf("expected four candidates and control as winner, got %+v", got)
	}
	if got.Attempts[0].Jitter != testControl {
		t.Fatal("first trial is not the original jitter")
	}
	seen := map[issuer.Jitter]bool{}
	for _, a := range got.Attempts {
		if a.Runs != 3 || a.Successes != 3 || a.MedianMS != 20 || seen[a.Jitter] || a.Jitter.Jmax >= r.state.MTU {
			t.Fatalf("invalid or repeated attempt: %+v", a)
		}
		seen[a.Jitter] = true
	}
	if r.probes != 12 || len(progress) < 4 {
		t.Fatalf("probes=%d callbacks=%d", r.probes, len(progress))
	}
	if progress[0].Best != nil || len(progress[0].Attempts) != 1 || progress[0].Attempts[0].Runs >= 3 {
		t.Fatalf("initial progress was overwritten or delayed: %+v", progress[0])
	}
	for i, call := range r.calls {
		if call == "probe" && (r.calls[i-1] != "start" || r.calls[i+1] != "stop") {
			t.Fatalf("trial does not start afresh: %v", r.calls)
		}
	}
	assertRestored(t, r, path)
}

func TestRunRanksSuccessRatioThenMedian(t *testing.T) {
	r := testRouter()
	path := filepath.Join(t.TempDir(), "pending.json")
	latencies := [][]int64{{1, 1, 0}, {1, 60, 90}, {3, 6, 50}, {1, 0, 0}}
	r.measure = func(r *fakeRouter, _ context.Context) (Measurement, error) {
		i := r.probes - 1
		ms := latencies[i/3][i%3]
		return Measurement{Success: ms > 0, Latency: time.Duration(ms) * time.Millisecond}, nil
	}
	got, err := New(r, path).Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Best == nil || *got.Best != 2 || got.Attempts[2].MedianMS != 6 {
		t.Fatalf("unexpected ranking: %+v", got)
	}
	assertRestored(t, r, path)
}

func TestRunNoSuccessfulProbeHasNoRecommendation(t *testing.T) {
	r := testRouter()
	r.measure = func(*fakeRouter, context.Context) (Measurement, error) {
		return Measurement{}, nil
	}
	path := filepath.Join(t.TempDir(), "pending.json")
	got, err := New(r, path).Run(context.Background(), nil)
	if err != nil || got.Best != nil || len(got.Attempts) != 4 {
		t.Fatalf("got %+v, err %v", got, err)
	}
	assertRestored(t, r, path)
}

func TestRunOneSuccessCanBeRecommended(t *testing.T) {
	r := testRouter()
	r.measure = func(r *fakeRouter, _ context.Context) (Measurement, error) {
		return Measurement{Success: r.probes == 4, Latency: time.Millisecond}, nil
	}
	path := filepath.Join(t.TempDir(), "pending.json")
	got, err := New(r, path).Run(context.Background(), nil)
	if err != nil || got.Best == nil || *got.Best != 1 {
		t.Fatalf("got %+v, err %v", got, err)
	}
	assertRestored(t, r, path)
}

func TestRunRejectsUnsafePreflightWithoutWritingRouter(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*Snapshot)
	}{
		{"running", func(s *Snapshot) { s.Running = true }},
		{"enabled", func(s *Snapshot) { s.Enabled = true }},
		{"missing identity", func(s *Snapshot) { s.Endpoint = "" }},
		{"no MTU", func(s *Snapshot) { s.MTU = 0 }},
		{"invalid triple", func(s *Snapshot) { s.Jitter.Jmin = 0 }},
		{"junk at MTU", func(s *Snapshot) { s.Jitter.Jmax = s.MTU }},
		{"no candidate fits", func(s *Snapshot) { s.Jitter = issuer.Jitter{}; s.MTU = 264 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := testRouter()
			tc.modify(&r.state)
			path := filepath.Join(t.TempDir(), "pending.json")
			_, err := New(r, path).Run(context.Background(), nil)
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("err=%v calls=%v", err, r.calls)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("preflight created journal: %v", err)
			}
		})
	}
}

func TestRunCancellationRestoresWithIndependentContext(t *testing.T) {
	r := testRouter()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path := filepath.Join(t.TempDir(), "pending.json")
	r.measure = func(r *fakeRouter, ctx context.Context) (Measurement, error) {
		if r.probes == 4 {
			if r.state.Jitter == testControl {
				t.Error("expected changed jitter when cancelling")
			}
			cancel()
			return Measurement{}, ctx.Err()
		}
		return Measurement{Success: true, Latency: time.Millisecond}, nil
	}
	got, err := New(r, path).Run(ctx, nil)
	if !errors.Is(err, context.Canceled) || got.Best != nil {
		t.Fatalf("got %+v, err %v", got, err)
	}
	assertRestored(t, r, path)
}

func TestRunPreservesDetectableExternalChange(t *testing.T) {
	r := testRouter()
	path := filepath.Join(t.TempDir(), "pending.json")
	external := issuer.Jitter{Jc: 1, Jmin: 35, Jmax: 79}
	r.measure = func(r *fakeRouter, _ context.Context) (Measurement, error) {
		r.state.Jitter = external
		return Measurement{Success: true, Latency: time.Millisecond}, nil
	}
	_, err := New(r, path).Run(context.Background(), nil)
	if err == nil || r.state.Jitter != external || !r.state.Running || !r.state.Enabled {
		t.Fatalf("external change not protected: err=%v state=%+v", err, r.state)
	}
	if !reflect.DeepEqual(r.calls, []string{"start", "probe"}) {
		t.Fatalf("unexpected mutations: %v", r.calls)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{r.state.Endpoint, r.state.LocalAddress, r.state.ServerPublicKey} {
		if strings.Contains(string(body), secret) {
			t.Fatal("journal contains plaintext target metadata")
		}
	}
	if _, err := New(r, path).Run(context.Background(), nil); err == nil || len(r.calls) != 2 {
		t.Fatalf("recovery changed external state: err=%v calls=%v", err, r.calls)
	}
}

func TestRunAfterInterruptedStopRecoversBeforeNewTrial(t *testing.T) {
	r := testRouter()
	path := filepath.Join(t.TempDir(), "pending.json")
	r.measure = func(r *fakeRouter, _ context.Context) (Measurement, error) {
		if r.probes == 4 {
			r.stopError = errors.New("simulated stop failure")
		}
		return Measurement{Success: true, Latency: time.Millisecond}, nil
	}
	_, err := New(r, path).Run(context.Background(), nil)
	if err == nil || !r.state.Running || r.state.Jitter == testControl {
		t.Fatalf("interruption did not leave pending work: err=%v state=%+v", err, r.state)
	}
	r.measure, r.stopError, r.calls = nil, nil, nil
	got, err := New(r, path).Run(context.Background(), nil)
	if err != nil || len(got.Attempts) != 4 || got.Attempts[0].Jitter != testControl {
		t.Fatalf("recovery failed: result=%+v err=%v", got, err)
	}
	if len(r.calls) < 2 || r.calls[0] != "stop" || r.calls[1] != "set" {
		t.Fatalf("first actions must be recovery, got %v", r.calls)
	}
	assertRestored(t, r, path)
}

func TestRunPreservesObservedChangeAcrossSubsequentMatchingSnapshot(t *testing.T) {
	r := testRouter()
	path := filepath.Join(t.TempDir(), "pending.json")
	changeObserved := false
	r.measure = func(*fakeRouter, context.Context) (Measurement, error) {
		changeObserved = true
		return Measurement{Success: true, Latency: time.Millisecond}, nil
	}
	r.snapshot = func(r *fakeRouter) Snapshot {
		s := r.state
		if changeObserved {
			changeObserved = false
			s.Jitter.Jc++
		}
		return s
	}
	_, err := New(r, path).Run(context.Background(), nil)
	if err == nil || !reflect.DeepEqual(r.calls, []string{"start", "probe"}) {
		t.Fatalf("observed conflict was overwritten: err=%v calls=%v", err, r.calls)
	}
	_, err = New(r, path).Run(context.Background(), nil)
	if err == nil || !reflect.DeepEqual(r.calls, []string{"start", "probe"}) {
		t.Fatalf("pending conflict was overwritten: err=%v calls=%v", err, r.calls)
	}
}

func TestRunStopsWhenOtherWireSettingsChange(t *testing.T) {
	r := testRouter()
	r.measure = func(r *fakeRouter, _ context.Context) (Measurement, error) {
		r.state.WireFingerprint[0] = 1
		return Measurement{Success: true}, nil
	}
	path := filepath.Join(t.TempDir(), "pending.json")
	result, err := New(r, path).Run(context.Background(), nil)
	if err == nil || result.Best != nil || !reflect.DeepEqual(r.calls, []string{"start", "probe"}) {
		t.Fatalf("unexpected external change was overwritten: result=%+v err=%v calls=%v", result, err, r.calls)
	}
}

func TestRunBreaksNonControlTiesByLowerCost(t *testing.T) {
	r := testRouter()
	path := filepath.Join(t.TempDir(), "pending.json")
	r.measure = func(r *fakeRouter, _ context.Context) (Measurement, error) {
		return Measurement{Success: r.probes > 3, Latency: time.Millisecond}, nil
	}
	got, err := New(r, path).Run(context.Background(), nil)
	if err != nil || got.Best == nil {
		t.Fatalf("got %+v, err %v", got, err)
	}
	best := 1
	for i := 2; i < len(got.Attempts); i++ {
		a, b := got.Attempts[i].Jitter, got.Attempts[best].Jitter
		if a.Jc*a.Jmax < b.Jc*b.Jmax {
			best = i
		}
	}
	if *got.Best != best {
		t.Fatalf("best=%d, expected candidate %d", *got.Best, best)
	}
}

func TestRunUsesCrossProcessLock(t *testing.T) {
	r := testRouter()
	path := filepath.Join(t.TempDir(), "pending.json")
	lock, err := filelock.Try(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	_, err = New(r, path).Run(context.Background(), nil)
	if !errors.Is(err, filelock.ErrLocked) || len(r.calls) != 0 {
		t.Fatalf("engine bypassed lock: err=%v calls=%v", err, r.calls)
	}
}

func TestResultOmitsTargetDetails(t *testing.T) {
	r := testRouter()
	path := filepath.Join(t.TempDir(), "pending.json")
	got, err := New(r, path).Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{r.state.Endpoint, r.state.LocalAddress, r.state.ServerPublicKey} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("result contains target metadata")
		}
	}
}

func assertRestored(t *testing.T, r *fakeRouter, path string) {
	t.Helper()
	if r.state.Jitter != testControl || r.state.Running || r.state.Enabled {
		t.Fatalf("control not restored: %+v", r.state)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal not removed: %v", err)
	}
}
