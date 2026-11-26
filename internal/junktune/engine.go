// Package junktune compares client junk parameters on an isolated test tunnel.
package junktune

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/filelock"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/store"
)

const (
	candidateCount = 4
	trialCount     = 3
	maxDraws       = 64
	runTimeout     = 6 * time.Minute
	trialTimeout   = 25 * time.Second
	restoreTimeout = 30 * time.Second
)

type Snapshot struct {
	Jitter          issuer.Jitter
	MTU             int
	Running         bool
	Enabled         bool
	Endpoint        string
	LocalAddress    string
	ServerPublicKey string
	WireFingerprint [32]byte
	Mimicry         [5]string
	Headers         [4]string
	Padding         [4]int
}

func (s Snapshot) stopped() bool { return !s.Running && !s.Enabled }

type Measurement struct {
	Success bool
	Latency time.Duration
}

// Router verifies the isolation and fixed routing of the test tunnel. Probe
// returns an unsuccessful measurement if the fresh tunnel cannot pass traffic.
type Router interface {
	Snapshot(context.Context) (Snapshot, error)
	SetJitter(context.Context, issuer.Jitter) error
	Start(context.Context) error
	Stop(context.Context) error
	Probe(context.Context) (Measurement, error)
}

type Attempt struct {
	Jitter    issuer.Jitter `json:"jitter"`
	Runs      int           `json:"runs"`
	Successes int           `json:"successes"`
	MedianMS  int64         `json:"median_ms"`
}

type Result struct {
	Attempts []Attempt `json:"attempts"`
	Best     *int      `json:"best"`
}

type Engine struct {
	router      Router
	journalPath string
}

func New(router Router, journalPath string) *Engine {
	return &Engine{router: router, journalPath: journalPath}
}

// Run holds a durable local lock through recovery, measurement and restoration.
// Progress receives a snapshot after each trial and before a recommendation is made.
func (e *Engine) Run(ctx context.Context, progress func(Result)) (Result, error) {
	result := Result{Attempts: make([]Attempt, 0, candidateCount)}
	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if e.router == nil || !filepath.IsAbs(e.journalPath) {
		return result, errors.New("автоподбор: требуется тестовый туннель и абсолютный путь журнала")
	}
	if err := os.MkdirAll(filepath.Dir(e.journalPath), 0o700); err != nil {
		return result, fmt.Errorf("автоподбор: каталог журнала: %w", err)
	}
	lock, err := filelock.Try(e.journalPath + ".lock")
	if err != nil {
		return result, err
	}
	defer lock.Close()

	if err := e.recover(ctx); err != nil {
		return result, fmt.Errorf("автоподбор: восстановление предыдущего сеанса: %w", err)
	}
	initial, err := e.snapshot(ctx)
	if err != nil {
		return result, err
	}
	if !initial.stopped() {
		return result, errors.New("тестовый туннель должен быть остановлен и отключён")
	}
	if err := validateJitter(initial.Jitter, initial.MTU); err != nil {
		return result, err
	}
	var medians [candidateCount]time.Duration
	candidates, err := generateCandidates(initial)
	if err != nil {
		return result, err
	}
	for index, candidate := range candidates {
		j := journal{
			Target: identity(initial), Original: &initial.Jitter, InFlight: &candidate, Phase: phasePrepared,
		}
		result.Attempts = append(result.Attempts, Attempt{Jitter: candidate})
		var latencies []time.Duration
		err := e.measure(ctx, j, func(m Measurement) {
			attempt := &result.Attempts[index]
			attempt.Runs++
			if m.Success {
				attempt.Successes++
				latencies = append(latencies, m.Latency)
				medians[index] = median(latencies)
				attempt.MedianMS = medians[index].Milliseconds()
			}
			if progress != nil {
				progress(Result{Attempts: slices.Clone(result.Attempts)})
			}
		})
		if err != nil {
			return result, err
		}
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	for i, attempt := range result.Attempts {
		if attempt.Successes > 0 && (result.Best == nil || better(result.Attempts, medians, i, *result.Best)) {
			best := i
			result.Best = &best
		}
	}
	return result, nil
}

func validateJitter(j issuer.Jitter, mtu int) error {
	mtuText := strconv.Itoa(mtu)
	if err := issuer.ValidateOverrides(&store.Overrides{
		Jc: &j.Jc, Jmin: &j.Jmin, Jmax: &j.Jmax, MTU: &mtuText,
	}); err != nil {
		return fmt.Errorf("недопустимые параметры тестового туннеля: %w", err)
	}
	if j != (issuer.Jitter{}) && (j.Jc == 0 || j.Jmin == 0 || j.Jmin >= j.Jmax || j.Jmax >= mtu) {
		return errors.New("требуется Jc > 0 и 0 < Jmin < Jmax < MTU либо нулевая тройка")
	}
	return nil
}

func generateCandidates(s Snapshot) ([]issuer.Jitter, error) {
	out := []issuer.Jitter{s.Jitter}
	for i := 0; i < maxDraws && len(out) < candidateCount; i++ {
		j, err := issuer.GenerateJitter(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("генерация параметров пробы: %w", err)
		}
		if validateJitter(j, s.MTU) == nil && !slices.Contains(out, j) {
			out = append(out, j)
		}
	}
	if len(out) != candidateCount {
		return nil, errors.New("не удалось подобрать четыре разные тройки в пределах MTU")
	}
	return out, nil
}

func (e *Engine) measure(ctx context.Context, j journal, recorded func(Measurement)) (err error) {
	if err := e.expect(ctx, j.Target, *j.Original, false); err != nil {
		return err
	}
	if err := e.save(j); err != nil {
		return err
	}
	defer func() {
		if errors.Is(err, errTunnelChanged) {
			err = e.freeze(j)
			return
		}
		restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), restoreTimeout)
		defer cancel()
		if restoreErr := e.restore(restoreCtx, j); restoreErr != nil {
			err = errors.Join(err, fmt.Errorf("восстановление тестового туннеля: %w", restoreErr))
		}
	}()
	if *j.InFlight != *j.Original {
		if err := e.expect(ctx, j.Target, *j.Original, false); err != nil {
			return err
		}
		if err := routerError("установка параметров пробы", e.router.SetJitter(ctx, *j.InFlight)); err != nil {
			return err
		}
	}
	for range trialCount {
		if err := e.expect(ctx, j.Target, *j.InFlight, false); err != nil {
			return err
		}
		j.Phase = phaseStarting
		if err := e.save(j); err != nil {
			j.Phase = phasePrepared
			return err
		}
		m, err := e.trial(ctx, j)
		if err != nil {
			return err
		}
		j.Phase = phasePrepared
		if err := e.save(j); err != nil {
			return err
		}
		recorded(m)
	}
	return nil
}

func (e *Engine) trial(ctx context.Context, j journal) (Measurement, error) {
	trialCtx, cancel := context.WithTimeout(ctx, trialTimeout)
	defer cancel()
	if err := routerError("запуск тестового туннеля", e.router.Start(trialCtx)); err != nil {
		return Measurement{}, err
	}
	if err := e.expect(trialCtx, j.Target, *j.InFlight, true); err != nil {
		return Measurement{}, err
	}
	m, err := e.router.Probe(trialCtx)
	if errors.Is(trialCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
		m, err = Measurement{}, nil
	}
	if err := routerError("замер тестового туннеля", err); err != nil {
		return Measurement{}, err
	}
	if m.Success && m.Latency < 0 {
		return Measurement{}, errors.New("замер вернул отрицательную задержку")
	}
	if err := e.expect(ctx, j.Target, *j.InFlight, true); err != nil {
		return Measurement{}, err
	}
	if err := routerError("остановка тестового туннеля", e.router.Stop(ctx)); err != nil {
		return Measurement{}, err
	}
	return m, e.expect(ctx, j.Target, *j.InFlight, false)
}

func (e *Engine) snapshot(ctx context.Context) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	s, err := e.router.Snapshot(ctx)
	if err != nil {
		return Snapshot{}, routerError("чтение тестового туннеля", err)
	}
	if s.Endpoint == "" || s.LocalAddress == "" || s.ServerPublicKey == "" {
		return Snapshot{}, errors.New("не удалось подтвердить идентичность тестового туннеля")
	}
	return s, nil
}

func (e *Engine) expect(ctx context.Context, target string, j issuer.Jitter, running bool) error {
	s, err := e.snapshot(ctx)
	if err != nil {
		return err
	}
	if identity(s) != target || s.Jitter != j {
		return errTunnelChanged
	}
	if s.Running != running || s.Enabled != running {
		return errors.New("не подтверждено состояние запуска тестового туннеля")
	}
	return nil
}

// Avoid copying router diagnostics into progress and public API results.
func routerError(action string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%s: %w", action, context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%s: %w", action, context.DeadlineExceeded)
	default:
		return fmt.Errorf("%s: ошибка роутера", action)
	}
}

func median(latencies []time.Duration) time.Duration {
	slices.Sort(latencies)
	middle := len(latencies) / 2
	if len(latencies)%2 == 1 {
		return latencies[middle]
	}
	return latencies[middle-1] + (latencies[middle]-latencies[middle-1])/2
}

func better(attempts []Attempt, medians [candidateCount]time.Duration, index, best int) bool {
	a, b := attempts[index], attempts[best]
	left, right := a.Successes*b.Runs, b.Successes*a.Runs
	if left != right {
		return left > right
	}
	if medians[index] != medians[best] {
		return medians[index] < medians[best]
	}
	if index == 0 || best == 0 {
		return index == 0
	}
	return int64(a.Jitter.Jc)*int64(a.Jitter.Jmax) < int64(b.Jitter.Jc)*int64(b.Jitter.Jmax)
}
