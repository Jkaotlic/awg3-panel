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
	Jitter                issuer.Jitter
	MTU                   int
	Running               bool
	Enabled               bool
	Endpoint              string
	LocalAddress          string
	ServerPublicKey       string
	WireFingerprint       [32]byte
	LegacyWireFingerprint [32]byte
	Mimicry               [5]string
	Headers               [4]string
	Padding               [4]int
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

// ObfuscationRouter changes J and CPS together on the same stopped tunnel.
type ObfuscationRouter interface {
	Router
	SetObfuscation(context.Context, Parameters) error
}

type Attempt struct {
	Jitter    issuer.Jitter `json:"jitter"`
	Runs      int           `json:"runs"`
	Successes int           `json:"successes"`
	MedianMS  int64         `json:"median_ms"`
	CPS       [5]string     `json:"cps,omitzero"`
	Profile   string        `json:"profile,omitempty"`
	Domain    string        `json:"domain,omitempty"`
	AvgMS     int64         `json:"avg_ms"`
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
	return e.run(ctx, nil, progress)
}

// FindJunk checks the control and up to MaxAttempts generated combinations of
// J and CPS. A generated result reaching the threshold ends the search.
func (e *Engine) FindJunk(ctx context.Context, options Options, progress func(Result)) (Result, error) {
	options, err := NormalizeOptions(options)
	if err != nil {
		return Result{}, err
	}
	return e.run(ctx, &options, progress)
}

func (e *Engine) run(ctx context.Context, options *Options, progress func(Result)) (Result, error) {
	limit, timeout := candidateCount, runTimeout
	if options != nil {
		limit = options.MaxAttempts + 1 // control is outside the search budget
		timeout = time.Duration(limit)*(trialCount*trialTimeout+restoreTimeout) + restoreTimeout
	}
	result := Result{Attempts: make([]Attempt, 0, limit)}
	ctx, cancel := context.WithTimeout(ctx, timeout)
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
		return result, fmt.Errorf("%w: предыдущий сеанс: %w", ErrRestore, err)
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
	if options != nil {
		if _, ok := e.router.(ObfuscationRouter); !ok {
			return result, errors.New("роутер не поддерживает совместную настройку J и CPS")
		}
	}
	candidates, err := candidatesForRun(options, initial)
	if err != nil {
		return result, err
	}
	original := snapshotParameters(initial)
	ranking := make([]time.Duration, len(candidates))
	for i, candidate := range candidates {
		j := newJournal(initial, original, candidate.Parameters, options != nil)
		attempt := Attempt{Jitter: candidate.Jitter}
		if options != nil {
			attempt.CPS, attempt.Profile, attempt.Domain = candidate.CPS, candidate.Profile, candidate.Domain
		}
		result.Attempts = append(result.Attempts, attempt)
		var latencies []time.Duration
		if err := e.measure(ctx, j, func(m Measurement) {
			attempt.Runs++
			if m.Success {
				attempt.Successes++
				latencies = append(latencies, m.Latency)
				med, avg := median(latencies), average(latencies)
				attempt.MedianMS, attempt.AvgMS = med.Milliseconds(), avg.Milliseconds()
				ranking[i] = med
				if options != nil {
					ranking[i] = avg
				}
			}
			result.Attempts[i] = attempt
			if progress != nil {
				progress(Result{Attempts: slices.Clone(result.Attempts)})
			}
		}); err != nil {
			if options != nil && errors.Is(err, context.Canceled) && !errors.Is(err, ErrRestore) {
				result.Best = recommend(result.Attempts[:i], ranking, true)
				return result, context.Canceled
			}
			return result, err
		}
		if options != nil && i > 0 && attempt.Successes > 0 &&
			attempt.Successes*100 >= options.ThresholdPct*attempt.Runs {
			break
		}
	}
	if err := ctx.Err(); err != nil {
		if options != nil && errors.Is(err, context.Canceled) {
			result.Best = recommend(result.Attempts, ranking, true)
		}
		return result, err
	}
	result.Best = recommend(result.Attempts, ranking, options != nil)
	return result, nil
}

func recommend(attempts []Attempt, ranking []time.Duration, full bool) *int {
	best := -1
	for i, attempt := range attempts {
		if attempt.Successes > 0 && (best == -1 || better(attempts, ranking, i, best, full)) {
			best = i
		}
	}
	if best == -1 {
		return nil
	}
	return &best
}

func candidatesForRun(options *Options, initial Snapshot) ([]Candidate, error) {
	if options != nil {
		return generateFindJunkCandidates(*options, initial)
	}
	settings, err := generateCandidates(initial)
	if err != nil {
		return nil, err
	}
	out := make([]Candidate, 0, len(settings))
	for _, j := range settings {
		out = append(out, Candidate{Parameters: Parameters{Jitter: j, CPS: initial.Mimicry}})
	}
	return out, nil
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
	if err := e.expect(ctx, j, j.original(), false); err != nil {
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
			err = errors.Join(err, fmt.Errorf("%w: %w", ErrRestore, restoreErr))
		}
	}()
	if j.inFlight() != j.original() {
		if err := e.expect(ctx, j, j.original(), false); err != nil {
			return err
		}
		if err := routerError("установка параметров пробы", e.change(ctx, j, j.inFlight())); err != nil {
			return err
		}
	}
	for range trialCount {
		if err := e.expect(ctx, j, j.inFlight(), false); err != nil {
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
	if err := e.expect(trialCtx, j, j.inFlight(), true); err != nil {
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
	if err := e.expect(ctx, j, j.inFlight(), true); err != nil {
		return Measurement{}, err
	}
	if err := routerError("остановка тестового туннеля", e.router.Stop(ctx)); err != nil {
		return Measurement{}, err
	}
	return m, e.expect(ctx, j, j.inFlight(), false)
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

func (e *Engine) change(ctx context.Context, j journal, p Parameters) error {
	if j.Full {
		r, ok := e.router.(ObfuscationRouter)
		if !ok {
			return errors.New("роутер не поддерживает восстановление J и CPS")
		}
		return r.SetObfuscation(ctx, p)
	}
	return e.router.SetJitter(ctx, p.Jitter)
}

func (e *Engine) expect(ctx context.Context, j journal, p Parameters, running bool) error {
	s, err := e.snapshot(ctx)
	if err != nil {
		return err
	}
	if !j.matchesTarget(s) || j.fromSnapshot(s) != p {
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

func average(latencies []time.Duration) time.Duration {
	n := time.Duration(len(latencies))
	var quotient, remainder time.Duration
	for _, latency := range latencies {
		quotient += latency / n
		remainder += latency % n
	}
	return quotient + remainder/n
}

func better(attempts []Attempt, ranking []time.Duration, index, best int, full bool) bool {
	a, b := attempts[index], attempts[best]
	left, right := a.Successes, b.Successes
	if !full {
		left, right = left*b.Runs, right*a.Runs
	}
	if left != right {
		return left > right
	}
	if ranking[index] != ranking[best] {
		return ranking[index] < ranking[best]
	}
	if full {
		return false
	}
	if index == 0 || best == 0 {
		return index == 0
	}
	return int64(a.Jitter.Jc)*int64(a.Jitter.Jmax) < int64(b.Jitter.Jc)*int64(b.Jitter.Jmax)
}
