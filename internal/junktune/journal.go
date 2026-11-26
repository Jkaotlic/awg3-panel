package junktune

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Jkaotlic/awg3-panel/internal/atomicfile"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
)

// ErrRestore marks a failed restoration, even if the initiating error was cancellation.
var ErrRestore = errors.New("не удалось восстановить тестовый туннель")

var errTunnelChanged = errors.New("состояние тестового туннеля изменилось вне ожидаемого шага, нужна проверка оператора")

type journalPhase string

const (
	phasePrepared journalPhase = "prepared"
	phaseStarting journalPhase = "starting"
	phaseConflict journalPhase = "conflict"
)

const currentJournalVersion = 2

type journal struct {
	Version     int            `json:"version,omitempty"`
	Target      string         `json:"target_hash"`
	Original    *issuer.Jitter `json:"original"`
	InFlight    *issuer.Jitter `json:"in_flight"`
	OriginalCPS *[5]string     `json:"original_cps,omitempty"`
	InFlightCPS *[5]string     `json:"in_flight_cps,omitempty"`
	Full        bool           `json:"full,omitempty"`
	Phase       journalPhase   `json:"phase"`
}

func newJournal(s Snapshot, before, after Parameters, full bool) journal {
	return journal{
		Version: currentJournalVersion, Target: identity(s),
		Original: &before.Jitter, InFlight: &after.Jitter,
		OriginalCPS: &before.CPS, InFlightCPS: &after.CPS,
		Full: full, Phase: phasePrepared,
	}
}

func snapshotParameters(s Snapshot) Parameters {
	return Parameters{Jitter: s.Jitter, CPS: s.Mimicry}
}

func (j journal) fromSnapshot(s Snapshot) Parameters {
	if j.Version == 0 {
		return Parameters{Jitter: s.Jitter}
	}
	return snapshotParameters(s)
}

func (j journal) original() Parameters {
	p := Parameters{Jitter: *j.Original}
	if j.OriginalCPS != nil {
		p.CPS = *j.OriginalCPS
	}
	return p
}

func (j journal) inFlight() Parameters {
	p := Parameters{Jitter: *j.InFlight}
	if j.InFlightCPS != nil {
		p.CPS = *j.InFlightCPS
	}
	return p
}

func (j journal) matchesTarget(s Snapshot) bool {
	if j.Version == 0 && s.LegacyWireFingerprint != ([32]byte{}) {
		s.WireFingerprint = s.LegacyWireFingerprint
	}
	return identity(s) == j.Target
}

func identity(s Snapshot) string {
	body, _ := json.Marshal([5]string{s.Endpoint, s.LocalAddress, s.ServerPublicKey, strconv.Itoa(s.MTU), hex.EncodeToString(s.WireFingerprint[:])})
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func (e *Engine) save(j journal) error {
	body, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if err := atomicfile.Write(e.journalPath, body, 0o600); err != nil {
		return fmt.Errorf("запись журнала автоподбора: %w", err)
	}
	return nil
}

func (e *Engine) recover(ctx context.Context) error {
	body, err := os.ReadFile(e.journalPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var j journal
	if err := json.Unmarshal(body, &j); err != nil {
		return errors.New("повреждён журнал автоподбора")
	}
	hash, err := hex.DecodeString(j.Target)
	if err != nil || len(hash) != sha256.Size || j.Original == nil || j.InFlight == nil {
		return errors.New("неполный журнал автоподбора")
	}
	switch j.Version {
	case 0:
		if j.OriginalCPS != nil || j.InFlightCPS != nil || j.Full {
			return errors.New("старый журнал содержит новые поля автоподбора")
		}
	case currentJournalVersion:
		if j.OriginalCPS == nil || j.InFlightCPS == nil || (!j.Full && *j.OriginalCPS != *j.InFlightCPS) {
			return errors.New("неполные или противоречивые данные CPS в журнале автоподбора")
		}
	default:
		return errors.New("неизвестная версия журнала автоподбора")
	}
	switch j.Phase {
	case phasePrepared, phaseStarting, phaseConflict:
	default:
		return errors.New("неизвестная фаза журнала автоподбора")
	}
	ctx, cancel := context.WithTimeout(ctx, restoreTimeout)
	defer cancel()
	return e.restore(ctx, j)
}

func (e *Engine) restore(ctx context.Context, j journal) error {
	current, err := e.snapshot(ctx)
	if err != nil {
		return err
	}
	original, inFlight := j.original(), j.inFlight()
	settings := j.fromSnapshot(current)
	if !j.matchesTarget(current) || (settings != original && settings != inFlight) {
		return e.freeze(j)
	}
	if j.Phase == phaseConflict {
		if !current.stopped() || settings != original {
			return errTunnelChanged
		}
		return e.clear()
	}
	if err := validateJitter(original.Jitter, current.MTU); err != nil {
		return err
	}
	if err := validateJitter(inFlight.Jitter, current.MTU); err != nil {
		return err
	}
	if j.Full && settings != original {
		if _, ok := e.router.(ObfuscationRouter); !ok {
			return errors.New("роутер не поддерживает восстановление J и CPS")
		}
	}
	if !current.stopped() {
		// A prepared candidate owns only the parameters. It may own a running
		// interface only after the start intent has been durably recorded.
		if j.Phase != phaseStarting || settings != inFlight {
			return e.freeze(j)
		}
		if err := routerError("остановка после пробы", e.router.Stop(ctx)); err != nil {
			return err
		}
		if err := e.expect(ctx, j, settings, false); err != nil {
			if errors.Is(err, errTunnelChanged) {
				return e.freeze(j)
			}
			return err
		}
	}
	if settings != original {
		if err := routerError("возврат исходных параметров", e.change(ctx, j, original)); err != nil {
			return err
		}
	}
	if err := e.expect(ctx, j, original, false); err != nil {
		if errors.Is(err, errTunnelChanged) {
			return e.freeze(j)
		}
		return err
	}
	return e.clear()
}

func (e *Engine) freeze(j journal) error {
	// A later matching snapshot cannot resolve an observed ownership conflict.
	if j.Phase == phaseConflict {
		return errTunnelChanged
	}
	j.Phase = phaseConflict
	return errors.Join(errTunnelChanged, e.save(j))
}

func (e *Engine) clear() error {
	if err := os.Remove(e.journalPath); err != nil {
		return fmt.Errorf("удаление журнала автоподбора: %w", err)
	}
	return atomicfile.SyncDir(filepath.Dir(e.journalPath))
}
