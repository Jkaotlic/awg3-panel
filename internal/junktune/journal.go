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

var errTunnelChanged = errors.New("состояние тестового туннеля изменилось вне ожидаемого шага, нужна проверка оператора")

type journalPhase string

const (
	phasePrepared journalPhase = "prepared"
	phaseStarting journalPhase = "starting"
	phaseConflict journalPhase = "conflict"
)

type journal struct {
	Target   string         `json:"target_hash"`
	Original *issuer.Jitter `json:"original"`
	InFlight *issuer.Jitter `json:"in_flight"`
	Phase    journalPhase   `json:"phase"`
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
	if identity(current) != j.Target || (current.Jitter != *j.Original && current.Jitter != *j.InFlight) {
		return e.freeze(j)
	}
	if j.Phase == phaseConflict {
		if !current.stopped() || current.Jitter != *j.Original {
			return errTunnelChanged
		}
		return e.clear()
	}
	if err := validateJitter(*j.Original, current.MTU); err != nil {
		return err
	}
	if err := validateJitter(*j.InFlight, current.MTU); err != nil {
		return err
	}
	if !current.stopped() {
		// A prepared candidate owns only its jitter. It may own a running
		// interface only after the start intent has been durably recorded.
		if j.Phase != phaseStarting || current.Jitter != *j.InFlight {
			return e.freeze(j)
		}
		if err := routerError("остановка после пробы", e.router.Stop(ctx)); err != nil {
			return err
		}
		if err := e.expect(ctx, j.Target, current.Jitter, false); err != nil {
			if errors.Is(err, errTunnelChanged) {
				return e.freeze(j)
			}
			return err
		}
	}
	if current.Jitter != *j.Original {
		if err := routerError("возврат исходных параметров", e.router.SetJitter(ctx, *j.Original)); err != nil {
			return err
		}
	}
	if err := e.expect(ctx, j.Target, *j.Original, false); err != nil {
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
