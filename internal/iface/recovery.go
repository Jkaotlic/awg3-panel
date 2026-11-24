package iface

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Jkaotlic/awg3-panel/internal/atomicfile"
	"github.com/Jkaotlic/awg3-panel/internal/filelock"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
)

type applyPhase string

const (
	phasePrepared   applyPhase = "prepared"
	phaseRestarting applyPhase = "restarting"
	phaseRollback   applyPhase = "rollback"
	phaseCommitted  applyPhase = "committed"
)

type applyJournal struct {
	Phase   applyPhase
	Queue   string
	Name    string
	Request string
	Backup  string
	Before  string
	After   string
	Device  string
	BinDir  string
}

func journalPath(configPath string) string { return configPath + ".iface-apply.json" }

func (j *applyJournal) save(configPath string) error {
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return atomicfile.Write(journalPath(configPath), data, 0o600)
}

func clearJournal(configPath string) error {
	if err := os.Remove(journalPath(configPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicfile.SyncDir(filepath.Dir(configPath))
}

// LockApply serializes privileged changes to a given config, regardless of
// which interface currently supplies the queue directory.
func LockApply(configPath string) (*os.File, error) {
	if err := trustedRootPath(configPath); err != nil {
		return nil, err
	}
	return filelock.Try(configPath + ".iface-apply.lock")
}

// ApplyQueued is used by the privileged CLI while holding LockApply.
func ApplyQueued(r Request, env Env, configPath, dir string) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tx := &applyJournal{Phase: phasePrepared, Queue: dir, Name: r.Name, Request: revision(data)}
	if r.Attach != nil {
		tx.Device = r.Attach.Device
		tx.BinDir = r.Attach.Block.BinDir
	}
	return apply(r, env, configPath, tx)
}

// RecoverApply rolls back or completes an interrupted change and consumes
// a committed request. The caller holds LockApply.
func RecoverApply(configPath string, host Host) (bool, error) {
	return recoverApply(configPath, host, func(binDir, device string) error {
		if err := trustedRootPath(filepath.Join(binDir, "awg")); err != nil {
			return err
		}
		_, err := runtime.NewExec(binDir).Show(device)
		return err
	})
}

func recoverApply(configPath string, host Host, show func(binDir, device string) error) (bool, error) {
	data, err := os.ReadFile(journalPath(configPath))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var j applyJournal
	if err := json.Unmarshal(data, &j); err != nil {
		return false, fmt.Errorf("повреждён журнал iface apply: %w", err)
	}
	switch j.Phase {
	case phasePrepared, phaseRestarting, phaseRollback, phaseCommitted:
	default:
		return false, fmt.Errorf("неизвестная фаза в журнале iface apply")
	}
	if j.Phase != phaseCommitted {
		if err := j.recoverConfig(configPath, host, show); err != nil {
			return false, err
		}
	}
	if j.Phase == phaseCommitted {
		if err := j.finishQueue(); err != nil {
			return false, err
		}
	}
	return true, clearJournal(configPath)
}

func (j *applyJournal) recoverConfig(configPath string, host Host, show func(binDir, device string) error) error {
	current, err := host.ReadFile(configPath)
	if err != nil {
		return err
	}
	switch revision(current) {
	case j.Before:
		// A previous recovery may have restored YAML before restarting.
	case j.After:
		if j.Phase == phaseRestarting {
			// The daemon may already have initialized attach state. Finish
			// the approved operation without replaying its initial checks.
			if err := j.finishRestart(configPath, host, show); err == nil {
				j.Phase = phaseCommitted
				return j.save(configPath)
			}
			// Recheck below before restoring any bytes. A manual edit while
			// the service was restarting must remain on disk.
			j.Phase = phaseRollback
			if err := j.save(configPath); err != nil {
				return err
			}
			return j.recoverConfig(configPath, host, show)
		}
		backup, err := host.ReadFile(j.Backup)
		if err != nil || revision(backup) != j.Before {
			return fmt.Errorf("не удалось проверить резервную копию %s", j.Backup)
		}
		if err := host.WriteFileAtomic(configPath, backup, 0o600); err != nil {
			return err
		}
	default:
		return fmt.Errorf("config.yaml изменён после прерывания iface apply, проверьте резервную копию %s", j.Backup)
	}
	if j.Phase != phasePrepared {
		return restartPanel(host)
	}
	return nil
}

func (j applyJournal) finishRestart(configPath string, host Host, show func(binDir, device string) error) error {
	if err := restartPanel(host); err != nil {
		return err
	}
	if j.Device != "" {
		if err := show(j.BinDir, j.Device); err != nil {
			return err
		}
	}
	current, err := host.ReadFile(configPath)
	if err != nil {
		return err
	}
	if revision(current) != j.After {
		return fmt.Errorf("config.yaml изменился во время восстановления")
	}
	return nil
}

func restartPanel(host Host) error {
	if err := host.Systemctl("restart", PanelUnit); err != nil {
		return err
	}
	return host.Systemctl("is-active", PanelUnit)
}

func (j applyJournal) finishQueue() error {
	if !validRequestName(j.Name) {
		return fmt.Errorf("недопустимое имя заявки в журнале iface apply")
	}
	root, err := openRequestDir(j.Queue)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	locked, err := lockRequestDir(root)
	if err != nil {
		return err
	}
	defer locked.Close()
	raw, err := readRegular(root, j.Name, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return syncQueue(locked)
	}
	if err != nil {
		return err
	}
	r, err := Parse(raw)
	if err != nil {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if revision(data) != j.Request {
		// The original is gone. Leave the replacement for fresh confirmation.
		return nil
	}
	r.Name = j.Name
	return consumeApproved(root, locked, r)
}

func makeAttachState(dir, id string, perm os.FileMode) error {
	root, err := openRealDir(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Mkdir(id, perm); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := root.Lstat(id)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("каталог состояния %q должен быть обычным каталогом", id)
	}
	return nil
}
