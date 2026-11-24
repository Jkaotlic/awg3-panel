package issuer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Jkaotlic/awg3-panel/internal/atomicfile"
	"github.com/Jkaotlic/awg3-panel/internal/filelock"
	"github.com/Jkaotlic/awg3-panel/internal/store"
)

const pendingSuffix = ".awg3panel.pending"

// peerTransaction is an undo record for an issuance or rotation. It is
// durable before the first write and removed only after all writes succeed.
type peerTransaction struct {
	KeyID    string
	OldKey   []byte
	OldState []byte
	Before   string
	After    string
}

func (s *Service) operationPath(suffix string) (string, error) {
	base := s.iface.Config
	if base == "" {
		base = s.iface.Storage.State
	}
	abs, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	return abs + suffix, nil
}

// ErrConcurrentWriter distinguishes lock contention from inconsistent data.
var ErrConcurrentWriter = errors.New("другой процесс уже меняет этот интерфейс")

func (s *Service) lockWriter() (*os.File, error) {
	if s.iface.Config != "" {
		info, err := os.Lstat(s.iface.Config)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: серверный конфиг для записи должен быть обычным файлом", ErrStateConflict)
		}
	}
	path, err := s.operationPath(lockSuffix)
	if err != nil {
		return nil, err
	}
	lock, err := filelock.Try(path)
	if errors.Is(err, filelock.ErrLocked) {
		return nil, fmt.Errorf("%w: %w", ErrStateConflict, ErrConcurrentWriter)
	}
	return lock, err
}

func (s *Service) beginWrite() (*os.File, error) {
	lock, err := s.lockWriter()
	if err != nil {
		return nil, err
	}
	if err := s.recoverPending(); err != nil {
		lock.Close()
		return nil, err
	}
	return lock, nil
}

const lockSuffix = ".awg3panel.lock"

type peerReadGuard struct {
	lock *os.File
	path string
}

func (s *Service) beginRead() (peerReadGuard, error) {
	path, err := s.operationPath(lockSuffix)
	if err != nil {
		return peerReadGuard{}, err
	}
	lock, err := filelock.Read(path)
	if errors.Is(err, filelock.ErrLocked) {
		return peerReadGuard{}, readConflict()
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return peerReadGuard{}, err
	}
	guard := peerReadGuard{lock: lock, path: path}
	if err := s.checkPending(); err != nil {
		guard.close()
		return peerReadGuard{}, err
	}
	return guard, nil
}

func readConflict() error {
	return fmt.Errorf("%w: %w", ErrStateConflict, ErrConcurrentWriter)
}

func (g peerReadGuard) close() {
	if g.lock != nil {
		g.lock.Close()
	}
}

func (g peerReadGuard) validate() error {
	if g.lock != nil {
		return nil
	}
	// Before the first writer there is no lock inode. Its appearance means
	// a writer could have overlapped this read. Later reads take the shared lock.
	_, err := os.Stat(g.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return readConflict()
}

func (s *Service) pendingPath() (string, error) { return s.operationPath(pendingSuffix) }

func (s *Service) checkPending() error {
	path, err := s.pendingPath()
	if err != nil {
		return err
	}
	_, err = os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return err
	default:
		return fmt.Errorf("%w: операция с пиром ожидает восстановления", ErrStateConflict)
	}
}

// Recover resumes interrupted operations before the full service starts.
// The no-journal path creates no files and does not call AWG.
func (s *Service) Recover() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.checkPending()
	if !errors.Is(err, ErrStateConflict) {
		return err
	}
	lock, err := s.beginWrite()
	if err != nil {
		return err
	}
	return lock.Close()
}

func readOptional(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

func restoreFile(path string, data []byte) error {
	if data != nil {
		return atomicfile.Write(path, data, 0o600)
	}
	return removeDurable(path)
}

func removeDurable(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return atomicfile.SyncDir(filepath.Dir(path))
}

// recoverPending runs only while holding the writer lock. It keeps the
// journal available until both disk and live state have been restored.
func (s *Service) recoverPending() error {
	path, err := s.pendingPath()
	if err != nil {
		return err
	}
	b, err := readOptional(path)
	if err != nil || b == nil {
		return err
	}
	var tx peerTransaction
	if err := json.Unmarshal(b, &tx); err != nil {
		return fmt.Errorf("журнал незавершённой операции повреждён")
	}
	if err := s.restoreTransaction(tx); err != nil {
		return fmt.Errorf("%w: восстановление незавершённой операции: %w", ErrRollbackFailed, err)
	}
	return removeDurable(path)
}

func (s *Service) restoreTransaction(tx peerTransaction) error {
	keyPath, err := s.keys.path(tx.KeyID)
	if err != nil {
		return err
	}
	if tx.Before != "" {
		if err := s.applier.recoverPeerMutation(tx.Before, tx.After); err != nil {
			return err
		}
	}
	return errors.Join(restoreFile(keyPath, tx.OldKey), restoreFile(s.iface.Storage.State, tx.OldState))
}

// commitPeer applies a peer change together with the matching private key
// and metadata. A nil mutation means only a disabled peer's stored state changes.
func (s *Service) commitPeer(st *store.State, id, privateKey string, mutate func(string) (string, error), exp Expect) error {
	return s.commitPeerChange(st, id, mutate, exp, func() error { return s.keys.Put(id, privateKey) }, nil)
}

// commitPeerChange brackets the device and metadata writes with a durable undo record.
func (s *Service) commitPeerChange(st *store.State, id string, mutate func(string) (string, error), exp Expect, beforeApply, afterSave func() error) error {
	path, err := s.pendingPath()
	if err != nil {
		return err
	}
	keyPath, err := s.keys.path(id)
	if err != nil {
		return err
	}
	tx := peerTransaction{KeyID: id}
	if tx.OldKey, err = readOptional(keyPath); err != nil {
		return err
	}
	if tx.OldState, err = readOptional(s.iface.Storage.State); err != nil {
		return err
	}
	var prepared bool
	prepare := func(before, after string) error {
		tx.Before, tx.After = before, after
		data, err := json.Marshal(tx)
		if err != nil {
			return err
		}
		prepared = true
		return atomicfile.Write(path, data, 0o600)
	}
	prepareKey := func(before, after string) error {
		if err := prepare(before, after); err != nil {
			return err
		}
		if beforeApply != nil {
			return beforeApply()
		}
		return nil
	}
	if mutate == nil {
		err = prepareKey("", "")
	} else {
		err = s.applier.apply(mutate, exp, prepareKey)
	}
	if err == nil {
		err = st.Save(s.iface.Storage.State)
	}
	if err == nil && afterSave != nil {
		err = afterSave()
	}
	if err == nil {
		// A durable removal is the commit point. If deletion already happened
		// and directory sync fails, recreating the journal precedes rollback.
		err = removeDurable(path)
		if err != nil {
			if prepareErr := prepare(tx.Before, tx.After); prepareErr != nil {
				return errors.Join(err, ErrRollbackFailed, prepareErr)
			}
		}
	}
	if err == nil || !prepared {
		return err
	}
	if restoreErr := s.recoverPending(); restoreErr != nil {
		return errors.Join(err, restoreErr)
	}
	return err
}
