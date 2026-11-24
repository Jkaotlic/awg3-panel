// Package filelock coordinates writers sharing a local filesystem.
package filelock

import (
	"errors"
	"fmt"
	"os"
)

var ErrLocked = errors.New("другой процесс уже меняет состояние")

// Try opens a stable lock file and acquires an exclusive lock until Close.
// Never remove the lock file: another process could then lock a different inode.
func Try(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := tryExclusive(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("блокировка %s: %w", path, err)
	}
	return f, nil
}

// Read opens an existing lock for sharing without creating any filesystem state.
func Read(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if err := tryShared(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
