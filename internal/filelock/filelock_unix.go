//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package filelock

import (
	"errors"
	"os"
	"syscall"
)

func tryExclusive(f *os.File) error {
	return tryLock(f, syscall.LOCK_EX)
}

func tryShared(f *os.File) error { return tryLock(f, syscall.LOCK_SH) }

func tryLock(f *os.File, mode int) error {
	err := syscall.Flock(int(f.Fd()), mode|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return ErrLocked
	}
	return err
}
