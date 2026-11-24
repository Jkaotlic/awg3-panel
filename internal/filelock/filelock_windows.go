package filelock

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

var lockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")

func tryExclusive(f *os.File) error {
	return tryLock(f, 3)
}

func tryShared(f *os.File) error { return tryLock(f, 1) }

func tryLock(f *os.File, flags uintptr) error {
	const lockViolation = syscall.Errno(33)
	var offset syscall.Overlapped
	ok, _, err := lockFileEx.Call(f.Fd(), flags, 0, 1, 0, uintptr(unsafe.Pointer(&offset)))
	if ok != 0 {
		return nil
	}
	if errors.Is(err, lockViolation) {
		return ErrLocked
	}
	return err
}
