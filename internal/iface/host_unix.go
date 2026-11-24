//go:build !windows

package iface

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const readFlags = os.O_RDONLY | syscall.O_NONBLOCK

// Every component must be controlled by root before using it for a lock,
// a recovery record or a privileged command.
func trustedRootPath(name string) error {
	for {
		info, err := os.Lstat(name)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 ||
			(!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("небезопасный путь для root apply: %s", name)
		}
		parent := filepath.Dir(name)
		if name == parent {
			return nil
		}
		name = parent
	}
}

func lockQueue(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func syncQueue(f *os.File) error { return f.Sync() }
