package bootstrap

import (
	"errors"
	"os"
	"syscall"
)

func trustedOwner(st os.FileInfo) error {
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || (s.Uid != 0 && int(s.Uid) != os.Geteuid()) {
		return errors.New("installation path has an untrusted owner")
	}
	return nil
}
