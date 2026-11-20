package bootstrap

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

const AdminPath = "/root/awg3panel-admin.conf"
const AdminRecordPath = "/var/lib/awg3panel-bootstrap/admin.json"

func preparationComplete(root string) (bool, error) {
	if err := safePath(root, CompletePath); err != nil {
		return false, err
	}
	b, err := os.ReadFile(target(root, CompletePath))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := privateFile(root, CompletePath); err != nil {
		return false, err
	}
	if string(b) != "prepared-v1\n" {
		return false, errors.New("invalid preparation completion marker")
	}
	return true, nil
}

// Inspect the full private trees before any privileged consumer follows them.
// WalkDir does not follow symlinks; safePath additionally validates ancestors.
func auxiliaryPaths(root string) error {
	for _, p := range []string{"/var/lib/awg3panel/awgtop", "/var/lib/awg3panel-bootstrap", AdminPath} {
		if err := safePath(root, p); err != nil {
			return err
		}
		full := target(root, p)
		if _, err := os.Lstat(full); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		if err := filepath.WalkDir(full, func(name string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			s, err := os.Lstat(name)
			if err != nil {
				return err
			}
			if s.Mode()&os.ModeSymlink != 0 || (!s.IsDir() && !s.Mode().IsRegular()) {
				return errors.New("unsafe auxiliary state path")
			}
			if err := trustedOwner(s); err != nil {
				return err
			}
			if runtime.GOOS != "windows" && s.Mode().Perm()&0077 != 0 {
				return errors.New("auxiliary state must be private (0700 directories, 0600 files)")
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
