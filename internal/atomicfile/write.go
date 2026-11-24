// Package atomicfile persists a replacement before returning to the caller.
package atomicfile

import (
	"os"
	"path/filepath"
)

// Write replaces path atomically. A directory sync failure may be reported
// after the replacement has become visible.
func Write(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replace(tmp.Name(), path); err != nil {
		return err
	}
	return SyncDir(dir)
}
