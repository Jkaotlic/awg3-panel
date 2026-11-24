//go:build !windows

package atomicfile

import "os"

func replace(source, target string) error { return os.Rename(source, target) }

func SyncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
