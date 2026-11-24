package filelock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestTryExcludesIndependentHolders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.lock")
	first, err := Try(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := Try(path); !errors.Is(err, ErrLocked) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("second holder acquired lock: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := Try(path)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestSharedReaderExcludesWriterWithoutCreatingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.lock")
	if f, err := Read(path); !os.IsNotExist(err) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("initial read: %v", err)
	}
	writer, err := Try(path)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := Read(path); !errors.Is(err, ErrLocked) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("reader during write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if f, err := Try(path); !errors.Is(err, ErrLocked) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("writer during read: %v", err)
	}
}
