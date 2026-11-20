//go:build !linux

package bootstrap

import "os"

// Production installation is Linux-only; other platforms run parser/unit tests.
func trustedOwner(os.FileInfo) error { return nil }
