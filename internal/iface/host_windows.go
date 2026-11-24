package iface

import (
	"fmt"
	"os"
)

const readFlags = os.O_RDONLY

func trustedRootPath(string) error {
	return fmt.Errorf("root apply поддерживается только на Linux")
}

// Windows builds are used for planning and tests, not for privileged apply.
func lockQueue(*os.File) error { return nil }

func syncQueue(*os.File) error { return nil }
