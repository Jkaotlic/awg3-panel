package atomicfile

import (
	"syscall"
	"unsafe"
)

var moveFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

// FlushFileBuffers does not support directory handles. Windows replaces files
// with WRITE_THROUGH; deletion and other directory changes are best effort.
func SyncDir(string) error { return nil }

func replace(source, target string) error {
	src, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	dst, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	const replaceExistingWriteThrough = 0x1 | 0x8
	ok, _, err := moveFileEx.Call(uintptr(unsafe.Pointer(src)), uintptr(unsafe.Pointer(dst)), replaceExistingWriteThrough)
	if ok == 0 {
		return err
	}
	return nil
}
