//go:build windows

package encz

import (
	"os"

	"golang.org/x/sys/windows"
)

func lockManifestFile(path string) (func() error, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	err = windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0,
		1,
		0,
		&overlapped,
	)
	if err != nil {
		f.Close()
		return nil, err
	}
	return func() error {
		unlockErr := windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &overlapped)
		closeErr := f.Close()
		if unlockErr != nil {
			return unlockErr
		}
		return closeErr
	}, nil
}
