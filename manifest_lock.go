package encz

import (
	"os"
	"path/filepath"
	"sync"
)

var manifestProcessLocks sync.Map

func canonicalManifestLockPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(abs)
	if resolvedDir, resolveErr := filepath.EvalSymlinks(dir); resolveErr == nil {
		dir = resolvedDir
	}
	return filepath.Join(dir, filepath.Base(abs)) + ".lock", nil
}

func withManifestLock(path string, fn func() error) error {
	lockPath, err := canonicalManifestLockPath(path)
	if err != nil {
		return err
	}
	value, _ := manifestProcessLocks.LoadOrStore(lockPath, &sync.Mutex{})
	processLock := value.(*sync.Mutex)
	processLock.Lock()
	defer processLock.Unlock()
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return err
	}
	unlock, err := lockManifestFile(lockPath)
	if err != nil {
		return err
	}
	callbackErr := fn()
	unlockErr := unlock()
	if callbackErr != nil {
		return callbackErr
	}
	return unlockErr
}
