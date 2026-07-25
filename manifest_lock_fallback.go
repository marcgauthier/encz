//go:build !unix && !windows

package encz

import "errors"

func lockManifestFile(string) (func() error, error) {
	return nil, errors.New("encz: interprocess manifest locking is unsupported on this platform")
}
