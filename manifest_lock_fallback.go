//go:build !unix && !windows

package sqliteseal

import "errors"

func lockManifestFile(string) (func() error, error) {
	return nil, errors.New("sqliteseal: interprocess manifest locking is unsupported on this platform")
}
