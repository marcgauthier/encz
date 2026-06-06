package encz

import (
	"fmt"
	"net/url"
	"path/filepath"
)

type Options struct {
	Key               string
	URIParameters     map[string]string
	JournalMode       string
	BusyTimeoutMillis *int
	ManifestPath      string
	RotationPolicy    *RotationPolicy
}

func BuildDSN(path string, opts Options) string {
	values := make(url.Values)
	for key, value := range opts.URIParameters {
		values.Set(key, value)
	}
	if opts.Key != "" {
		values.Set("vfs", "encz")
		values.Set("crypto_key", opts.Key)
	}
	if opts.JournalMode != "" {
		values.Set("_journal_mode", opts.JournalMode)
	}
	if opts.BusyTimeoutMillis != nil {
		values.Set("_busy_timeout", fmt.Sprintf("%d", *opts.BusyTimeoutMillis))
	}

	uri := "file:" + filepath.ToSlash(path)
	if encoded := values.Encode(); encoded != "" {
		uri += "?" + encoded
	}
	return uri
}

func BuildEnczDSN(path, key string) string {
	return BuildDSN(path, Options{Key: key})
}
