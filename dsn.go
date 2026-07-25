package encz

import (
	"fmt"
	"net/url"
	"path/filepath"
)

type Options struct {
	Key               string
	Cipher            Cipher
	URIParameters     map[string]string
	JournalMode       string
	BusyTimeoutMillis *int
	ManifestPath      string
	RotationPolicy    *RotationPolicy
}

// BuildDSN builds a non-secret SQLite DSN. Encryption keys are intentionally
// rejected because database/sql retains DSNs in ordinary process memory and
// applications commonly log them.
func BuildDSN(path string, opts Options) (string, error) {
	if opts.Key != "" || hasDirectKeyConfig(opts) || opts.URIParameters["encz_registry"] != "" {
		return "", ErrDirectKeyUnsupported
	}
	return buildDSN(path, opts), nil
}

// BuildEnczDSN is retained only to provide an explicit migration error.
// Deprecated: use OpenEncz or OpenWithOptions; direct-key DSNs are disabled.
func BuildEnczDSN(string, string) (string, error) {
	return "", ErrDirectKeyUnsupported
}

func buildDSN(path string, opts Options) string {
	values := make(url.Values)
	for key, value := range opts.URIParameters {
		switch key {
		case "crypto_key", "crypto_key_hex", "crypto_key_env":
			continue
		default:
			values.Set(key, value)
		}
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
