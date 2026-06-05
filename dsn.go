package encz

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

type Options struct {
	Key               string
	Compression       string
	CompressionLevel  *int
	URIParameters     map[string]string
	JournalMode       string
	BusyTimeoutMillis *int
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
	if opts.Compression != "" {
		values.Set("crypto_compression", opts.Compression)
	}
	if opts.CompressionLevel != nil {
		values.Set("crypto_compression_level", fmt.Sprintf("%d", *opts.CompressionLevel))
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

func BuildEnczDSN(path, key, compression string) string {
	opts := Options{
		Key:         key,
		Compression: compression,
	}
	return BuildDSN(path, opts)
}

func normalizeCompression(compression string) string {
	if compression == "" {
		return "none"
	}
	return strings.ToLower(compression)
}
