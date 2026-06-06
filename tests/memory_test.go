package tests

import (
	"errors"
	"testing"

	"github.com/marcgauthier/encz"
)

func TestInMemoryUnsupported(t *testing.T) {
	if _, err := encz.OpenEncz(":memory:", "MemSecret123"); !errors.Is(err, encz.ErrFileBackedRequired) {
		t.Fatalf("expected ErrFileBackedRequired, got %v", err)
	}
}

func TestSharedMemoryUnsupported(t *testing.T) {
	_, err := encz.OpenWithOptions("sharedmem", encz.Options{
		Key: "SharedMemSecret123",
		URIParameters: map[string]string{
			"mode":  "memory",
			"cache": "shared",
		},
	})
	if !errors.Is(err, encz.ErrFileBackedRequired) {
		t.Fatalf("expected ErrFileBackedRequired, got %v", err)
	}
}
