package memory

import (
	"errors"
	"testing"

	"github.com/marcgauthier/SQLiteSeal"
)

func TestInMemoryUnsupported(t *testing.T) {
	if _, err := sqliteseal.OpenSQLiteSeal(":memory:", "MemSecret123"); !errors.Is(err, sqliteseal.ErrFileBackedRequired) {
		t.Fatalf("expected ErrFileBackedRequired, got %v", err)
	}
}

func TestSharedMemoryUnsupported(t *testing.T) {
	_, err := sqliteseal.OpenWithOptions("sharedmem", sqliteseal.Options{
		Key: "SharedMemSecret123",
		URIParameters: map[string]string{
			"mode":  "memory",
			"cache": "shared",
		},
	})
	if !errors.Is(err, sqliteseal.ErrFileBackedRequired) {
		t.Fatalf("expected ErrFileBackedRequired, got %v", err)
	}
}
