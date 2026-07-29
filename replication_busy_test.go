package sqliteseal

import (
	"context"
	"errors"
	"testing"

	sqlite3 "github.com/mattn/go-sqlite3"
)

func TestRetryReplicationBusyEventuallySucceeds(t *testing.T) {
	attempts := 0
	err := retryReplicationBusy(context.Background(), func() error {
		attempts++
		if attempts < 3 {
			return sqlite3.Error{Code: sqlite3.ErrBusy}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("attempts=%d want 3", attempts)
	}
}

func TestRetryReplicationBusyDoesNotRetryPermanentError(t *testing.T) {
	permanent := errors.New("permanent")
	attempts := 0
	err := retryReplicationBusy(context.Background(), func() error {
		attempts++
		return permanent
	})
	if !errors.Is(err, permanent) {
		t.Fatalf("error=%v want %v", err, permanent)
	}
	if attempts != 1 {
		t.Fatalf("attempts=%d want 1", attempts)
	}
}

func TestRetryReplicationBusyHonorsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	attempts := 0
	err := retryReplicationBusy(ctx, func() error {
		attempts++
		return sqlite3.Error{Code: sqlite3.ErrLocked}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v want context canceled", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts=%d want 1", attempts)
	}
}
