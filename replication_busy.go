package sqliteseal

import (
	"context"
	"errors"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
)

const replicationBusyRetryWindow = 30 * time.Second

func isReplicationBusy(err error) bool {
	var sqliteErr sqlite3.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	return sqliteErr.Code == sqlite3.ErrBusy || sqliteErr.Code == sqlite3.ErrLocked
}

// retryReplicationBusy keeps transient SQLite writer contention local to the
// replication runtime. A busy database must not tear down an otherwise healthy
// replication session.
func retryReplicationBusy(ctx context.Context, operation func() error) error {
	started := time.Now()
	delay := 10 * time.Millisecond
	for {
		err := operation()
		if err == nil || !isReplicationBusy(err) {
			return err
		}
		if time.Since(started) >= replicationBusyRetryWindow {
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return context.Cause(ctx)
		case <-timer.C:
		}
		if delay < 500*time.Millisecond {
			delay *= 2
			if delay > 500*time.Millisecond {
				delay = 500 * time.Millisecond
			}
		}
	}
}
