package main

import (
	"context"
	"path/filepath"
	"testing"
)

func TestMaintenancePhases(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping encrypted maintenance phases in short mode")
	}
	dir := t.TempDir()
	logger, err := newLiveLogger(filepath.Join(dir, "maintenance.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	ctx, cancel := context.WithCancelCause(context.Background())
	r := newRunner(ctx, cancel, testConfig(dir), logger)
	if err := r.initialize(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.close() })

	phases := []struct {
		name string
		fn   func() error
	}{
		{"audit", r.audit},
		{"reopen", r.reopen},
		{"backup", r.backupRestore},
		{"rekey", r.rekey},
	}
	for _, phase := range phases {
		r.gate.Lock()
		err := phase.fn()
		r.gate.Unlock()
		if err != nil {
			t.Fatalf("%s: %v", phase.name, err)
		}
	}
	if r.stats.audits.Load() != 1 || r.stats.backups.Load() != 1 || r.stats.rekeys.Load() != 1 {
		t.Fatalf("maintenance counters: audit=%d backup=%d rekey=%d",
			r.stats.audits.Load(), r.stats.backups.Load(), r.stats.rekeys.Load())
	}
	if err := r.finalAudit(); err != nil {
		t.Fatal(err)
	}
}
