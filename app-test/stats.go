package main

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

type counters struct {
	inserts        atomic.Uint64
	updates        atomic.Uint64
	selects        atomic.Uint64
	joins          atomic.Uint64
	retention      atomic.Uint64
	audits         atomic.Uint64
	reopens        atomic.Uint64
	backups        atomic.Uint64
	rekeys         atomic.Uint64
	errors         atomic.Uint64
	lastCacheHits  atomic.Uint64
	lastCacheMiss  atomic.Uint64
	lastAEAD       atomic.Uint64
	lastPhysical   atomic.Uint64
	lastOracleRows atomic.Int64
}

func (c *counters) operations() uint64 {
	return c.inserts.Load() + c.updates.Load() + c.selects.Load() + c.joins.Load()
}

func (c *counters) progress(start time.Time, dbPath string) string {
	elapsed := time.Since(start)
	ops := c.operations()
	rate := float64(ops) / max(elapsed.Seconds(), 0.001)
	hits, misses := c.lastCacheHits.Load(), c.lastCacheMiss.Load()
	cachePct := float64(0)
	if hits+misses > 0 {
		cachePct = float64(hits) * 100 / float64(hits+misses)
	}
	var size int64
	if info, err := os.Stat(dbPath); err == nil {
		size = info.Size()
	}
	return fmt.Sprintf(
		"elapsed=%s ops=%d (%.1f/s) ins=%d upd=%d sel=%d join=%d rows=%d trim=%d db=%.1fMB cache=%.1f%% AEAD=%d disk=%d audit=%d reopen=%d backup=%d rekey=%d errors=%d",
		elapsed.Round(time.Second), ops, rate,
		c.inserts.Load(), c.updates.Load(), c.selects.Load(), c.joins.Load(),
		c.lastOracleRows.Load(), c.retention.Load(), float64(size)/(1<<20),
		cachePct, c.lastAEAD.Load(), c.lastPhysical.Load(), c.audits.Load(),
		c.reopens.Load(), c.backups.Load(), c.rekeys.Load(), c.errors.Load(),
	)
}
