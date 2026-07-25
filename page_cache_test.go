package sqliteseal

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestNormalizeDecryptedPageCacheBytes(t *testing.T) {
	tests := []struct {
		name    string
		input   int64
		want    int64
		wantErr error
	}{
		{"default", 0, DefaultDecryptedPageCacheBytes, nil},
		{"disabled", DisableDecryptedPageCache, 0, nil},
		{"custom", 4096, 4096, nil},
		{"invalid", -2, 0, ErrPageCacheSizeInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeDecryptedPageCacheBytes(tc.input)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("bytes = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestInvalidPageCacheSizeDoesNotCreateFiles(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "invalid-cache.db")
	_, err := OpenWithOptions(dbPath, Options{
		Key:                     "InvalidCacheSizePassword",
		DecryptedPageCacheBytes: -2,
	})
	if !errors.Is(err, ErrPageCacheSizeInvalid) {
		t.Fatalf("error = %v, want %v", err, ErrPageCacheSizeInvalid)
	}
	for _, path := range []string{dbPath, dbPath + ".encz"} {
		if exists, statErr := fileExists(path); statErr != nil {
			t.Fatal(statErr)
		} else if exists {
			t.Fatalf("invalid configuration created %s", path)
		}
	}
}

func TestDecryptedPageCacheLRUEvictsAndWipes(t *testing.T) {
	stats := &readStats{enabled: true}
	cache := newDecryptedPageCache(8, stats)
	key1 := pageCacheKey{pageNo: 1, pageSize: 8}
	key2 := pageCacheKey{pageNo: 2, offset: 8, pageSize: 8}
	cache.put(key1, []byte("secret-1"), []byte("token-1"))

	entry := cache.entries[key1].Value.(*pageCacheEntry)
	evictedPage := entry.page
	evictedToken := entry.token
	cache.put(key2, []byte("secret-2"), []byte("token-2"))

	if cache.entries[key1] != nil {
		t.Fatal("least-recently-used entry was not evicted")
	}
	if !bytes.Equal(evictedPage, make([]byte, len(evictedPage))) {
		t.Fatal("evicted plaintext was not wiped")
	}
	if !bytes.Equal(evictedToken, make([]byte, len(evictedToken))) {
		t.Fatal("evicted token was not wiped")
	}
	if stats.snapshot().CacheEvictions != 1 {
		t.Fatalf("evictions = %d, want 1", stats.snapshot().CacheEvictions)
	}
}

func TestDecryptedPageCacheRejectsChangedToken(t *testing.T) {
	stats := &readStats{enabled: true}
	cache := newDecryptedPageCache(4096, stats)
	key := pageCacheKey{pageNo: 2, offset: 4096, pageSize: 8}
	cache.put(key, []byte("contents"), []byte("old-token"))

	page := make([]byte, 8)
	token := make([]byte, 32)
	n, ok := cache.candidate(key, page, token)
	if !ok {
		t.Fatal("expected cache candidate")
	}
	if cache.confirm(key, token[:n], []byte("new-token")) {
		t.Fatal("changed disk token was accepted")
	}
	if cache.entries[key] != nil {
		t.Fatal("stale entry was not invalidated")
	}
}

func TestReadPerformanceStatsAndCacheHits(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "stats.db")
	db, err := OpenWithOptions(dbPath, Options{
		Key:                        "StatsCachePassword",
		JournalMode:                "WAL",
		DecryptedPageCacheBytes:    1 << 20,
		EnableReadPerformanceStats: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`PRAGMA cache_size=1; CREATE TABLE data(id INTEGER PRIMARY KEY, payload BLOB)`); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 3000)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO data(payload) VALUES(?)`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 96; i++ {
		if _, err := stmt.Exec(payload); err != nil {
			t.Fatal(err)
		}
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}

	db.ResetReadPerformanceStats()
	for i := 0; i < 2; i++ {
		var total int
		if err := db.QueryRow(`SELECT sum(length(payload)) FROM data`).Scan(&total); err != nil {
			t.Fatal(err)
		}
		if total != len(payload)*96 {
			t.Fatalf("total = %d", total)
		}
	}
	stats := db.ReadPerformanceStats()
	if !stats.Enabled {
		t.Fatal("statistics are not enabled")
	}
	if stats.PageRequests == 0 || stats.AEADOpenCalls == 0 {
		t.Fatalf("missing read metrics: %+v", stats)
	}
	if stats.CacheHits == 0 {
		t.Fatalf("expected validated cache hits: %+v", stats)
	}
	if stats.ScratchAllocations > 2 {
		t.Fatalf("scratch buffers allocated per page: %+v", stats)
	}
	db.ResetReadPerformanceStats()
	if got := db.ReadPerformanceStats(); got.PageRequests != 0 || !got.Enabled {
		t.Fatalf("reset stats = %+v", got)
	}
}

func TestCacheDoesNotReturnStalePageAcrossHandles(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "shared.db")
	opts := Options{
		Key:                     "CrossHandleCachePassword",
		JournalMode:             "WAL",
		DecryptedPageCacheBytes: 1 << 20,
	}
	writer, err := OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	writer.SetMaxOpenConns(1)
	if _, err := writer.Exec(`CREATE TABLE values_table(id INTEGER PRIMARY KEY, value TEXT); INSERT INTO values_table VALUES(1, 'before')`); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}

	reader, err := OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	reader.SetMaxOpenConns(1)
	if _, err := reader.Exec(`PRAGMA cache_size=1`); err != nil {
		t.Fatal(err)
	}
	var value string
	if err := reader.QueryRowContext(context.Background(), `SELECT value FROM values_table WHERE id=1`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "before" {
		t.Fatalf("initial value = %q", value)
	}
	if _, err := writer.Exec(`UPDATE values_table SET value='after' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	if err := reader.QueryRow(`SELECT value FROM values_table WHERE id=1`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "after" {
		t.Fatalf("cached stale value = %q, want after", value)
	}
}

func TestDisabledCacheAndStats(t *testing.T) {
	db, err := OpenWithOptions(filepath.Join(t.TempDir(), "disabled.db"), Options{
		Key:                     "DisabledCachePassword",
		DecryptedPageCacheBytes: DisableDecryptedPageCache,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reg, ok := getKeyRegistry(db.registryHandle)
	if !ok {
		t.Fatal("registry not found")
	}
	if reg.pageCache != nil {
		t.Fatal("page cache should be disabled")
	}
	if stats := db.ReadPerformanceStats(); stats.Enabled {
		t.Fatalf("stats unexpectedly enabled: %+v", stats)
	}
}
