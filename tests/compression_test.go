package tests

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marcgauthier/encz"
)

// helper to return int pointer
func intPtr(val int) *int {
	return &val
}

// TC-ZIP-001: TestCompressionCodecs validates size efficiency differences and readability across codecs.
func TestCompressionCodecs(t *testing.T) {
	tempDir := t.TempDir()
	nonePath := filepath.Join(tempDir, "none.db")
	zstdPath := filepath.Join(tempDir, "zstd.db")
	deflatePath := filepath.Join(tempDir, "deflate.db")

	configs := []struct {
		path        string
		compression string
	}{
		{path: nonePath, compression: "none"},
		{path: zstdPath, compression: "zstd"},
		{path: deflatePath, compression: "deflate"},
	}

	key := "CompressionSecret123"
	// Highly repetitive, compressible text
	sampleText := strings.Repeat("This is a highly compressible piece of text designed to test the compression algorithm. ", 20)

	for _, cfg := range configs {
		db, err := encz.OpenEncz(cfg.path, key, cfg.compression)
		if err != nil {
			t.Fatalf("failed to open (%s): %v", cfg.compression, err)
		}

		_, err = db.Exec(`CREATE TABLE comp_test (id INTEGER PRIMARY KEY, content TEXT)`)
		if err != nil {
			db.Close()
			t.Fatalf("failed to create table (%s): %v", cfg.compression, err)
		}

		// Insert 500 rows to ensure enough pages are allocated and compressed
		tx, err := db.Begin()
		if err != nil {
			db.Close()
			t.Fatalf("failed to begin tx (%s): %v", cfg.compression, err)
		}
		stmt, err := tx.Prepare(`INSERT INTO comp_test (content) VALUES (?)`)
		if err != nil {
			tx.Rollback()
			db.Close()
			t.Fatalf("failed to prepare stmt (%s): %v", cfg.compression, err)
		}
		for i := 0; i < 500; i++ {
			if _, err := stmt.Exec(sampleText); err != nil {
				stmt.Close()
				tx.Rollback()
				db.Close()
				t.Fatalf("failed to insert row %d (%s): %v", i, cfg.compression, err)
			}
		}
		stmt.Close()
		if err := tx.Commit(); err != nil {
			db.Close()
			t.Fatalf("failed to commit tx (%s): %v", cfg.compression, err)
		}

		// Run PRAGMA integrity_check before closing
		var integrity string
		err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
		if err != nil || integrity != "ok" {
			db.Close()
			t.Fatalf("integrity check failed for %s: %s, err=%v", cfg.compression, integrity, err)
		}

		db.Close()
	}

	// Read file sizes
	noneInfo, err := os.Stat(nonePath)
	if err != nil {
		t.Fatalf("stat none: %v", err)
	}
	zstdInfo, err := os.Stat(zstdPath)
	if err != nil {
		t.Fatalf("stat zstd: %v", err)
	}
	deflateInfo, err := os.Stat(deflatePath)
	if err != nil {
		t.Fatalf("stat deflate: %v", err)
	}

	t.Logf("Sizes - None: %d bytes, Zstd: %d bytes, Deflate: %d bytes", noneInfo.Size(), zstdInfo.Size(), deflateInfo.Size())

	// Both zstd and deflate should be significantly smaller than none
	if zstdInfo.Size() >= noneInfo.Size() {
		t.Errorf("Zstd DB size (%d) is not smaller than None DB size (%d)", zstdInfo.Size(), noneInfo.Size())
	}
	if deflateInfo.Size() >= noneInfo.Size() {
		t.Errorf("Deflate DB size (%d) is not smaller than None DB size (%d)", deflateInfo.Size(), noneInfo.Size())
	}

	// Verify we can reopen and read the text
	for _, cfg := range configs {
		db, err := encz.OpenEncz(cfg.path, key, cfg.compression)
		if err != nil {
			t.Fatalf("reopen failed (%s): %v", cfg.compression, err)
		}
		defer db.Close()

		var count int
		err = db.QueryRow(`SELECT count(*) FROM comp_test`).Scan(&count)
		if err != nil {
			t.Fatalf("count rows failed (%s): %v", cfg.compression, err)
		}
		if count != 500 {
			t.Errorf("expected 500 rows, got %d for %s", count, cfg.compression)
		}
	}
}

// TC-ZIP-002: TestCompressionLevels validates various compression levels including extreme values.
func TestCompressionLevels(t *testing.T) {
	key := "LevelSecret99"

	cases := []struct {
		name        string
		compression string
		level       *int
		expectFail  bool
	}{
		{name: "Deflate_Min", compression: "deflate", level: intPtr(1), expectFail: false},
		{name: "Deflate_Default", compression: "deflate", level: nil, expectFail: false},
		{name: "Deflate_Max", compression: "deflate", level: intPtr(9), expectFail: false},
		{name: "Deflate_ExtremeHigh", compression: "deflate", level: intPtr(999), expectFail: true},
		{name: "Deflate_ExtremeLow", compression: "deflate", level: intPtr(-999), expectFail: true},

		{name: "Zstd_Min", compression: "zstd", level: intPtr(-1), expectFail: false},
		{name: "Zstd_Default", compression: "zstd", level: nil, expectFail: false},
		{name: "Zstd_Max", compression: "zstd", level: intPtr(22), expectFail: false},
		{name: "Zstd_ExtremeHigh", compression: "zstd", level: intPtr(999), expectFail: false},
		{name: "Zstd_ExtremeLow", compression: "zstd", level: intPtr(-999), expectFail: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "level.db")
			opts := encz.Options{
				Key:              key,
				Compression:      tc.compression,
				CompressionLevel: tc.level,
			}

			db, err := encz.OpenWithOptions(dbPath, opts)
			if err == nil {
				_, err = db.Exec(`CREATE TABLE lvl (id INTEGER PRIMARY KEY, content TEXT)`)
			}

			if tc.expectFail {
				if err == nil {
					db.Close()
					t.Error("expected failure for invalid compression level, but operation succeeded")
				}
				return
			}

			if err != nil {
				if db != nil {
					db.Close()
				}
				t.Fatalf("failed: %v", err)
			}

			sampleText := strings.Repeat("Level testing content repetition. ", 30)
			_, err = db.Exec(`INSERT INTO lvl (content) VALUES (?)`, sampleText)
			if err != nil {
				db.Close()
				t.Fatalf("failed to insert: %v", err)
			}

			var got string
			err = db.QueryRow(`SELECT content FROM lvl WHERE id = 1`).Scan(&got)
			if err != nil {
				db.Close()
				t.Fatalf("failed to query: %v", err)
			}
			if got != sampleText {
				db.Close()
				t.Errorf("mismatch: expected %q, got %q", sampleText, got)
			}

			// Validate database integrity check passes
			var integrity string
			err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
			db.Close()
			if err != nil || integrity != "ok" {
				t.Errorf("integrity check failed: %s, err=%v", integrity, err)
			}
		})
	}
}

// TC-ZIP-003: TestIncompressibleData ensures random data is handled correctly without overflow.
func TestIncompressibleData(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "random.db")
	key := "RandomKey123"

	// Create a zstd compressed database
	db, err := encz.OpenEncz(dbPath, key, "zstd")
	if err != nil {
		t.Fatalf("failed to open: %v", err)
	}

	_, err = db.Exec(`CREATE TABLE random_payloads (id INTEGER PRIMARY KEY, data BLOB)`)
	if err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}

	// Generate incompressible (random) data
	randomPayloads := make([][]byte, 50)
	for i := range randomPayloads {
		buf := make([]byte, 8192) // 8KB per row (forces multi-page allocations)
		_, err := rand.Read(buf)
		if err != nil {
			db.Close()
			t.Fatalf("rand read: %v", err)
		}
		randomPayloads[i] = buf
	}

	// Insert into DB
	tx, err := db.Begin()
	if err != nil {
		db.Close()
		t.Fatalf("begin tx: %v", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO random_payloads (data) VALUES (?)`)
	if err != nil {
		tx.Rollback()
		db.Close()
		t.Fatalf("prepare: %v", err)
	}
	for _, payload := range randomPayloads {
		if _, err := stmt.Exec(payload); err != nil {
			stmt.Close()
			tx.Rollback()
			db.Close()
			t.Fatalf("insert payload: %v", err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		db.Close()
		t.Fatalf("commit: %v", err)
	}

	// Verify database integrity
	var integrity string
	err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
	if err != nil || integrity != "ok" {
		db.Close()
		t.Fatalf("integrity check failed: %s, err=%v", integrity, err)
	}
	db.Close()

	// Reopen and check values
	reopened, err := encz.OpenEncz(dbPath, key, "zstd")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	rows, err := reopened.Query(`SELECT data FROM random_payloads ORDER BY id`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	idx := 0
	for rows.Next() {
		var got []byte
		if err := rows.Scan(&got); err != nil {
			t.Fatalf("scan row %d: %v", idx, err)
		}
		if !bytesEqual(got, randomPayloads[idx]) {
			t.Errorf("random payload mismatch at index %d", idx)
		}
		idx++
	}
	if idx != 50 {
		t.Errorf("expected 50 rows, got %d", idx)
	}
}

// TC-ZIP-004: TestZeroBlockCompression writes massive columns containing repeated zeros
func TestZeroBlockCompression(t *testing.T) {
	tempDir := t.TempDir()
	nonePath := filepath.Join(tempDir, "none_zero.db")
	zstdPath := filepath.Join(tempDir, "zstd_zero.db")

	key := "ZeroKey123"
	// Generate 16KB of zero bytes (highly compressible)
	zeros := make([]byte, 16384)

	// Write to None DB
	dbNone, err := encz.OpenEncz(nonePath, key, "none")
	if err != nil {
		t.Fatalf("open none: %v", err)
	}
	_, err = dbNone.Exec(`CREATE TABLE zero_test (data BLOB)`)
	if err != nil {
		dbNone.Close()
		t.Fatalf("create none table: %v", err)
	}
	for i := 0; i < 100; i++ {
		_, err = dbNone.Exec(`INSERT INTO zero_test (data) VALUES (?)`, zeros)
		if err != nil {
			dbNone.Close()
			t.Fatalf("insert none row %d: %v", i, err)
		}
	}
	dbNone.Close()

	// Write to Zstd DB
	dbZstd, err := encz.OpenEncz(zstdPath, key, "zstd")
	if err != nil {
		t.Fatalf("open zstd: %v", err)
	}
	_, err = dbZstd.Exec(`CREATE TABLE zero_test (data BLOB)`)
	if err != nil {
		dbZstd.Close()
		t.Fatalf("create zstd table: %v", err)
	}
	for i := 0; i < 100; i++ {
		_, err = dbZstd.Exec(`INSERT INTO zero_test (data) VALUES (?)`, zeros)
		if err != nil {
			dbZstd.Close()
			t.Fatalf("insert zstd row %d: %v", i, err)
		}
	}
	dbZstd.Close()

	// Check file sizes
	noneInfo, err := os.Stat(nonePath)
	if err != nil {
		t.Fatalf("stat none: %v", err)
	}
	zstdInfo, err := os.Stat(zstdPath)
	if err != nil {
		t.Fatalf("stat zstd: %v", err)
	}

	t.Logf("Zero block DB sizes - None: %d bytes, Zstd: %d bytes", noneInfo.Size(), zstdInfo.Size())

	// Zstd DB should be significantly smaller (e.g. less than 45% of none DB size)
	ratio := float64(zstdInfo.Size()) / float64(noneInfo.Size())
	if ratio > 0.45 {
		t.Errorf("Compression ratio is not high enough: %f (None: %d, Zstd: %d)", ratio, noneInfo.Size(), zstdInfo.Size())
	}

	// Reopen and verify data in compressed DB
	reopened, err := encz.OpenEncz(zstdPath, key, "zstd")
	if err != nil {
		t.Fatalf("reopen zstd: %v", err)
	}
	defer reopened.Close()

	var count int
	err = reopened.QueryRow(`SELECT count(*) FROM zero_test`).Scan(&count)
	if err != nil {
		t.Fatalf("query count: %v", err)
	}
	if count != 100 {
		t.Errorf("expected 100 rows, got %d", count)
	}

	var got []byte
	err = reopened.QueryRow(`SELECT data FROM zero_test LIMIT 1`).Scan(&got)
	if err != nil {
		t.Fatalf("query blob: %v", err)
	}
	if !bytesEqual(got, zeros) {
		t.Error("zeros blob data corruption in compressed database")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
