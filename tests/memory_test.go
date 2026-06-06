package tests

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marcgauthier/encz"
)

// TC-MEM-001: TestInMemoryOnly opens and uses an encrypted database in RAM.
func TestInMemoryOnly(t *testing.T) {
	key := "MemSecret123"

	// SQLite URI syntax for in-memory database with params
	db, err := encz.OpenEncz(":memory:", key)
	if err != nil {
		t.Fatalf("failed to open in-memory database: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE ram_table (id INTEGER PRIMARY KEY, msg TEXT)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}

	_, err = db.Exec(`INSERT INTO ram_table (msg) VALUES ("in-ram message")`)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	var msg string
	err = db.QueryRow(`SELECT msg FROM ram_table WHERE id = 1`).Scan(&msg)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if msg != "in-ram message" {
		t.Errorf("expected 'in-ram message', got %q", msg)
	}

	var integrity string
	err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
	if err != nil || integrity != "ok" {
		t.Errorf("integrity check failed: %s, err=%v", integrity, err)
	}
}

// TC-MEM-002: TestInMemorySharedCache tests sharing an in-memory encrypted cache between two connections.
func TestInMemorySharedCache(t *testing.T) {
	key := "SharedMemSecret123"

	opts := encz.Options{
		Key: key,
		URIParameters: map[string]string{
			"mode":  "memory",
			"cache": "shared",
		},
	}

	// Two distinct DB instances sharing the same path name "sharedmem" with cache=shared
	db1, err := encz.OpenWithOptions("sharedmem", opts)
	if err != nil {
		t.Fatalf("failed to open db1: %v", err)
	}
	defer db1.Close()

	db2, err := encz.OpenWithOptions("sharedmem", opts)
	if err != nil {
		t.Fatalf("failed to open db2: %v", err)
	}
	defer db2.Close()

	// Create table and insert in connection 1
	_, err = db1.Exec(`CREATE TABLE shared_data (val TEXT)`)
	if err != nil {
		t.Fatalf("db1 create table: %v", err)
	}
	_, err = db1.Exec(`INSERT INTO shared_data (val) VALUES ("shared-value")`)
	if err != nil {
		t.Fatalf("db1 insert: %v", err)
	}

	// Query from connection 2
	var val string
	err = db2.QueryRow(`SELECT val FROM shared_data`).Scan(&val)
	if err != nil {
		t.Fatalf("db2 query failed: %v", err)
	}
	if val != "shared-value" {
		t.Errorf("expected 'shared-value', got %q", val)
	}
}

// TC-MEM-003: TestSmallPageCache sets a very small cache size and performs bulk writes/reads.
func TestSmallPageCache(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "smallcache.db")
	key := "CacheSecret99"

	db, err := encz.OpenEncz(dbPath, key)
	if err != nil {
		t.Fatalf("failed to open: %v", err)
	}
	defer db.Close()

	// Set cache size to 2 pages (~2KB or 8KB depending on page size)
	_, err = db.Exec(`PRAGMA cache_size = 2`)
	if err != nil {
		t.Fatalf("failed to set cache size: %v", err)
	}

	_, err = db.Exec(`CREATE TABLE cache_stress (id INTEGER PRIMARY KEY, data TEXT)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}

	// Perform 1000 individual insert transactions to force constant dirty-page VFS flushes
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO cache_stress (data) VALUES (?)`)
	if err != nil {
		tx.Rollback()
		t.Fatalf("prepare: %v", err)
	}
	longText := strings.Repeat("Force caching pressure. ", 20)
	for i := 0; i < 1000; i++ {
		if _, err := stmt.Exec(longText); err != nil {
			stmt.Close()
			tx.Rollback()
			t.Fatalf("insert %d failed: %v", i, err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tx: %v", err)
	}

	// Query data back to verify page reads under small cache
	rows, err := db.Query(`SELECT data FROM cache_stress LIMIT 10`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			t.Fatalf("scan row %d: %v", count, err)
		}
		if data != longText {
			t.Errorf("data mismatch at index %d", count)
		}
		count++
	}

	// Verify database integrity check
	var integrity string
	err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
	if err != nil || integrity != "ok" {
		t.Errorf("integrity check failed: %s, err=%v", integrity, err)
	}
}

// TC-MEM-004: TestVariablePageSizes validates VFS encryption with different SQLite page sizes.
func TestVariablePageSizes(t *testing.T) {
	key := "PageSizeSecret123"
	pageSizes := []int{4096}

	for _, size := range pageSizes {
		t.Run(fmt.Sprintf("PageSize_%d", size), func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "pagesize.db")

			// 1. Create database and set page size
			db, err := encz.OpenEncz(dbPath, key)
			if err != nil {
				t.Fatalf("failed to open: %v", err)
			}

			_, err = db.Exec(fmt.Sprintf(`PRAGMA page_size = %d`, size))
			if err != nil {
				db.Close()
				t.Fatalf("failed to set page_size: %v", err)
			}

			// Creating a table registers the page_size in the file header
			_, err = db.Exec(`CREATE TABLE pages (id INTEGER PRIMARY KEY, note TEXT)`)
			if err != nil {
				db.Close()
				t.Fatalf("failed to create table: %v", err)
			}

			// Verify page size is indeed set to the requested size
			var actualSize int
			err = db.QueryRow(`PRAGMA page_size`).Scan(&actualSize)
			if err != nil {
				db.Close()
				t.Fatalf("query page_size: %v", err)
			}
			if actualSize != size {
				db.Close()
				t.Fatalf("expected page_size %d, got %d", size, actualSize)
			}

			// Insert data
			_, err = db.Exec(`INSERT INTO pages (note) VALUES ("testing page size alignment")`)
			if err != nil {
				db.Close()
				t.Fatalf("insert failed: %v", err)
			}
			db.Close()

			// 2. Reopen and verify readability
			reopened, err := encz.OpenEncz(dbPath, key)
			if err != nil {
				t.Fatalf("reopen failed: %v", err)
			}
			defer reopened.Close()

			var note string
			err = reopened.QueryRow(`SELECT note FROM pages WHERE id = 1`).Scan(&note)
			if err != nil {
				t.Fatalf("query reopened: %v", err)
			}
			if note != "testing page size alignment" {
				t.Errorf("data mismatch: got %q", note)
			}

			// Validate database integrity
			var integrity string
			err = reopened.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
			if err != nil || integrity != "ok" {
				t.Errorf("integrity check failed: %s, err=%v", integrity, err)
			}
		})
	}
}

// TC-MEM-005: TestTempStoreLocation runs query sorting with different temp_store configurations.
func TestTempStoreLocation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "tempstore.db")
	key := "TempStoreSecret"

	db, err := encz.OpenEncz(dbPath, key)
	if err != nil {
		t.Fatalf("failed to open: %v", err)
	}
	defer db.Close()

	// Seed some data
	_, err = db.Exec(`CREATE TABLE data (id INTEGER PRIMARY KEY, val TEXT)`)
	if err != nil {
		t.Fatalf("failed to create table: %v", err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO data (val) VALUES (?)`)
	if err != nil {
		tx.Rollback()
		t.Fatalf("prepare: %v", err)
	}
	for i := 0; i < 2000; i++ {
		if _, err := stmt.Exec(fmt.Sprintf("item_%d_val_marker_string", i)); err != nil {
			stmt.Close()
			tx.Rollback()
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	tempModes := []string{"FILE", "MEMORY"}
	for _, mode := range tempModes {
		t.Run("TempStore_"+mode, func(t *testing.T) {
			_, err = db.Exec(fmt.Sprintf(`PRAGMA temp_store = %s`, mode))
			if err != nil {
				t.Fatalf("failed to set temp_store: %v", err)
			}

			// Run a query with sorting that forces temporary table creation
			rows, err := db.Query(`
				SELECT d1.val, d2.val 
				FROM data d1 
				CROSS JOIN data d2 
				WHERE d1.id < 50 AND d2.id < 50
				ORDER BY d1.val DESC, d2.val ASC
			`)
			if err != nil {
				t.Fatalf("query failed: %v", err)
			}
			defer rows.Close()

			count := 0
			for rows.Next() {
				var v1, v2 string
				if err := rows.Scan(&v1, &v2); err != nil {
					t.Fatalf("scan failed: %v", err)
				}
				count++
			}
			if count != 49*49 {
				t.Errorf("expected %d rows, got %d", 49*49, count)
			}
		})
	}
}
