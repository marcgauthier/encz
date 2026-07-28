package sqliteseal

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/awnumar/memguard"
	_ "github.com/mattn/go-sqlite3"
)

// ── Helpers ────────────────────────────────────────────────────────────────

// createPlainDB creates a plain SQLite database with seed data and returns its path.
func createPlainDB(t *testing.T, name string) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), name)
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open plain db: %v", err)
	}
	defer db.Close()
	seedDatabase(t, db)
	return dbPath
}

// createEncryptedDB creates a SqliteSeal database with seed data and returns its path.
func createEncryptedDB(t *testing.T, name, key string, cipher Cipher) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), name)
	db, err := OpenWithOptions(dbPath, Options{
		Key:         key,
		Cipher:      cipher,
		JournalMode: "WAL",
	})
	if err != nil {
		t.Fatalf("open encrypted db: %v", err)
	}
	defer db.Close()
	seedDatabase(t, db.DB)
	return dbPath
}

// seedDatabase populates a database with test tables and data.
func seedDatabase(t *testing.T, db *sql.DB) {
	t.Helper()
	stmts := []string{
		`CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL, price REAL, data BLOB, created_at TIMESTAMP)`,
		`CREATE TABLE tags (id INTEGER PRIMARY KEY, item_id INTEGER, tag TEXT, FOREIGN KEY(item_id) REFERENCES items(id))`,
		`CREATE INDEX idx_tags_item ON tags(item_id)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}

	ts := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	blob := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	rows := []struct {
		name  string
		price float64
		data  []byte
		ts    time.Time
	}{
		{"alpha", 9.99, blob, ts},
		{"beta", 19.50, nil, ts.Add(time.Hour)},
		{"gamma", 0.0, []byte{}, ts.Add(2 * time.Hour)},
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO items(name, price, data, created_at) VALUES(?, ?, ?, ?)`,
			r.name, r.price, r.data, r.ts); err != nil {
			t.Fatalf("insert item %q: %v", r.name, err)
		}
	}
	tagRows := []struct {
		itemID int
		tag    string
	}{
		{1, "first"},
		{1, "important"},
		{2, "second"},
	}
	for _, r := range tagRows {
		if _, err := db.Exec(`INSERT INTO tags(item_id, tag) VALUES(?, ?)`, r.itemID, r.tag); err != nil {
			t.Fatalf("insert tag: %v", err)
		}
	}
}

// verifyConvertedDB opens the converted database and checks all data.
func verifyConvertedDB(t *testing.T, dbPath, key string, cipher Cipher) {
	t.Helper()
	db, err := OpenWithOptions(dbPath, Options{
		Key:         key,
		Cipher:      cipher,
		JournalMode: "WAL",
	})
	if err != nil {
		t.Fatalf("open converted db: %v", err)
	}
	defer db.Close()
	verifyDatabaseContent(t, db.DB)
}

// verifyPlainDB opens a plain SQLite database and checks all data.
func verifyPlainDB(t *testing.T, dbPath string) {
	t.Helper()
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open plain db: %v", err)
	}
	defer db.Close()
	verifyDatabaseContent(t, db)
}

// verifyDatabaseContent checks the seeded data is intact.
func verifyDatabaseContent(t *testing.T, db *sql.DB) {
	t.Helper()

	// Integrity check.
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		t.Fatalf("integrity_check: %v", err)
	}
	if integrity != "ok" {
		t.Fatalf("integrity_check: %q", integrity)
	}

	// Item count.
	var itemCount int
	if err := db.QueryRow(`SELECT count(*) FROM items`).Scan(&itemCount); err != nil {
		t.Fatalf("count items: %v", err)
	}
	if itemCount != 3 {
		t.Fatalf("expected 3 items, got %d", itemCount)
	}

	// Tag count.
	var tagCount int
	if err := db.QueryRow(`SELECT count(*) FROM tags`).Scan(&tagCount); err != nil {
		t.Fatalf("count tags: %v", err)
	}
	if tagCount != 3 {
		t.Fatalf("expected 3 tags, got %d", tagCount)
	}

	// Verify first row values.
	var name string
	var price float64
	var data []byte
	if err := db.QueryRow(`SELECT name, price, data FROM items WHERE id = 1`).Scan(&name, &price, &data); err != nil {
		t.Fatalf("select item 1: %v", err)
	}
	if name != "alpha" {
		t.Fatalf("expected name 'alpha', got %q", name)
	}
	if price != 9.99 {
		t.Fatalf("expected price 9.99, got %f", price)
	}
	expected := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	if !bytesEqual(data, expected) {
		t.Fatalf("blob mismatch: got %v", data)
	}

	// Verify NULL data for row 2.
	var nullData sql.NullString
	if err := db.QueryRow(`SELECT data FROM items WHERE id = 2`).Scan(&nullData); err != nil {
		t.Fatalf("select item 2 data: %v", err)
	}
	if nullData.Valid {
		t.Fatal("expected NULL data for item 2")
	}

	// Verify index is used (tags index).
	var tagResult string
	if err := db.QueryRow(`SELECT tag FROM tags WHERE item_id = 1 ORDER BY tag LIMIT 1`).Scan(&tagResult); err != nil {
		t.Fatalf("select tag: %v", err)
	}
	if tagResult != "first" {
		t.Fatalf("expected tag 'first', got %q", tagResult)
	}
}

// ── Plain → Encrypted ─────────────────────────────────────────────────────

func TestConvertPlainToAES(t *testing.T) {
	srcPath := createPlainDB(t, "plain.db")
	dstPath := filepath.Join(t.TempDir(), "aes.db")
	key := "ConvertTestKey123"

	if err := ConvertDB(srcPath, dstPath, ConvertOptions{
		TargetKey:    key,
		TargetCipher: CipherAES256GCM,
	}); err != nil {
		t.Fatalf("ConvertDB: %v", err)
	}
	verifyConvertedDB(t, dstPath, key, CipherAES256GCM)
}

func TestConvertPlainToChaCha(t *testing.T) {
	srcPath := createPlainDB(t, "plain.db")
	dstPath := filepath.Join(t.TempDir(), "chacha.db")
	key := "ConvertTestKey123"

	if err := ConvertDB(srcPath, dstPath, ConvertOptions{
		TargetKey:    key,
		TargetCipher: CipherChaCha20Poly1305,
	}); err != nil {
		t.Fatalf("ConvertDB: %v", err)
	}
	verifyConvertedDB(t, dstPath, key, CipherChaCha20Poly1305)
}

func TestConvertPlainToXChaCha(t *testing.T) {
	srcPath := createPlainDB(t, "plain.db")
	dstPath := filepath.Join(t.TempDir(), "xchacha.db")
	key := "ConvertTestKey123"

	if err := ConvertDB(srcPath, dstPath, ConvertOptions{
		TargetKey:    key,
		TargetCipher: CipherXChaCha20Poly1305,
	}); err != nil {
		t.Fatalf("ConvertDB: %v", err)
	}
	verifyConvertedDB(t, dstPath, key, CipherXChaCha20Poly1305)
}

// ── Cipher Switch ──────────────────────────────────────────────────────────

func TestConvertAESToChaCha(t *testing.T) {
	key := "CipherSwitchKey123"
	srcPath := createEncryptedDB(t, "aes.db", key, CipherAES256GCM)
	dstPath := filepath.Join(t.TempDir(), "chacha.db")

	if err := ConvertDB(srcPath, dstPath, ConvertOptions{
		SourceKey:    key,
		TargetCipher: CipherChaCha20Poly1305,
	}); err != nil {
		t.Fatalf("ConvertDB: %v", err)
	}
	verifyConvertedDB(t, dstPath, key, CipherChaCha20Poly1305)
}

func TestConvertAESToXChaCha(t *testing.T) {
	key := "CipherSwitchKey123"
	srcPath := createEncryptedDB(t, "aes.db", key, CipherAES256GCM)
	dstPath := filepath.Join(t.TempDir(), "xchacha.db")

	if err := ConvertDB(srcPath, dstPath, ConvertOptions{
		SourceKey:    key,
		TargetCipher: CipherXChaCha20Poly1305,
	}); err != nil {
		t.Fatalf("ConvertDB: %v", err)
	}
	verifyConvertedDB(t, dstPath, key, CipherXChaCha20Poly1305)
}

func TestConvertChaChaToAES(t *testing.T) {
	key := "CipherSwitchKey123"
	srcPath := createEncryptedDB(t, "chacha.db", key, CipherChaCha20Poly1305)
	dstPath := filepath.Join(t.TempDir(), "aes.db")

	if err := ConvertDB(srcPath, dstPath, ConvertOptions{
		SourceKey:    key,
		TargetCipher: CipherAES256GCM,
	}); err != nil {
		t.Fatalf("ConvertDB: %v", err)
	}
	verifyConvertedDB(t, dstPath, key, CipherAES256GCM)
}

func TestConvertChaChaToXChaCha(t *testing.T) {
	key := "CipherSwitchKey123"
	srcPath := createEncryptedDB(t, "chacha.db", key, CipherChaCha20Poly1305)
	dstPath := filepath.Join(t.TempDir(), "xchacha.db")

	if err := ConvertDB(srcPath, dstPath, ConvertOptions{
		SourceKey:    key,
		TargetCipher: CipherXChaCha20Poly1305,
	}); err != nil {
		t.Fatalf("ConvertDB: %v", err)
	}
	verifyConvertedDB(t, dstPath, key, CipherXChaCha20Poly1305)
}

func TestConvertXChaChaToAES(t *testing.T) {
	key := "CipherSwitchKey123"
	srcPath := createEncryptedDB(t, "xchacha.db", key, CipherXChaCha20Poly1305)
	dstPath := filepath.Join(t.TempDir(), "aes.db")

	if err := ConvertDB(srcPath, dstPath, ConvertOptions{
		SourceKey:    key,
		TargetCipher: CipherAES256GCM,
	}); err != nil {
		t.Fatalf("ConvertDB: %v", err)
	}
	verifyConvertedDB(t, dstPath, key, CipherAES256GCM)
}

func TestConvertXChaChaToChaCha(t *testing.T) {
	key := "CipherSwitchKey123"
	srcPath := createEncryptedDB(t, "xchacha.db", key, CipherXChaCha20Poly1305)
	dstPath := filepath.Join(t.TempDir(), "chacha.db")

	if err := ConvertDB(srcPath, dstPath, ConvertOptions{
		SourceKey:    key,
		TargetCipher: CipherChaCha20Poly1305,
	}); err != nil {
		t.Fatalf("ConvertDB: %v", err)
	}
	verifyConvertedDB(t, dstPath, key, CipherChaCha20Poly1305)
}

// ── Same Cipher Re-encrypt ─────────────────────────────────────────────────

func TestConvertSameCipher(t *testing.T) {
	key := "SameCipherKey123"
	srcPath := createEncryptedDB(t, "aes.db", key, CipherAES256GCM)
	dstPath := filepath.Join(t.TempDir(), "aes-reencrypt.db")

	if err := ConvertDB(srcPath, dstPath, ConvertOptions{
		SourceKey:    key,
		TargetCipher: CipherAES256GCM,
	}); err != nil {
		t.Fatalf("ConvertDB: %v", err)
	}
	verifyConvertedDB(t, dstPath, key, CipherAES256GCM)
}

// ── Key Change ─────────────────────────────────────────────────────────────

func TestConvertWithKeyChange(t *testing.T) {
	oldKey := "OldKey123"
	newKey := "NewKey456"
	srcPath := createEncryptedDB(t, "old.db", oldKey, CipherAES256GCM)
	dstPath := filepath.Join(t.TempDir(), "new.db")

	if err := ConvertDB(srcPath, dstPath, ConvertOptions{
		SourceKey:    oldKey,
		TargetKey:    newKey,
		TargetCipher: CipherChaCha20Poly1305,
	}); err != nil {
		t.Fatalf("ConvertDB: %v", err)
	}
	verifyConvertedDB(t, dstPath, newKey, CipherChaCha20Poly1305)

	// Old key should not work on the new database.
	_, err := OpenWithOptions(dstPath, Options{Key: oldKey})
	if err == nil {
		t.Fatal("expected old key to fail on converted database")
	}
}

// ── Decrypt to Plain ───────────────────────────────────────────────────────

func TestConvertToPlainFromAES(t *testing.T) {
	key := "DecryptKey123"
	srcPath := createEncryptedDB(t, "aes.db", key, CipherAES256GCM)
	dstPath := filepath.Join(t.TempDir(), "plain.db")

	if err := ConvertDB(srcPath, dstPath, ConvertOptions{
		SourceKey: key,
	}); err != nil {
		t.Fatalf("ConvertDB: %v", err)
	}
	verifyPlainDB(t, dstPath)

	// No manifest should exist for the plain output.
	if _, err := os.Stat(dstPath + ".encz"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no manifest for plain output, stat err=%v", err)
	}
}

func TestConvertToPlainFromChaCha(t *testing.T) {
	key := "DecryptKey123"
	srcPath := createEncryptedDB(t, "chacha.db", key, CipherChaCha20Poly1305)
	dstPath := filepath.Join(t.TempDir(), "plain.db")

	if err := ConvertDB(srcPath, dstPath, ConvertOptions{
		SourceKey: key,
	}); err != nil {
		t.Fatalf("ConvertDB: %v", err)
	}
	verifyPlainDB(t, dstPath)
}

func TestConvertToPlainFromXChaCha(t *testing.T) {
	key := "DecryptKey123"
	srcPath := createEncryptedDB(t, "xchacha.db", key, CipherXChaCha20Poly1305)
	dstPath := filepath.Join(t.TempDir(), "plain.db")

	if err := ConvertDB(srcPath, dstPath, ConvertOptions{
		SourceKey: key,
	}); err != nil {
		t.Fatalf("ConvertDB: %v", err)
	}
	verifyPlainDB(t, dstPath)
}

// ── Data Fidelity ──────────────────────────────────────────────────────────

func TestConvertPreservesData(t *testing.T) {
	srcPath := createPlainDB(t, "types.db")
	dstPath := filepath.Join(t.TempDir(), "types-enc.db")
	key := "TypesKey123"

	if err := ConvertDB(srcPath, dstPath, ConvertOptions{
		TargetKey:    key,
		TargetCipher: CipherAES256GCM,
	}); err != nil {
		t.Fatalf("ConvertDB: %v", err)
	}

	// Full verification of all column types.
	db, err := OpenWithOptions(dstPath, Options{Key: key, Cipher: CipherAES256GCM})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Verify TEXT.
	var name string
	if err := db.QueryRow(`SELECT name FROM items WHERE id = 1`).Scan(&name); err != nil {
		t.Fatalf("text: %v", err)
	}
	if name != "alpha" {
		t.Fatalf("text mismatch: %q", name)
	}

	// Verify REAL.
	var price float64
	if err := db.QueryRow(`SELECT price FROM items WHERE id = 1`).Scan(&price); err != nil {
		t.Fatalf("real: %v", err)
	}
	if price != 9.99 {
		t.Fatalf("real mismatch: %f", price)
	}

	// Verify BLOB.
	var blob []byte
	if err := db.QueryRow(`SELECT data FROM items WHERE id = 1`).Scan(&blob); err != nil {
		t.Fatalf("blob: %v", err)
	}
	if !bytesEqual(blob, []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}) {
		t.Fatalf("blob mismatch: %v", blob)
	}

	// Verify NULL.
	var nullData sql.NullString
	if err := db.QueryRow(`SELECT data FROM items WHERE id = 2`).Scan(&nullData); err != nil {
		t.Fatalf("null: %v", err)
	}
	if nullData.Valid {
		t.Fatal("expected NULL")
	}

	// Verify TIMESTAMP.
	var ts time.Time
	if err := db.QueryRow(`SELECT created_at FROM items WHERE id = 1`).Scan(&ts); err != nil {
		t.Fatalf("timestamp: %v", err)
	}
	expected := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	if !ts.Equal(expected) {
		t.Fatalf("timestamp mismatch: %v", ts)
	}
}

func TestConvertMultiTable(t *testing.T) {
	srcPath := filepath.Join(t.TempDir(), "multi.db")
	plain, err := sql.Open("sqlite3", srcPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for _, stmt := range []string{
		`CREATE TABLE a (id INTEGER PRIMARY KEY, val TEXT)`,
		`CREATE TABLE b (id INTEGER PRIMARY KEY, ref INTEGER, FOREIGN KEY(ref) REFERENCES a(id))`,
		`CREATE INDEX idx_b_ref ON b(ref)`,
		`CREATE VIEW v_a AS SELECT id, val FROM a WHERE val IS NOT NULL`,
		`CREATE TRIGGER trg_a_insert AFTER INSERT ON a BEGIN INSERT INTO b(ref) VALUES (NEW.id); END`,
		`INSERT INTO a(val) VALUES ('one'), ('two'), ('three')`,
	} {
		if _, err := plain.Exec(stmt); err != nil {
			plain.Close()
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
	plain.Close()

	dstPath := filepath.Join(t.TempDir(), "multi-enc.db")
	key := "MultiKey123"
	if err := ConvertDB(srcPath, dstPath, ConvertOptions{
		TargetKey:    key,
		TargetCipher: CipherXChaCha20Poly1305,
	}); err != nil {
		t.Fatalf("ConvertDB: %v", err)
	}

	db, err := OpenWithOptions(dstPath, Options{Key: key, Cipher: CipherXChaCha20Poly1305})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Verify tables exist and have data.
	var aCount, bCount int
	db.QueryRow(`SELECT count(*) FROM a`).Scan(&aCount)
	db.QueryRow(`SELECT count(*) FROM b`).Scan(&bCount)
	if aCount != 3 {
		t.Fatalf("expected 3 rows in a, got %d", aCount)
	}
	if bCount != 3 {
		t.Fatalf("expected 3 rows in b (from trigger), got %d", bCount)
	}

	// Verify view.
	var viewCount int
	db.QueryRow(`SELECT count(*) FROM v_a`).Scan(&viewCount)
	if viewCount != 3 {
		t.Fatalf("expected 3 rows from view, got %d", viewCount)
	}
}

func TestConvertLargeDB(t *testing.T) {
	srcPath := filepath.Join(t.TempDir(), "large.db")
	plain, err := sql.Open("sqlite3", srcPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	plain.Exec(`CREATE TABLE big (id INTEGER PRIMARY KEY, payload BLOB)`)
	tx, _ := plain.Begin()
	stmt, _ := tx.Prepare(`INSERT INTO big(payload) VALUES(?)`)
	for i := 0; i < 1000; i++ {
		payload := make([]byte, 1024)
		for j := range payload {
			payload[j] = byte((i + j) % 251)
		}
		stmt.Exec(payload)
	}
	stmt.Close()
	tx.Commit()
	plain.Close()

	dstPath := filepath.Join(t.TempDir(), "large-enc.db")
	key := "LargeKey123"
	if err := ConvertDB(srcPath, dstPath, ConvertOptions{
		TargetKey:    key,
		TargetCipher: CipherAES256GCM,
	}); err != nil {
		t.Fatalf("ConvertDB: %v", err)
	}

	db, err := OpenWithOptions(dstPath, Options{Key: key, Cipher: CipherAES256GCM})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	var count int
	db.QueryRow(`SELECT count(*) FROM big`).Scan(&count)
	if count != 1000 {
		t.Fatalf("expected 1000 rows, got %d", count)
	}
}

// ── Source Unmodified ──────────────────────────────────────────────────────

func TestConvertSourceUnmodified(t *testing.T) {
	srcPath := createPlainDB(t, "source.db")

	// Read source content before conversion.
	beforeData, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}

	dstPath := filepath.Join(t.TempDir(), "dest.db")
	if err := ConvertDB(srcPath, dstPath, ConvertOptions{
		TargetKey:    "SourceCheckKey",
		TargetCipher: CipherAES256GCM,
	}); err != nil {
		t.Fatalf("ConvertDB: %v", err)
	}

	// Read source content after conversion.
	afterData, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read source after: %v", err)
	}

	if !bytesEqual(beforeData, afterData) {
		t.Fatal("source database was modified during conversion")
	}
}

// ── Error Cases ────────────────────────────────────────────────────────────

func TestConvertErrorMissingSource(t *testing.T) {
	err := ConvertDB("/nonexistent/db.db", filepath.Join(t.TempDir(), "out.db"), ConvertOptions{
		TargetKey: "Key123",
	})
	if !errors.Is(err, ErrConvertSourceNotFound) {
		t.Fatalf("expected ErrConvertSourceNotFound, got %v", err)
	}
}

func TestConvertErrorOutputExists(t *testing.T) {
	srcPath := createPlainDB(t, "src.db")
	dstPath := filepath.Join(t.TempDir(), "exists.db")
	os.WriteFile(dstPath, []byte("already here"), 0o600)

	err := ConvertDB(srcPath, dstPath, ConvertOptions{
		TargetKey: "Key123",
	})
	if !errors.Is(err, ErrConvertOutputExists) {
		t.Fatalf("expected ErrConvertOutputExists, got %v", err)
	}
}

func TestConvertErrorNoKeys(t *testing.T) {
	srcPath := createPlainDB(t, "nokeys.db")
	dstPath := filepath.Join(t.TempDir(), "out.db")

	err := ConvertDB(srcPath, dstPath, ConvertOptions{})
	if !errors.Is(err, ErrConvertTargetKeyNeeded) {
		t.Fatalf("expected ErrConvertTargetKeyNeeded, got %v", err)
	}
}

func TestConvertErrorSourceKeyForPlain(t *testing.T) {
	srcPath := createPlainDB(t, "plain.db")
	dstPath := filepath.Join(t.TempDir(), "out.db")

	err := ConvertDB(srcPath, dstPath, ConvertOptions{
		SourceKey:    "UnneededKey",
		TargetKey:    "Key123",
		TargetCipher: CipherAES256GCM,
	})
	if !errors.Is(err, ErrConvertNotEncrypted) {
		t.Fatalf("expected ErrConvertNotEncrypted, got %v", err)
	}
}

func TestConvertErrorWrongSourceKey(t *testing.T) {
	key := "CorrectKey123"
	srcPath := createEncryptedDB(t, "encrypted.db", key, CipherAES256GCM)
	dstPath := filepath.Join(t.TempDir(), "out.db")

	err := ConvertDB(srcPath, dstPath, ConvertOptions{
		SourceKey:    "WrongKey123",
		TargetCipher: CipherChaCha20Poly1305,
	})
	if err == nil {
		t.Fatal("expected error for wrong source key")
	}
}

func TestConvertErrorEmptyPaths(t *testing.T) {
	err := ConvertDB("", filepath.Join(t.TempDir(), "out.db"), ConvertOptions{TargetKey: "key"})
	if !errors.Is(err, ErrConvertInvalidOptions) {
		t.Fatalf("expected ErrConvertInvalidOptions for empty src, got %v", err)
	}

	err = ConvertDB(filepath.Join(t.TempDir(), "src.db"), "", ConvertOptions{TargetKey: "key"})
	if !errors.Is(err, ErrConvertInvalidOptions) {
		t.Fatalf("expected ErrConvertInvalidOptions for empty dst, got %v", err)
	}
}

func TestConvertCleanupOnFailure(t *testing.T) {
	// Create a valid encrypted source.
	key := "CleanupKey123"
	srcPath := createEncryptedDB(t, "cleanup.db", key, CipherAES256GCM)
	dstPath := filepath.Join(t.TempDir(), "cleanup-out.db")

	// Try to convert with wrong source key — should fail and clean up.
	_ = ConvertDB(srcPath, dstPath, ConvertOptions{
		SourceKey:    "WrongKey",
		TargetCipher: CipherChaCha20Poly1305,
	})

	// Verify no partial output remains.
	if _, err := os.Stat(dstPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected output to be cleaned up, stat err=%v", err)
	}
	if _, err := os.Stat(dstPath + ".encz"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected manifest to be cleaned up, stat err=%v", err)
	}
}

func TestReencryptDBInPlace_Basic(t *testing.T) {
	key := "InPlaceSecret123!"
	dbPath := createEncryptedDB(t, "inplace_basic.db", key, CipherAES256GCM)

	// Rotate DEKs manually by opening, acquiring key registry, and rotating.
	sealDB, err := OpenWithOptions(dbPath, Options{Key: key})
	if err != nil {
		t.Fatalf("open db for rotation: %v", err)
	}
	reg, ok := getKeyRegistry(sealDB.registryHandle)
	if !ok {
		sealDB.Close()
		t.Fatal("failed to acquire registry handle")
	}
	// Force DEK rotation twice
	if err := reg.rotateActiveDEKLocked(timeNowUTC().Add(25 * time.Hour)); err != nil {
		sealDB.Close()
		t.Fatalf("rotate DEK 1: %v", err)
	}
	if err := reg.rotateActiveDEKLocked(timeNowUTC().Add(50 * time.Hour)); err != nil {
		sealDB.Close()
		t.Fatalf("rotate DEK 2: %v", err)
	}
	sealDB.Close()

	// Verify manifest before re-encryption has multiple DEKs
	keyBuf := memguard.NewBufferFromBytes([]byte(key))
	payloadBefore, _, err := loadManifest(dbPath+".encz", keyBuf)
	keyBuf.Destroy()
	if err != nil {
		t.Fatalf("load manifest before: %v", err)
	}
	if len(payloadBefore.DEKs) <= 1 {
		t.Fatalf("expected multiple DEKs before re-encryption, got %d", len(payloadBefore.DEKs))
	}

	// Perform in-place re-encryption
	err = ReencryptDBInPlace(dbPath, ReencryptOptions{
		Key: key,
	})
	if err != nil {
		t.Fatalf("ReencryptDBInPlace failed: %v", err)
	}

	// Verify manifest after re-encryption has exactly 1 DEK (Key ID 1)
	keyBuf = memguard.NewBufferFromBytes([]byte(key))
	payloadAfter, _, err := loadManifest(dbPath+".encz", keyBuf)
	keyBuf.Destroy()
	if err != nil {
		t.Fatalf("load manifest after: %v", err)
	}
	if len(payloadAfter.DEKs) != 1 {
		t.Fatalf("expected 1 DEK after re-encryption, got %d", len(payloadAfter.DEKs))
	}
	if payloadAfter.ActiveDEKKeyID != 0 {
		t.Fatalf("expected ActiveDEKKeyID=0 after re-encryption, got %d", payloadAfter.ActiveDEKKeyID)
	}

	// Verify database content remains intact
	sealDB, err = OpenWithOptions(dbPath, Options{Key: key})
	if err != nil {
		t.Fatalf("open db after re-encryption: %v", err)
	}
	defer sealDB.Close()
	verifyDatabaseContent(t, sealDB.DB)
}

func TestReencryptDBInPlace_ChangeKeyAndCipher(t *testing.T) {
	oldKey := "OldSecretKey123!"
	newKey := "NewSecretKey456!"
	dbPath := createEncryptedDB(t, "inplace_rekey.db", oldKey, CipherAES256GCM)

	err := ReencryptDBInPlace(dbPath, ReencryptOptions{
		Key:          oldKey,
		TargetKey:    newKey,
		TargetCipher: CipherChaCha20Poly1305,
	})
	if err != nil {
		t.Fatalf("ReencryptDBInPlace failed: %v", err)
	}

	// Should fail with old key
	wrongDB, err := OpenWithOptions(dbPath, Options{Key: oldKey})
	if err == nil {
		wrongDB.Close()
		t.Fatal("expected error opening with old key")
	}

	// Should succeed with new key and cipher
	sealDB, err := OpenWithOptions(dbPath, Options{Key: newKey, Cipher: CipherChaCha20Poly1305})
	if err != nil {
		t.Fatalf("open with new key and cipher failed: %v", err)
	}
	defer sealDB.Close()
	verifyDatabaseContent(t, sealDB.DB)
}

func TestReencryptDBInPlace_ValidationErrors(t *testing.T) {
	// Empty path
	err := ReencryptDBInPlace("", ReencryptOptions{Key: "key"})
	if !errors.Is(err, ErrConvertInvalidOptions) {
		t.Fatalf("expected ErrConvertInvalidOptions for empty path, got %v", err)
	}

	// Empty key
	err = ReencryptDBInPlace(filepath.Join(t.TempDir(), "db.db"), ReencryptOptions{Key: ""})
	if !errors.Is(err, ErrConvertSourceKeyNeeded) {
		t.Fatalf("expected ErrConvertSourceKeyNeeded for empty key, got %v", err)
	}

	// Non-existent source
	err = ReencryptDBInPlace(filepath.Join(t.TempDir(), "nonexistent.db"), ReencryptOptions{Key: "key"})
	if !errors.Is(err, ErrConvertSourceNotFound) {
		t.Fatalf("expected ErrConvertSourceNotFound for missing source, got %v", err)
	}

	// Missing manifest
	plainPath := createPlainDB(t, "plain.db")
	err = ReencryptDBInPlace(plainPath, ReencryptOptions{Key: "key"})
	if !errors.Is(err, ErrManifestMissing) {
		t.Fatalf("expected ErrManifestMissing for plain db, got %v", err)
	}
}

