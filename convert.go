package sqliteseal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awnumar/memguard"
)

var (
	ErrConvertSourceNotFound  = errors.New("sqliteseal: source database does not exist")
	ErrConvertOutputExists    = errors.New("sqliteseal: conversion output file already exists")
	ErrConvertInvalidOptions  = errors.New("sqliteseal: invalid conversion options")
	ErrConvertSourceKeyNeeded = errors.New("sqliteseal: source key is required for encrypted source databases")
	ErrConvertTargetKeyNeeded = errors.New("sqliteseal: target key is required when converting to an encrypted database")
	ErrConvertNotEncrypted    = errors.New("sqliteseal: source database is not encrypted but a source key was provided")
	ErrConvertIntegrityFailed = errors.New("sqliteseal: converted database failed integrity check")
)

// ConvertOptions configures the ConvertDB operation.
type ConvertOptions struct {
	// SourceKey is the master key for the source database.
	// Required when the source is a SqliteSeal-encrypted database.
	// Must be empty when the source is a plain SQLite database.
	SourceKey string

	// TargetKey is the master key for the converted database.
	// Required when converting to a SqliteSeal database.
	// If empty and SourceKey is set and TargetCipher is set, SourceKey is reused.
	// Must be empty when decrypting to plain SQLite (TargetCipher also empty).
	TargetKey string

	// TargetCipher selects the cipher for the converted database.
	// Must be one of CipherAES256GCM, CipherChaCha20Poly1305, or CipherXChaCha20Poly1305.
	// Defaults to CipherAES256GCM when converting to an encrypted database.
	//
	// Leave empty together with TargetKey to decrypt to a plain SQLite file.
	TargetCipher Cipher
}

// ReencryptOptions configures the ReencryptDBInPlace operation.
type ReencryptOptions struct {
	// Key is the master key for the source database.
	// Required.
	Key string

	// TargetKey is the optional new master key for the re-encrypted database.
	// If empty, Key is reused.
	TargetKey string

	// TargetCipher selects the cipher for the re-encrypted database.
	// Must be one of CipherAES256GCM, CipherChaCha20Poly1305, or CipherXChaCha20Poly1305.
	// Defaults to the current database cipher if empty.
	TargetCipher Cipher
}

// ConvertDB reads the database at srcPath and writes a converted copy to dstPath.
//
// Supported conversions:
//   - Plain SQLite → SqliteSeal: SourceKey empty, TargetKey required.
//   - SqliteSeal cipher switch:  SourceKey required, TargetCipher selects the new cipher.
//   - SqliteSeal re-encrypt:     Same cipher, new DEKs; optionally a new TargetKey.
//   - SqliteSeal → Plain SQLite: SourceKey required, TargetKey and TargetCipher both empty.
//
// The source database is never modified. dstPath must not already exist.
// On error, any partially written output is removed.
func ConvertDB(srcPath, dstPath string, opts ConvertOptions) error {
	if err := mustRegister(); err != nil {
		return err
	}

	// ── 1. Validate paths ──────────────────────────────────────────────
	if strings.TrimSpace(srcPath) == "" {
		return fmt.Errorf("%w: source path is empty", ErrConvertInvalidOptions)
	}
	if strings.TrimSpace(dstPath) == "" {
		return fmt.Errorf("%w: destination path is empty", ErrConvertInvalidOptions)
	}

	srcExists, err := fileExists(srcPath)
	if err != nil {
		return err
	}
	if !srcExists {
		return ErrConvertSourceNotFound
	}

	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return err
	}
	dstExists, err := fileExists(dstPath)
	if err != nil {
		return err
	}
	if dstExists {
		return ErrConvertOutputExists
	}

	// ── 2. Detect source type ──────────────────────────────────────────
	srcManifestPath := srcPath + ".encz"
	srcHasManifest, err := fileExists(srcManifestPath)
	if err != nil {
		return err
	}

	// ── 3. Determine conversion scenario ───────────────────────────────
	decryptToPlain := false
	if srcHasManifest {
		// Source is encrypted.
		if opts.SourceKey == "" {
			return ErrConvertSourceKeyNeeded
		}
		if opts.TargetKey == "" && opts.TargetCipher == "" {
			// Decrypt to plain SQLite.
			decryptToPlain = true
		} else if opts.TargetKey == "" && opts.TargetCipher != "" {
			// Cipher switch: reuse SourceKey as TargetKey.
			opts.TargetKey = opts.SourceKey
		}
	} else {
		// Source is plain SQLite.
		if opts.SourceKey != "" {
			return ErrConvertNotEncrypted
		}
		if opts.TargetKey == "" {
			return ErrConvertTargetKeyNeeded
		}
	}

	// Normalize target cipher for encrypted output.
	if !decryptToPlain {
		opts.TargetCipher, err = normalizeCipher(opts.TargetCipher)
		if err != nil {
			return err
		}
	}

	// ── 4. Destination manifest path ───────────────────────────────────
	dstManifestPath := dstPath + ".encz"
	if !decryptToPlain {
		dstManifestExists, err := fileExists(dstManifestPath)
		if err != nil {
			return err
		}
		if dstManifestExists {
			return fmt.Errorf("%w: %s", ErrConvertOutputExists, dstManifestPath)
		}
	}

	// Cleanup on failure.
	cleanupOnError := func() {
		_ = os.Remove(dstPath)
		_ = os.Remove(dstPath + "-wal")
		_ = os.Remove(dstPath + "-shm")
		if !decryptToPlain {
			_ = os.Remove(dstManifestPath)
			_ = os.Remove(dstManifestPath + ".lock")
		}
	}

	// Determine whether we can use the fast page-copy path. The SQLite
	// backup API requires matching reserved-byte counts, so it only works
	// when both source and destination use the same VFS type (both
	// encrypted). For cross-format conversions we fall back to SQL-level
	// schema/data replication.
	canPageCopy := srcHasManifest && !decryptToPlain

	// ── 5. Open source database ────────────────────────────────────────
	var srcSQLDB *sql.DB
	var srcSealDB *DB

	if srcHasManifest {
		srcSealDB, err = OpenWithOptions(srcPath, Options{
			Key: opts.SourceKey,
		})
		if err != nil {
			return err
		}
		defer srcSealDB.Close()
		srcSQLDB = srcSealDB.DB
	} else {
		srcSQLDB, err = sql.Open("sqlite3",
			"file:"+filepath.ToSlash(srcPath)+"?mode=ro&_busy_timeout=5000")
		if err != nil {
			return err
		}
		defer srcSQLDB.Close()
		if err := srcSQLDB.Ping(); err != nil {
			return err
		}
	}

	// ── 6. Create target database ──────────────────────────────────────
	var dstSQLDB *sql.DB
	var dstRegistryHandle uint64

	if decryptToPlain {
		dstSQLDB, err = sql.Open("sqlite3",
			"file:"+filepath.ToSlash(dstPath)+"?_journal_mode=WAL&_busy_timeout=5000")
		if err != nil {
			cleanupOnError()
			return err
		}
		defer dstSQLDB.Close()
		if err := dstSQLDB.Ping(); err != nil {
			cleanupOnError()
			return err
		}
	} else {
		targetKeyBuf := memguard.NewBufferFromBytes([]byte(opts.TargetKey))
		defer targetKeyBuf.Destroy()

		policy, policyErr := normalizeCreateRotationPolicy(nil)
		if policyErr != nil {
			cleanupOnError()
			return policyErr
		}

		payload, payloadErr := newManifestPayload(policy, opts.TargetCipher, timeNowUTC())
		if payloadErr != nil {
			cleanupOnError()
			return payloadErr
		}

		if manifestErr := saveManifest(dstManifestPath, targetKeyBuf, payload); manifestErr != nil {
			cleanupOnError()
			return manifestErr
		}

		handle, regErr := registerKeyRegistry(dstManifestPath, targetKeyBuf, payload, policy, false)
		if regErr != nil {
			cleanupOnError()
			return regErr
		}
		dstRegistryHandle = handle
		defer destroyKeyRegistry(dstRegistryHandle)

		dstOpts := applyRegistryToOptions(Options{Cipher: opts.TargetCipher, JournalMode: "WAL"}, dstRegistryHandle)
		dstSQLDB, err = openSQLDB(buildDSN(dstPath, dstOpts))
		if err != nil {
			cleanupOnError()
			return err
		}
		defer dstSQLDB.Close()
	}

	// ── 7. Copy database content ───────────────────────────────────────
	if canPageCopy {
		// Fast path: both source and destination use the encrypted VFS
		// with identical reserved-byte counts, so we can use the SQLite
		// backup API for a direct page-level copy.
		if err := copyDatabasePages(context.Background(), srcSQLDB, dstSQLDB); err != nil {
			cleanupOnError()
			return err
		}
	} else {
		// Slow path: source and destination have different page formats
		// (plain vs encrypted). Copy schema and data via SQL statements.
		if err := copyDatabaseSQL(context.Background(), srcSQLDB, dstSQLDB); err != nil {
			cleanupOnError()
			return err
		}
	}

	// ── 8. VACUUM ──────────────────────────────────────────────────────
	if _, err := dstSQLDB.Exec(`VACUUM`); err != nil {
		cleanupOnError()
		return err
	}

	// ── 9. Integrity check ─────────────────────────────────────────────
	var integrity string
	if err := dstSQLDB.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		cleanupOnError()
		return err
	}
	if integrity != "ok" {
		cleanupOnError()
		return fmt.Errorf("%w: %s", ErrConvertIntegrityFailed, integrity)
	}

	return nil
}

// copyDatabaseSQL replicates a database's schema and data via SQL statements.
// This is used when the source and destination have incompatible page formats
// (e.g., different reserved-byte counts for plain vs encrypted databases).
//
// Schema objects are created in two phases:
//  1. Tables and indexes are created first.
//  2. Data is copied for each table.
//  3. Triggers and views are created after data is loaded.
//
// This ordering prevents triggers from firing during data copy and
// creating duplicate rows.
func copyDatabaseSQL(ctx context.Context, srcDB, dstDB *sql.DB) error {
	// Query all schema objects from the source.
	rows, err := srcDB.QueryContext(ctx,
		`SELECT type, name, sql FROM sqlite_master
		 WHERE sql IS NOT NULL
		 ORDER BY CASE type
		     WHEN 'table' THEN 1
		     WHEN 'index' THEN 2
		     WHEN 'trigger' THEN 3
		     WHEN 'view' THEN 4
		     ELSE 5
		 END, name`)
	if err != nil {
		return fmt.Errorf("sqliteseal: read source schema: %w", err)
	}
	defer rows.Close()

	type schemaObject struct {
		objType string
		name    string
		ddl     string
	}
	var preDataObjects []schemaObject  // tables and indexes
	var postDataObjects []schemaObject // triggers and views
	for rows.Next() {
		var obj schemaObject
		if err := rows.Scan(&obj.objType, &obj.name, &obj.ddl); err != nil {
			return fmt.Errorf("sqliteseal: scan schema row: %w", err)
		}
		// Skip internal SQLite objects.
		if strings.HasPrefix(obj.name, "sqlite_") {
			continue
		}
		switch obj.objType {
		case "table", "index":
			preDataObjects = append(preDataObjects, obj)
		default:
			postDataObjects = append(postDataObjects, obj)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("sqliteseal: iterate schema: %w", err)
	}

	// Phase 1: Create tables and indexes.
	for _, obj := range preDataObjects {
		if _, err := dstDB.ExecContext(ctx, obj.ddl); err != nil {
			return fmt.Errorf("sqliteseal: create %s %q: %w", obj.objType, obj.name, err)
		}
	}

	// Phase 2: Copy data for each table (no triggers exist yet).
	for _, obj := range preDataObjects {
		if obj.objType != "table" {
			continue
		}
		if err := copyTableData(ctx, srcDB, dstDB, obj.name); err != nil {
			return err
		}
	}

	// Phase 3: Create triggers and views after data is loaded.
	for _, obj := range postDataObjects {
		if _, err := dstDB.ExecContext(ctx, obj.ddl); err != nil {
			return fmt.Errorf("sqliteseal: create %s %q: %w", obj.objType, obj.name, err)
		}
	}

	return nil
}

// copyTableData copies all rows from a table in srcDB to the same table in dstDB.
func copyTableData(ctx context.Context, srcDB, dstDB *sql.DB, tableName string) error {
	// Get column names for this table.
	colRows, err := srcDB.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%q)", tableName))
	if err != nil {
		return fmt.Errorf("sqliteseal: table_info %q: %w", tableName, err)
	}
	var colNames []string
	for colRows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dfltValue sql.NullString
		var pk int
		if err := colRows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			colRows.Close()
			return fmt.Errorf("sqliteseal: scan column info for %q: %w", tableName, err)
		}
		colNames = append(colNames, name)
	}
	colRows.Close()
	if err := colRows.Err(); err != nil {
		return fmt.Errorf("sqliteseal: iterate columns for %q: %w", tableName, err)
	}

	if len(colNames) == 0 {
		return nil
	}

	// Build SELECT and INSERT statements.
	quotedCols := make([]string, len(colNames))
	placeholders := make([]string, len(colNames))
	for i, name := range colNames {
		quotedCols[i] = fmt.Sprintf("%q", name)
		placeholders[i] = "?"
	}
	selectSQL := fmt.Sprintf("SELECT %s FROM %q", strings.Join(quotedCols, ", "), tableName)
	insertSQL := fmt.Sprintf("INSERT INTO %q (%s) VALUES (%s)",
		tableName,
		strings.Join(quotedCols, ", "),
		strings.Join(placeholders, ", "))

	// Read all source rows.
	dataRows, err := srcDB.QueryContext(ctx, selectSQL)
	if err != nil {
		return fmt.Errorf("sqliteseal: select from %q: %w", tableName, err)
	}
	defer dataRows.Close()

	// Begin a transaction for bulk insert.
	tx, err := dstDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqliteseal: begin tx for %q: %w", tableName, err)
	}

	stmt, err := tx.PrepareContext(ctx, insertSQL)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("sqliteseal: prepare insert for %q: %w", tableName, err)
	}
	defer stmt.Close()

	colCount := len(colNames)
	values := make([]any, colCount)
	scanDest := make([]any, colCount)
	for i := range values {
		scanDest[i] = &values[i]
	}

	for dataRows.Next() {
		if err := dataRows.Scan(scanDest...); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("sqliteseal: scan row from %q: %w", tableName, err)
		}
		if _, err := stmt.ExecContext(ctx, values...); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("sqliteseal: insert row into %q: %w", tableName, err)
		}
	}
	if err := dataRows.Err(); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("sqliteseal: iterate rows from %q: %w", tableName, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqliteseal: commit %q: %w", tableName, err)
	}

	return nil
}

// ReencryptDBInPlace re-encrypts an encrypted database in-place, consolidating all
// historical DEKs down to a single active DEK (Key ID 1), compacting storage via VACUUM,
// and optionally updating the master key or cipher.
//
// The operation is performed atomically using a temporary destination database.
// On success, old historical DEKs are eliminated and the database size is optimized.
// On failure, the original database remains untouched.
func ReencryptDBInPlace(dbPath string, opts ReencryptOptions) error {
	if err := mustRegister(); err != nil {
		return err
	}

	if strings.TrimSpace(dbPath) == "" {
		return fmt.Errorf("%w: database path is empty", ErrConvertInvalidOptions)
	}
	if opts.Key == "" {
		return ErrConvertSourceKeyNeeded
	}

	srcExists, err := fileExists(dbPath)
	if err != nil {
		return err
	}
	if !srcExists {
		return ErrConvertSourceNotFound
	}

	manifestPath := dbPath + ".encz"
	manifestExists, err := fileExists(manifestPath)
	if err != nil {
		return err
	}
	if !manifestExists {
		return ErrManifestMissing
	}

	// Read existing manifest to determine current cipher if TargetCipher is omitted.
	targetCipher := opts.TargetCipher
	if targetCipher == "" {
		keyBuf := memguard.NewBufferFromBytes([]byte(opts.Key))
		payload, _, loadErr := loadManifest(manifestPath, keyBuf)
		keyBuf.Destroy()
		if loadErr != nil {
			return loadErr
		}
		targetCipher = payload.Cipher
	}

	targetKey := opts.TargetKey
	if targetKey == "" {
		targetKey = opts.Key
	}

	// Create temporary staging directory in the same directory to allow atomic renames.
	dir := filepath.Dir(dbPath)
	stageDir, err := os.MkdirTemp(dir, ".reencrypt-stage-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stageDir)

	tempDBPath := filepath.Join(stageDir, filepath.Base(dbPath))

	// Re-encrypt to temporary destination using ConvertDB.
	convOpts := ConvertOptions{
		SourceKey:    opts.Key,
		TargetKey:    targetKey,
		TargetCipher: targetCipher,
	}
	if err := ConvertDB(dbPath, tempDBPath, convOpts); err != nil {
		return err
	}

	tempManifestPath := tempDBPath + ".encz"

	// Lock manifest during file substitution to prevent concurrent access.
	return withManifestLock(manifestPath, func() error {
		// Clean up WAL and SHM sidecars for original database before replacing files.
		_ = os.Remove(dbPath + "-wal")
		_ = os.Remove(dbPath + "-shm")

		bakDBPath := filepath.Join(stageDir, "backup.db")
		bakManifestPath := filepath.Join(stageDir, "backup.db.encz")

		if err := os.Rename(dbPath, bakDBPath); err != nil {
			return err
		}
		if err := os.Rename(manifestPath, bakManifestPath); err != nil {
			_ = os.Rename(bakDBPath, dbPath)
			return err
		}

		if err := os.Rename(tempDBPath, dbPath); err != nil {
			_ = os.Rename(bakManifestPath, manifestPath)
			_ = os.Rename(bakDBPath, dbPath)
			return err
		}
		if err := os.Rename(tempManifestPath, manifestPath); err != nil {
			_ = os.Remove(dbPath)
			_ = os.Rename(bakManifestPath, manifestPath)
			_ = os.Rename(bakDBPath, dbPath)
			return err
		}

		_ = syncParentDir(dir)
		return nil
	})
}

