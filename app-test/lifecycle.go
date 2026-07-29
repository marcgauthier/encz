package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	sqliteseal "github.com/marcgauthier/SQLiteSeal"
)

func certifyPublicAPI(baseDir, masterKey string, logger *liveLogger) error {
	logger.Info("API certification started")
	if err := sqliteseal.Register(); err != nil {
		return fmt.Errorf("Register first call: %w", err)
	}
	if err := sqliteseal.Register(); err != nil {
		return fmt.Errorf("Register idempotent call: %w", err)
	}
	busy := 1000
	if dsn, err := sqliteseal.BuildDSN(filepath.Join(baseDir, "dsn.db"), sqliteseal.Options{
		JournalMode:       "WAL",
		BusyTimeoutMillis: &busy,
	}); err != nil || !strings.Contains(dsn, "_journal_mode=WAL") {
		return fmt.Errorf("BuildDSN safe options: dsn=%q err=%w", dsn, err)
	}
	if _, err := sqliteseal.BuildDSN("bad.db", sqliteseal.Options{Key: masterKey}); !errors.Is(err, sqliteseal.ErrDirectKeyUnsupported) {
		return fmt.Errorf("BuildDSN key rejection: got %v", err)
	}
	if _, err := sqliteseal.BuildSQLiteSealDSN("bad.db", masterKey); !errors.Is(err, sqliteseal.ErrDirectKeyUnsupported) {
		return fmt.Errorf("BuildSQLiteSealDSN expected ErrDirectKeyUnsupported, got %v", err)
	}
	if _, err := sqliteseal.BuildEnczDSN("bad.db", masterKey); !errors.Is(err, sqliteseal.ErrDirectKeyUnsupported) {
		return fmt.Errorf("BuildEnczDSN expected ErrDirectKeyUnsupported, got %v", err)
	}

	defaultPath := filepath.Join(baseDir, "open-default.db")
	defaultDB, err := sqliteseal.OpenSQLiteSeal(defaultPath, masterKey)
	if err != nil {
		return fmt.Errorf("OpenSQLiteSeal: %w", err)
	}
	if _, err := defaultDB.Exec(`CREATE TABLE api_check(id INTEGER PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		defaultDB.Close()
		return err
	}
	if _, err := defaultDB.Exec(`INSERT INTO api_check(value) VALUES ('sealed')`); err != nil {
		defaultDB.Close()
		return err
	}
	if err := defaultDB.Close(); err != nil {
		return err
	}
	legacyDB, err := sqliteseal.OpenEncz(defaultPath, masterKey)
	if err != nil {
		return fmt.Errorf("OpenEncz: %w", err)
	}
	var value string
	if err := legacyDB.QueryRow(`SELECT value FROM api_check`).Scan(&value); err != nil || value != "sealed" {
		legacyDB.Close()
		return fmt.Errorf("OpenEncz read expected sealed got %q: %w", value, err)
	}
	if err := legacyDB.Close(); err != nil {
		return err
	}

	ciphers := []sqliteseal.Cipher{
		sqliteseal.CipherAES256GCM,
		sqliteseal.CipherChaCha20Poly1305,
		sqliteseal.CipherXChaCha20Poly1305,
	}
	for i, cipher := range ciphers {
		path := filepath.Join(baseDir, fmt.Sprintf("cipher-%d.db", i))
		db, err := sqliteseal.OpenWithOptions(path, sqliteseal.Options{
			Key:                        masterKey,
			Cipher:                     cipher,
			EnableReadPerformanceStats: true,
			DecryptedPageCacheBytes:    2 << 20,
		})
		if err != nil {
			return fmt.Errorf("OpenWithOptions cipher=%s: %w", cipher, err)
		}
		if db.SQLDB() == nil {
			db.Close()
			return fmt.Errorf("SQLDB cipher=%s returned nil", cipher)
		}
		if _, err := db.Exec(`CREATE TABLE cipher_check(id INTEGER PRIMARY KEY, value TEXT)`); err != nil {
			db.Close()
			return err
		}
		if _, err := db.Exec(`INSERT INTO cipher_check(value) VALUES ('cipher-data')`); err != nil {
			db.Close()
			return err
		}
		if err := certifyHandleAPI(baseDir, masterKey, i, db); err != nil {
			db.Close()
			return fmt.Errorf("cipher=%s: %w", cipher, err)
		}
		if err := db.Close(); err != nil {
			return err
		}
		if err := db.Close(); err != nil {
			return fmt.Errorf("idempotent Close cipher=%s: %w", cipher, err)
		}
	}
	if err := certifyLogHandler(baseDir, masterKey); err != nil {
		return err
	}
	logger.Info("API certification passed")
	return nil
}

func certifyHandleAPI(baseDir, masterKey string, index int, db *sqliteseal.DB) error {
	policy := sqliteseal.RotationPolicy{
		KEKRotationDays:  14,
		DEKRotationHours: 48,
		AutoRewrap:       true,
		KeepPreviousKey:  true,
	}
	if err := db.SetRotationPolicy(policy); err != nil {
		return fmt.Errorf("SetRotationPolicy: %w", err)
	}
	info, err := db.RotationStatus()
	if err != nil || !info.Exists || info.DEKRotationHours != 48 {
		return fmt.Errorf("RotationStatus info=%+v err=%w", info, err)
	}
	if stats := db.ReadPerformanceStats(); !stats.Enabled {
		return errors.New("ReadPerformanceStats was not enabled")
	}
	db.ResetReadPerformanceStats()
	if stats := db.ReadPerformanceStats(); stats.PageRequests != 0 || stats.AEADOpenCalls != 0 {
		return fmt.Errorf("ResetReadPerformanceStats left counters: %+v", stats)
	}
	if err := db.ReKey("definitely-wrong-key", masterKey+"-new"); !errors.Is(err, sqliteseal.ErrCurrentKeyMismatch) {
		return fmt.Errorf("ReKey wrong-key expected ErrCurrentKeyMismatch, got %v", err)
	}

	archive := filepath.Join(baseDir, fmt.Sprintf("api-backup-%d.seal", index))
	if err := db.Backup(archive, sqliteseal.BackupOptions{Compression: sqliteseal.BackupCompressionStore}); err != nil {
		return fmt.Errorf("Backup store: %w", err)
	}
	if err := db.Backup(archive, sqliteseal.BackupOptions{Compression: sqliteseal.BackupCompressionStore}); !errors.Is(err, sqliteseal.ErrBackupOutputExists) {
		return fmt.Errorf("Backup overwrite expected ErrBackupOutputExists, got %v", err)
	}
	if err := db.Backup(filepath.Join(baseDir, fmt.Sprintf("zstd-%d.seal", index)), sqliteseal.BackupOptions{Compression: sqliteseal.BackupCompressionZstd}); !errors.Is(err, sqliteseal.ErrBackupCompressionUnsupported) {
		return fmt.Errorf("Backup zstd expected unsupported, got %v", err)
	}
	testDir := filepath.Join(baseDir, fmt.Sprintf("test-backup-%d", index))
	if err := sqliteseal.TestBackup(archive, masterKey, testDir); err != nil {
		return fmt.Errorf("TestBackup: %w", err)
	}
	restoreDir := filepath.Join(baseDir, fmt.Sprintf("restore-%d", index))
	if err := sqliteseal.RestoreBackup(archive, masterKey, restoreDir, false); err != nil {
		return fmt.Errorf("RestoreBackup: %w", err)
	}
	if err := sqliteseal.RestoreBackup(archive, masterKey, restoreDir, false); err == nil {
		return errors.New("RestoreBackup overwrite protection unexpectedly succeeded")
	}
	if err := sqliteseal.RestoreBackup(archive, masterKey, restoreDir, true); err != nil {
		return fmt.Errorf("RestoreBackup overwrite=true: %w", err)
	}
	temporaryKey := fmt.Sprintf("%s-api-rekey-%d", masterKey, index)
	if err := db.ReKey(masterKey, temporaryKey); err != nil {
		return fmt.Errorf("ReKey forward: %w", err)
	}
	if err := db.ReKey(temporaryKey, masterKey); err != nil {
		return fmt.Errorf("ReKey reverse: %w", err)
	}
	return nil
}

func certifyLogHandler(baseDir, masterKey string) error {
	path := filepath.Join(baseDir, "tamper.db")
	db, err := sqliteseal.OpenSQLiteSeal(path, masterKey)
	if err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE TABLE tamper_check(id INTEGER PRIMARY KEY, value BLOB)`); err != nil {
		db.Close()
		return err
	}
	if _, err := db.Exec(`INSERT INTO tamper_check(value) VALUES (randomblob(2048))`); err != nil {
		db.Close()
		return err
	}
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		db.Close()
		return err
	}
	if err := db.Close(); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	one := []byte{0}
	if _, err := f.ReadAt(one, 512); err != nil {
		f.Close()
		return err
	}
	one[0] ^= 0x80
	if _, err := f.WriteAt(one, 512); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()

	var messages []string
	sqliteseal.SetLogHandler(func(message string) {
		messages = append(messages, message)
	})
	defer sqliteseal.SetLogHandler(nil)
	tampered, openErr := sqliteseal.OpenSQLiteSeal(path, masterKey)
	if tampered != nil {
		var count int
		openErr = tampered.QueryRow(`SELECT count(*) FROM tamper_check`).Scan(&count)
		tampered.Close()
	}
	if openErr == nil {
		return errors.New("tampered encrypted page unexpectedly opened")
	}
	if len(messages) == 0 {
		return fmt.Errorf("SetLogHandler received no authentication error; open error=%v", openErr)
	}
	return nil
}

func (r *runner) maintenance() {
	defer close(r.maintDone)
	audit := time.NewTicker(r.cfg.AuditEvery)
	reopen := time.NewTicker(r.cfg.ReopenEvery)
	backup := time.NewTicker(r.cfg.BackupEvery)
	rekey := time.NewTicker(r.cfg.RekeyEvery)
	defer audit.Stop()
	defer reopen.Stop()
	defer backup.Stop()
	defer rekey.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-audit.C:
			r.runMaintenance("audit", r.audit)
		case <-reopen.C:
			r.runMaintenance("reopen", r.reopen)
		case <-backup.C:
			r.runMaintenance("backup", r.backupRestore)
		case <-rekey.C:
			r.runMaintenance("rekey", r.rekey)
		}
	}
}

func (r *runner) runMaintenance(name string, fn func() error) {
	if r.ctx.Err() != nil {
		return
	}
	r.gate.Lock()
	defer r.gate.Unlock()
	r.log.Info("maintenance=%s start", name)
	if err := fn(); err != nil {
		if r.ctx.Err() == nil {
			r.fail(fmt.Errorf("maintenance=%s: %w", name, err))
		}
		return
	}
	r.log.Info("maintenance=%s passed", name)
}

func (r *runner) audit() error {
	if err := r.fullAudit(r.ctx, r.db.SQLDB()); err != nil {
		return err
	}
	info, err := r.db.RotationStatus()
	if err != nil || !info.Exists {
		return fmt.Errorf("RotationStatus info=%+v: %w", info, err)
	}
	stats := r.db.ReadPerformanceStats()
	if !stats.Enabled {
		return errors.New("read performance statistics unexpectedly disabled")
	}
	r.db.ResetReadPerformanceStats()
	reset := r.db.ReadPerformanceStats()
	if reset.PageRequests != 0 || reset.AEADOpenCalls != 0 {
		return fmt.Errorf("read statistics reset failed: %+v", reset)
	}
	r.stats.audits.Add(1)
	return nil
}

func (r *runner) reopen() error {
	if err := r.db.Close(); err != nil {
		return err
	}
	db, err := sqliteseal.OpenWithOptions(r.cfg.DBPath, r.openOptions(r.key, r.cfg.CipherValue))
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(r.cfg.Workers + 2)
	r.db = db
	if err := r.fullAudit(r.ctx, db.SQLDB()); err != nil {
		return err
	}
	r.stats.reopens.Add(1)
	return nil
}

func (r *runner) backupRestore() error {
	number := r.stats.backups.Load() + 1
	compression := sqliteseal.BackupCompressionDeflate
	if number%2 == 0 {
		compression = sqliteseal.BackupCompressionStore
	}
	archive := filepath.Join(r.cfg.RunDir, fmt.Sprintf("backup-%04d.seal", number))
	if err := r.db.Backup(archive, sqliteseal.BackupOptions{Compression: compression}); err != nil {
		return err
	}
	testDir := filepath.Join(r.cfg.RunDir, fmt.Sprintf("backup-test-%04d", number))
	if err := sqliteseal.TestBackup(archive, r.key, testDir); err != nil {
		return err
	}
	restoreDir := filepath.Join(r.cfg.RunDir, fmt.Sprintf("restore-%04d", number))
	if err := sqliteseal.RestoreBackup(archive, r.key, restoreDir, false); err != nil {
		return err
	}
	restoredPath := filepath.Join(restoreDir, strings.TrimSuffix(filepath.Base(archive), filepath.Ext(archive))+".bak")
	restored, err := sqliteseal.OpenWithOptions(restoredPath, r.openOptions(r.key, r.cfg.CipherValue))
	if err != nil {
		return fmt.Errorf("open restored backup: %w", err)
	}
	auditErr := r.fullAudit(r.ctx, restored.SQLDB())
	closeErr := restored.Close()
	if auditErr != nil {
		return auditErr
	}
	if closeErr != nil {
		return closeErr
	}
	r.stats.backups.Add(1)
	return nil
}

func (r *runner) rekey() error {
	oldKey := r.key
	r.keyIndex++
	newKey := fmt.Sprintf("%s-rotation-%d", r.cfg.MasterKey, r.keyIndex%2)
	if newKey == oldKey {
		newKey += "-next"
	}
	if err := r.db.ReKey("wrong-"+oldKey, newKey); !errors.Is(err, sqliteseal.ErrCurrentKeyMismatch) {
		return fmt.Errorf("wrong old key expected ErrCurrentKeyMismatch, got %v", err)
	}
	if err := r.db.ReKey(oldKey, newKey); err != nil {
		return err
	}
	if wrong, err := sqliteseal.OpenWithOptions(r.cfg.DBPath, r.openOptions(oldKey, r.cfg.CipherValue)); err == nil {
		wrong.Close()
		return errors.New("old key still opened database after ReKey")
	}
	r.key = newKey
	if err := r.reopen(); err != nil {
		return err
	}
	r.stats.rekeys.Add(1)
	return nil
}

func (r *runner) finalAudit() error {
	r.gate.Lock()
	defer r.gate.Unlock()
	if r.db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return r.fullAudit(ctx, r.db.SQLDB())
}
