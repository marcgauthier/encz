# SQLiteSeal Operations & Administration Guide

This guide provides operational procedures, migration playbooks, backup/restore workflows, performance tuning strategies, and troubleshooting steps for system administrators, DBAs, and developers using `SQLiteSeal` (`github.com/marcgauthier/SQLiteSeal`).

---

## 1. Database Migration & Conversion (`ConvertDB`)

`SQLiteSeal` provides the standalone function `ConvertDB` to handle offline conversions between plaintext SQLite databases and encrypted databases, as well as cipher transitions.

```go
func ConvertDB(srcPath, dstPath string, opts ConvertOptions) error
```

> **Operational Note**: `ConvertDB` operates strictly out-of-place. The `srcPath` file is never modified, and `dstPath` must not exist prior to invocation. If conversion fails, any temporary destination file is automatically cleaned up.

### Common Migration Workflows

#### Workflow A: Encrypting Plaintext SQLite → SQLiteSeal

```go
package main

import (
    "log"

    "github.com/marcgauthier/SQLiteSeal"
)

func main() {
    opts := sqliteseal.ConvertOptions{
        SourceKey:    "", // Plaintext source requires empty SourceKey
        TargetKey:    "ProductionSuperSecretPassphrase2026!",
        TargetCipher: sqliteseal.CipherAES256GCM, // Or CipherXChaCha20Poly1305
    }

    if err := sqliteseal.ConvertDB("legacy.db", "encrypted.db", opts); err != nil {
        log.Fatalf("conversion failed: %v", err)
    }
    log.Println("Database encrypted successfully!")
}
```

#### Workflow B: Switching Cipher Suites (AES-256-GCM → XChaCha20-Poly1305)

```go
opts := sqliteseal.ConvertOptions{
    SourceKey:    "ProductionSuperSecretPassphrase2026!",
    TargetKey:    "ProductionSuperSecretPassphrase2026!", // Reuse or update
    TargetCipher: sqliteseal.CipherXChaCha20Poly1305,
}

if err := sqliteseal.ConvertDB("aes.db", "xchacha.db", opts); err != nil {
    log.Fatalf("cipher migration failed: %v", err)
}
```

#### Workflow C: Decrypting SQLiteSeal → Plaintext SQLite

```go
opts := sqliteseal.ConvertOptions{
    SourceKey:    "ProductionSuperSecretPassphrase2026!",
    TargetKey:    "", // Empty target key signals plaintext export
    TargetCipher: "", // Empty target cipher
}

if err := sqliteseal.ConvertDB("encrypted.db", "plaintext.db", opts); err != nil {
    log.Fatalf("decryption export failed: %v", err)
}
```

---

## 2. Live Key Management & Rotation

### Live Passphrase Rekeying (`ReKey`)

Re-keying updates the Key Encryption Key (KEK) protecting the sidecar manifest. This operation completes almost instantaneously because on-disk page data does not need to be re-encrypted.

```go
db, err := sqliteseal.OpenSQLiteSeal("app.db", "OldSecretPassphrase")
if err != nil {
    log.Fatal(err)
}
defer db.Close()

// Re-key database to a new master key
if err := db.ReKey("OldSecretPassphrase", "NewSecretPassphrase2026!"); err != nil {
    log.Fatalf("rekey failed: %v", err)
}
```

### Inspecting Rotation Status

```go
info, err := db.RotationStatus()
if err != nil {
    log.Fatal(err)
}

log.Printf("Manifest Path: %s", info.ManifestPath)
log.Printf("Active DEK ID: %d", info.ActiveDEKKeyID)
log.Printf("Total DEKs: %d", info.TotalDEKs)
log.Printf("Pending KEK Rotation: %v", info.PendingKEKRotation)
```

---

## 3. Backup & Secure Restore Workflows

### Creating Encrypted Backups (`(*DB) Backup`)

`SQLiteSeal` generates a single, self-contained zip archive containing the database file and sidecar manifest, fully encrypted using AES-256-GCM.

```go
backupOpts := sqliteseal.BackupOptions{
    Compression: sqliteseal.BackupCompressionDeflate, // "store", "deflate", or "zstd"
}

if err := db.Backup("/backups/app_20260728.zip", backupOpts); err != nil {
    log.Fatalf("backup failed: %v", err)
}
```

### Performing Secure Restores (`RestoreBackup`)

`RestoreBackup` unpacks the archive into a temporary private staging folder, validates SQLite database integrity and manifest matching, and safely replaces the target database files in the target directory.

```go
err := sqliteseal.RestoreBackup(
    "/backups/app_20260728.zip",
    "ProductionSuperSecretPassphrase2026!",
    "/var/data/app",
    true, // Overwrite existing file if present
)
if err != nil {
    log.Fatalf("restore failed: %v", err)
}
```

---

## 4. Performance Tuning & Metrics

### Decrypted Page Cache Configuration

By default, `SQLiteSeal` maintains a **128 MB** in-memory decrypted page LRU cache per `DB` handle. For read-heavy applications, increasing this limit reduces AEAD CPU overhead.

```go
opts := sqliteseal.Options{
    Key:                     "Passphrase",
    DecryptedPageCacheBytes: 512 << 20, // 512 MB LRU cache
    EnableReadPerformanceStats: true,
}
db, err := sqliteseal.OpenWithOptions("app.db", opts)
```

### Monitoring Read Performance Stats

```go
stats := db.ReadPerformanceStats()

hitRatio := float64(stats.Hits) / float64(stats.Hits+stats.Misses) * 100
log.Printf("Cache Hit Ratio: %.2f%%", hitRatio)
log.Printf("Total Decryptions: %d", stats.Decryptions)
log.Printf("Bytes Read: %d", stats.BytesRead)
```

### Running Standalone Benchmarks

`SQLiteSeal` includes a benchmark tool in `tests-benchmark` comparing performance against plain SQLite and Turso AES-256-GCM.

```bash
cd tests-benchmark
go run . -rows 10000 -write-rows 20000
```

---

## 5. Concurrency & Operating Rules

1. **Write-Ahead Logging (WAL)**: `SQLiteSeal` enforces WAL or MEMORY journal modes. Rollback journals (`DELETE`, `TRUNCATE`, `PERSIST`) are rejected with `ErrUnsafeJournalMode` because unencrypted rollback journal files on disk present a security hazard.
2. **File Lock Coordination**: The sidecar file `db.encz.lock` coordinates manifest updates across processes. Ensure application processes have read and write permissions for `db.db`, `db.encz`, and `db.encz.lock`.
3. **No Direct DSN Keys**: Passing passwords or hex keys in SQLite DSN strings is explicitly disabled (`ErrDirectKeyUnsupported`) to prevent sensitive key material from appearing in process lists, log aggregators, or stack traces.

---

## 6. Troubleshooting Common Errors

| Error | Root Cause | Resolution |
| :--- | :--- | :--- |
| `ErrManifestMissing` | The `.encz` manifest sidecar file is missing or was deleted. | Restore the corresponding `.encz` file from backup. Databases cannot be opened without their manifest. |
| `ErrManifestAuthFailed` | Provided master key is incorrect or manifest is corrupted. | Verify passphrase accuracy or test against backup archives. |
| `ErrCurrentKeyMismatch` | `oldKey` parameter in `ReKey` does not match active handle key. | Pass the exact key currently active on the `*DB` handle. |
| `ErrUnsafeJournalMode` | PRAGMA journal_mode was set to `DELETE` or `TRUNCATE`. | Set journal mode to `WAL` or `MEMORY`. |
| `ErrDirectKeyUnsupported` | Encryption keys passed via DSN URL parameters. | Use `OpenSQLiteSeal` or `OpenWithOptions` instead of `sql.Open("sqlite3", dsn)`. |
