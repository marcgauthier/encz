# SQLiteSeal API Reference

This document provides a comprehensive catalog of all exported types, functions, methods, options structs, constants, and error sentinels in the `sqliteseal` Go package (`github.com/marcgauthier/SQLiteSeal`).

---

## Table of Contents

- [Core Types](#core-types)
  - [`DB`](#type-db)
  - [`Options`](#type-options)
  - [`Cipher`](#type-cipher)
- [Database Lifecycle Management](#database-lifecycle-management)
  - [`OpenSQLiteSeal`](#func-opensqliteseal)
  - [`OpenWithOptions`](#func-openwithoptions)
  - [`(*DB) Close`](#func-db-close)
  - [`(*DB) SQLDB`](#func-db-sqldb)
- [Key Rotation & Security Policy](#key-rotation--security-policy)
  - [`(*DB) ReKey`](#func-db-rekey)
  - [`(*DB) SetRotationPolicy`](#func-db-setrotationpolicy)
  - [`(*DB) RotationStatus`](#func-db-rotationstatus)
  - [`RotationPolicy`](#type-rotationpolicy)
  - [`RotationInfo`](#type-rotationinfo)
- [Backup & Recovery](#backup--recovery)
  - [`(*DB) Backup`](#func-db-backup)
  - [`RestoreBackup`](#func-restorebackup)
  - [`BackupOptions`](#type-backupoptions)
  - [`BackupCompression`](#type-backupcompression)
- [Database Conversion & Migration](#database-conversion--migration)
  - [`ConvertDB`](#func-convertdb)
  - [`ConvertOptions`](#type-convertoptions)
- [Performance & Monitoring](#performance--monitoring)
  - [`(*DB) ReadPerformanceStats`](#func-db-readperformancestats)
  - [`(*DB) ResetReadPerformanceStats`](#func-db-resetreadperformancestats)
  - [`ReadPerformanceStats`](#type-readperformancestats)
- [DSN Utilities](#dsn-utilities)
  - [`BuildDSN`](#func-builddsn)
- [Constants & Error Sentinels](#constants--error-sentinels)

---

## Core Types

### `type DB`

`DB` wraps a `*sql.DB` instance to provide transparent page encryption management, key state retention, and cryptographic lifecycle controls.

```go
type DB struct {
    *sql.DB
    // Private fields manage locking, paths, memguard keys, and registry handles
}
```

---

### `type Options`

`Options` configures database connection parameters, cipher selection, page cache limits, and key rotation policies.

```go
type Options struct {
    Key                        string
    Cipher                     Cipher
    URIParameters              map[string]string
    JournalMode                string
    BusyTimeoutMillis          *int
    ManifestPath               string
    RotationPolicy             *RotationPolicy
    DecryptedPageCacheBytes    int64
    EnableReadPerformanceStats bool
}
```

| Field | Type | Description |
| :--- | :--- | :--- |
| `Key` | `string` | **Required.** Master passphrase or raw key string used to unlock the database manifest. |
| `Cipher` | `Cipher` | AEAD cipher algorithm (`CipherAES256GCM`, `CipherChaCha20Poly1305`, or `CipherXChaCha20Poly1305`). Defaults to `CipherAES256GCM` for new databases. |
| `URIParameters` | `map[string]string` | Custom SQLite URI query parameters appended to the DSN (e.g. `_mutex=no`). Direct key options are stripped. |
| `JournalMode` | `string` | Desired journal mode (`"WAL"` or `"MEMORY"`). Note: On-disk rollback journals (`DELETE`, `TRUNCATE`, `PERSIST`) are forbidden for security. |
| `BusyTimeoutMillis` | `*int` | Optional timeout in milliseconds for busy database lock waits. |
| `ManifestPath` | `string` | Optional explicit path to the `.encz` manifest file. Defaults to `<dbpath>.encz`. |
| `RotationPolicy` | `*RotationPolicy` | Custom automatic key rotation thresholds for KEK and DEKs. |
| `DecryptedPageCacheBytes` | `int64` | Memory budget in bytes for decrypted page LRU cache. Default: 128 MB (`128 << 20`). Set to `-1` to disable cache. |
| `EnableReadPerformanceStats` | `bool` | Enables atomic tracking of page cache hits/misses and AEAD metrics. |

---

### `type Cipher`

`Cipher` identifies the authenticated encryption algorithm used by a database.

```go
type Cipher string

const (
    CipherAES256GCM         Cipher = "aes-256-gcm"
    CipherChaCha20Poly1305  Cipher = "chacha20-poly1305"
    CipherXChaCha20Poly1305 Cipher = "xchacha20-poly1305"
    CipherChaChaPoly        Cipher = CipherChaCha20Poly1305  // Alias
    CipherXChaChaPoly       Cipher = CipherXChaCha20Poly1305 // Alias
)
```

---

## Database Lifecycle Management

### `func OpenSQLiteSeal`

```go
func OpenSQLiteSeal(path, key string) (*DB, error)
```

Opens or creates a `SQLiteSeal` encrypted database using default options (AES-256-GCM, 128 MB decrypted page cache, WAL mode).

**Example:**
```go
db, err := sqliteseal.OpenSQLiteSeal("app.db", "MySecretMasterPassphrase123!")
if err != nil {
    log.Fatalf("failed to open encrypted db: %v", err)
}
defer db.Close()
```

---

### `func OpenWithOptions`

```go
func OpenWithOptions(path string, opts Options) (*DB, error)
```

Opens or creates an encrypted database with granular configuration parameters.

**Example:**
```go
db, err := sqliteseal.OpenWithOptions("app.db", sqliteseal.Options{
    Key:                     "MySecretMasterPassphrase123!",
    Cipher:                  sqliteseal.CipherXChaCha20Poly1305,
    JournalMode:             "WAL",
    DecryptedPageCacheBytes: 256 << 20, // 256 MB
})
```

---

### `func (*DB) Close`

```go
func (db *DB) Close() error
```

Closes the underlying database connection, unregisters the CGO key registry handle, zeroes all key buffers in memory (`memguard`), and purges the decrypted page cache.

---

### `func (*DB) SQLDB`

```go
func (db *DB) SQLDB() *sql.DB
```

Returns the internal standard Go `*sql.DB` reference. Returns `nil` if `db` is `nil`.

---

## Key Rotation & Security Policy

### `func (*DB) ReKey`

```go
func (db *DB) ReKey(oldKey, newKey string) error
```

Re-encrypts the sidecar manifest's Master Key Envelope Key (KEK) with `newKey`. Does not require re-encrypting existing database pages on disk.

---

### `func (*DB) SetRotationPolicy`

```go
func (db *DB) SetRotationPolicy(policy RotationPolicy) error
```

Updates the key rotation thresholds stored in the sidecar manifest.

---

### `func (*DB) RotationStatus`

```go
func (db *DB) RotationStatus() (RotationInfo, error)
```

Returns current key rotation metadata, timestamps, active DEK key ID, and pending rotation flags.

---

### `type RotationPolicy`

```go
type RotationPolicy struct {
    KEKRotationDays  int `json:"kek_rotation_days"`  // Default: 7
    DEKRotationHours int `json:"dek_rotation_hours"` // Default: 24
}
```

---

### `type RotationInfo`

```go
type RotationInfo struct {
    ManifestPath                 string
    CreationTimestamp            time.Time
    LastKEKRotationTimestamp     time.Time
    NextKEKRotationDueTimestamp time.Time
    LastDEKRotationTimestamp     time.Time
    NextDEKRotationDueTimestamp time.Time
    ActiveDEKKeyID               uint32
    TotalDEKs                    int
    PendingDEKRotation           bool
    PendingKEKRotation           bool
}
```

---

## Backup & Recovery

### `func (*DB) Backup`

```go
func (db *DB) Backup(toFile string, opts BackupOptions) error
```

Creates a single encrypted zip archive at `toFile` containing atomic snapshots of the database file and sidecar manifest.

---

### `func RestoreBackup`

```go
func RestoreBackup(file, masterKey, toFolder string, overwriteExistingFile bool) error
```

Authenticates and unpacks an encrypted backup archive into a temporary staging folder, validates its database integrity and manifest consistency, and safely commits the restored database and manifest to `toFolder`.

---

### `type BackupOptions`

```go
type BackupOptions struct {
    Compression BackupCompression
}
```

---

### `type BackupCompression`

```go
type BackupCompression string

const (
    BackupCompressionStore   BackupCompression = "store"
    BackupCompressionDeflate BackupCompression = "deflate"
    BackupCompressionZstd    BackupCompression = "zstd"
)
```

---

## Database Conversion & Migration

### `func ConvertDB`

```go
func ConvertDB(srcPath, dstPath string, opts ConvertOptions) error
```

Performs offline conversion between plaintext SQLite databases and `SQLiteSeal` encrypted databases, or migrates between different ciphers/keys.

Supported Modes:
- **Plain SQLite → SQLiteSeal**: `SourceKey: ""` -> `TargetKey: "..."`, `TargetCipher: CipherAES256GCM`
- **Cipher Switch**: `SourceKey: "..."` -> `TargetCipher: CipherXChaCha20Poly1305`
- **SQLiteSeal → Plain SQLite**: `SourceKey: "..."` -> `TargetKey: ""`, `TargetCipher: ""`

---

### `type ConvertOptions`

```go
type ConvertOptions struct {
    SourceKey    string
    TargetKey    string
    TargetCipher Cipher
}
```

---

## Performance & Monitoring

### `func (*DB) ReadPerformanceStats`

```go
func (db *DB) ReadPerformanceStats() ReadPerformanceStats
```

Returns atomic counters for decrypted page reads, cache hits, misses, tag validations, and I/O byte counts.

---

### `func (*DB) ResetReadPerformanceStats`

```go
func (db *DB) ResetReadPerformanceStats()
```

Resets all read performance metrics to zero.

---

### `type ReadPerformanceStats`

```go
type ReadPerformanceStats struct {
    Hits           uint64
    Misses         uint64
    Decryptions    uint64
    Encryptions    uint64
    BytesRead      uint64
    BytesWritten   uint64
    CacheEvictions uint64
    TagValidations uint64
}
```

---

## DSN Utilities

### `func BuildDSN`

```go
func BuildDSN(path string, opts Options) (string, error)
```

Builds a standard SQLite URI connection string. Direct key parameters in DSNs are intentionally forbidden to prevent key leaks in logs.

---

## Constants & Error Sentinels

| Error Sentinel | Description |
| :--- | :--- |
| `ErrDBClosed` | Database handle is closed. |
| `ErrKeyRequired` | Encryption key string is missing or empty. |
| `ErrCurrentKeyMismatch` | Provided old key does not match active handle key during `ReKey`. |
| `ErrManifestMissing` | Required `.encz` sidecar manifest file was not found. |
| `ErrManifestMismatch` | Database UUID and manifest UUID do not match. |
| `ErrManifestInvalid` | Sidecar manifest content is corrupted or invalid. |
| `ErrManifestAuthFailed` | Failed to authenticate/decrypt manifest with provided key. |
| `ErrDirectKeyUnsupported` | Passing encryption keys in URI connection strings is forbidden. |
| `ErrFileBackedRequired` | SQLiteSeal only supports file-backed databases (no `:memory:`). |
| `ErrUnsafeJournalMode` | Rollback journals on disk are unencrypted; must use WAL or MEMORY. |
| `ErrRotationPolicyInvalid` | Rotation policy parameters are outside allowed bounds. |
| `ErrCipherUnsupported` | Requested cipher string is unrecognized. |
| `ErrCipherMismatch` | Specified cipher does not match cipher in manifest. |
| `ErrConvertSourceNotFound` | Source database path does not exist during `ConvertDB`. |
| `ErrConvertOutputExists` | Target output path already exists during `ConvertDB`. |
| `ErrConvertIntegrityFailed` | Converted database failed SQLite integrity check. |
| `ErrBackupTargetRequired` | Target archive path was not provided for `Backup`. |
| `ErrBackupOutputExists` | Target backup archive already exists. |
| `ErrBackupAuthFailed` | Authentication tag validation failed when extracting backup archive. |
