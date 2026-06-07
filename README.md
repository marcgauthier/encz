# encz

`encz` is a Go wrapper around `github.com/mattn/go-sqlite3` that adds transparent page-level encryption to SQLite database files and stores envelope-protected key material in a `*.encz` sidecar manifest.

## Architecture

`encz` registers a custom SQLite VFS named `encz`. For file-backed databases, the master key unlocks a `db.encz` manifest that contains the full DEK set for the database. SQLite then opens the database through that VFS and page I/O is transformed in place on the flat database file.

- **Storage format**: Standard SQLite database and WAL files on disk, plus an encrypted `db.encz` sidecar manifest.
- **Reserved bytes**: `encz` reserves 36 bytes on each SQLite page.
- **Encryption**: Page payloads are encrypted with **AES-256-GCM**.
- **Per-page metadata**: The final 36 reserved bytes hold 4 bytes of flags, a 4-byte DEK key ID, a 12-byte nonce, and a 16-byte authentication tag.
- **Multi-DEK model**: Every page stores the DEK key ID used to encrypt it. Older DEKs remain in the manifest forever, so a single database can contain pages encrypted under different DEKs.
- **Encrypted-only API**: `encz` only supports file-backed encrypted databases. Plain SQLite files, in-memory databases, and direct-key compatibility paths are rejected by the package helpers.

```
 SQLite Engine (SQL parsing, query planning, B-trees)
                      |
                      v
         Custom SQLite VFS Extension (encz)
                      |
                      v
             AES-256-GCM encryption
                      |
                      v
           Flat SQLite database / WAL files
```

## Requirements

- Go 1.25+
- CGO enabled
- OpenSSL development/runtime support
- On Linux AMD64 and Windows AMD64, this repository includes bundled native libraries under `lib/`
- On other platforms, the native dependencies must be available to the Go toolchain

## Install

```bash
go get github.com/marcgauthier/encz
```

## Usage

```go
package main

import (
	"log"

	"github.com/marcgauthier/encz"
)

func main() {
	db, err := encz.OpenEncz("users.db", "Password123Password123Password123")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.SetMaxOpenConns(5)

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		log.Fatal(err)
	}

	if err := db.SetRotationPolicy(encz.RotationPolicy{
		KEKRotationDays:  30,
		DEKRotationHours: 24,
		AutoRewrap:       true,
		KeepPreviousKey:  true,
	}); err != nil {
		log.Fatal(err)
	}

	if err := db.ReKey("Password123Password123Password123", "NewPassword123NewPassword123"); err != nil {
		log.Fatal(err)
	}

	if err := db.Backup("users-backup.zip", encz.BackupOptions{Compression: encz.BackupCompressionDeflate}); err != nil {
		log.Fatal(err)
	}
}
```

## API Notes

- `encz.OpenEncz` opens an existing encrypted database when `<db>.encz` is present and creates both files when neither the database nor manifest exists.
- `encz.OpenWithOptions` returns `*encz.DB`, which wraps `*sql.DB` and adds manifest operations such as `ReKey`, `SetRotationPolicy`, `RotationStatus`, and `Backup`.
- Opening fails with `encz.ErrManifestMissing` when a database file exists without its manifest.
- Opening fails with `encz.ErrManifestAuthFailed` when the manifest exists but the master key is wrong.
- In-memory paths and direct-key URI compatibility settings are rejected by the package helpers.

## Backup & Restore

`encz` provides a robust, encrypted backup and restore mechanism designed to securely package the database and its envelope keys.

### Backing Up

The `Backup` method creates a single, encrypted `.zip` archive containing the `.bak` database file and its matching `.bak.encz` manifest.

```go
err := db.Backup("backup.zip", encz.BackupOptions{
	Compression: encz.BackupCompressionDeflate,
})
```

- **Encryption**: The archive is sealed using AES-256-GCM. A secondary key is derived from the active master key using a unique salt, separate from the primary database's KEK.
- **Payload**: Contains the database page-encrypted files and the manifest containing all historical DEKs.

### Testing Backups

Before performing a restore, you can verify the integrity of an archive using `TestBackup`.

```go
err := encz.TestBackup("backup.zip", "MasterKey123", "/tmp/restore-test")
```

This decrypts and unpacks the backup archive to a temporary directory, opens the database using the restored manifest, and runs `PRAGMA integrity_check`.

### Restoring Backups

The `RestoreBackup` function safely extracts and restores a database from an encrypted backup archive.

```go
err := encz.RestoreBackup("backup.zip", "MasterKey123", "/path/to/restore/dir", false)
```

- **Integrity Validation**: Decrypts the archive to a temporary location and executes `PRAGMA integrity_check` before copying files to the destination. If verification fails, the restore is aborted.
- **Overwrite Protection**: The final parameter (`overwriteExistingFile`) acts as a safety guard. If set to `false`, the restore process will fail if a database file or manifest already exists in the target directory, preventing accidental data loss.

## Public API Reference

Below is a summary of all public package-level functions and methods available in `encz`.

### Package-Level Functions

- **`Register() error`**  
  Registers the custom `encz` SQLite VFS and driver name with Go's `database/sql` package automatically.
- **`BuildDSN(path string, opts Options) string`**  
  Constructs a standard SQLite connection DSN containing the custom VFS configuration and options.
- **`BuildEnczDSN(path, key string) string`**  
  Constructs a simplified connection string using the default `encz` driver and master key.
- **`OpenEncz(path, key string) (*DB, error)`**  
  Opens or creates an encrypted database with default configurations and the specified master key.
- **`OpenWithOptions(path string, opts Options) (*DB, error)`**  
  Opens or creates an encrypted database using a customized `Options` configuration.
- **`TestBackup(file, masterKey, tempFolder string) error`**  
  Decrypts a backup archive and runs a full database integrity check to verify backup correctness.
- **`RestoreBackup(file, masterKey, toFolder string, overwriteExistingFile bool) error`**  
  Decrypts and restores the database and its manifest to a target folder, with overwrite protection.

### Database Handle Methods (`*DB`)

- **`SQLDB() *sql.DB`**  
  Returns the underlying database connection pool used for executing standard SQL queries.
- **`Close() error`**  
  Closes the database connections and securely purges/wipes all cryptographic keys from memory.
- **`ReKey(oldKey, newKey string) error`**  
  Changes the database master key by re-encrypting the manifest envelope with a new derived KEK.
- **`SetRotationPolicy(policy RotationPolicy) error`**  
  Updates and persists the key rotation settings inside the database's sidecar manifest.
- **`RotationStatus() (RotationInfo, error)`**  
  Returns the active rotation policy, DEK count, and when KEK/DEK rotations are next scheduled.
- **`Backup(toFile string, opts BackupOptions) error`**  
  Generates an encrypted ZIP backup of the active database and manifest.


## Key Rotation

`encz` utilizes envelope encryption to secure file-backed databases:

1. **Master Key**: The user-provided passphrase.
2. **Key Encryption Key (KEK)**: Derived from the master key using Argon2id, used to encrypt/decrypt the sidecar `db.encz` manifest.
3. **Data Encryption Keys (DEKs)**: Cryptographically secure 256-bit keys generated by the library, stored inside the manifest, and used to encrypt the actual SQLite database pages.

The rotation policy is configured per-database and stored inside the encrypted manifest:

```go
type RotationPolicy struct {
	KEKRotationDays  int
	DEKRotationHours int
	AutoRewrap       bool
	KeepPreviousKey  bool
}
```

Defaults for newly created databases:
- `KEKRotationDays`: `7`
- `DEKRotationHours`: `24`
- `AutoRewrap`: `true`
- `KeepPreviousKey`: `true`

---

### Master Key & KEK Rotation

* **Passphrase Changes (`ReKey`)**: Calling `db.ReKey(oldKey, newKey)` re-encrypts the manifest envelope with a new KEK derived from the new master key. This operation is instant and completely independent of the database size because **no database pages are rewritten or re-encrypted**.
* **Automatic KEK Rotation**: When `AutoRewrap` is enabled, the KEK is automatically rotated and the manifest re-encrypted on database opening if the `KEKRotationDays` interval has passed.

---

### Data Encryption Key (DEK) Rotation

`encz` implements a **multi-DEK architecture** with lazy, incremental DEK rotation:

* **Trigger**: DEK rotation is assessed automatically on write operations. When a transaction attempts to write pages to disk (including WAL checkpoints), `encz` checks if the active DEK has been in use longer than the configured `DEKRotationHours` interval.
* **Mechanism**: If the interval has expired:
  1. A new 32-byte DEK is cryptographically generated.
  2. The new DEK is appended to the encrypted manifest sidecar (`db.encz`) and assigned the next sequential Key ID.
  3. The new DEK becomes the active key.
* **Incremental Writes**: Only newly written or modified database pages are encrypted with the new active DEK. Unmodified pages are not touched. This avoids massive disk I/O and keeps rotation operations lightweight.
* **Key Resolution**: Each page's 36-byte trailer stores the specific Key ID used to encrypt its payload. When reading a page, the VFS reads the Key ID from the page trailer, retrieves the corresponding DEK from the manifest, and decrypts the payload.
* **Historical Retention**: Older DEKs are preserved in the encrypted manifest indefinitely so that older, unmodified pages remain fully readable.

---

### Key Status & Management

* `db.SetRotationPolicy(...)` persists new rotation settings into the encrypted manifest.
* `db.RotationStatus()` returns a `RotationInfo` struct containing the active policy, the current active DEK Key ID, the total count of DEKs in the manifest, and the next due times for KEK and DEK rotation.

## Compatibility

This release changes the page trailer format from 32 reserved bytes to 36 reserved bytes and changes the manifest schema from a single-DEK model to a multi-DEK model.

Release scope:

- This version is intended for newly created `encz` databases only.
- Existing databases created with the older format are not supported by this release.
- This package does not provide automatic migration, in-place upgrade, or compatibility fallback for older database files.
- Existing deployments must keep using the previous format until a separate migration path is introduced.
