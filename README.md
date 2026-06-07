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
- `db.Backup("backup.zip", encz.BackupOptions{Compression: encz.BackupCompressionDeflate})` creates an encrypted backup container. Internally it builds a ZIP with an encrypted `.bak` database and matching `.bak.encz` manifest using the current manifest DEK set, then encrypts that ZIP with the supplied master key and removes the plaintext ZIP.
- `encz.TestBackup(file, masterKey, tempFolder)` decrypts an encrypted backup container, extracts it, opens the `.bak` database with the manifest-derived DEKs, and runs `PRAGMA integrity_check`.
- Opening fails with `encz.ErrManifestMissing` when a database file exists without its manifest.
- Opening fails with `encz.ErrManifestAuthFailed` when the manifest exists but the master key is wrong.
- In-memory paths and direct-key URI compatibility settings are rejected by the package helpers.

## Key Rotation

`encz` uses envelope encryption for file-backed databases:

- the master key derives a KEK with Argon2id
- the KEK decrypts `db.encz`
- the manifest stores every DEK ever used for the database
- each page stores the DEK key ID required to decrypt that page

Rotation policy is stored inside the encrypted manifest:

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

Behavior:

- `db.SetRotationPolicy(...)` persists new rotation settings into the encrypted manifest.
- `db.ReKey(oldKey, newKey)` re-encrypts the manifest with a new master key without rewriting database pages or changing stored DEKs.
- DEK rotation happens on the first write after the configured interval expires. A new DEK is generated, appended to the manifest with the next key ID, and used for subsequent rewritten pages.
- Existing pages remain readable with their original DEKs. The manifest keeps all prior DEKs indefinitely.
- `db.RotationStatus()` reports the persisted policy, current active DEK key ID, key count, and next due times.

## Compatibility

This release changes the page trailer format from 32 reserved bytes to 36 reserved bytes and changes the manifest schema from a single-DEK model to a multi-DEK model. Existing databases created with the older format are not automatically migrated by this package.
