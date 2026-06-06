# encz

`encz` is a Go wrapper around `github.com/mattn/go-sqlite3` that adds transparent page-level encryption to SQLite database files and stores envelope-protected key material in a `*.encz` sidecar manifest.

## Architecture

`encz` registers a custom SQLite VFS named `encz`. For file-backed databases, the master key unlocks a `db.encz` manifest that contains the effective page-encryption DEK. SQLite then opens the database through that VFS and page I/O is transformed in place on the flat database file.

- **Storage format**: Standard SQLite database and WAL files on disk, plus an encrypted `db.encz` sidecar manifest.
- **Reserved bytes**: `encz` uses SQLite's per-page reserved space. The current implementation reserves 32 bytes on each page.
- **Encryption**: Page payloads are encrypted with **AES-256-GCM** using a random DEK loaded from the manifest.
- **Per-page metadata**: The final 32 reserved bytes hold 4 bytes of flags, a 12-byte nonce, and a 16-byte authentication tag.
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
		KEKRotationDays: 30,
		AutoRewrap:      true,
		KeepPreviousKey: true,
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
- `db.Backup("backup.zip", encz.BackupOptions{Compression: encz.BackupCompressionDeflate})` creates an encrypted backup container. Internally it builds a ZIP with an encrypted `.bak` database and matching `.bak.encz` manifest using the current manifest DEK, then encrypts that ZIP with the supplied master key and removes the plaintext ZIP.
- Opening fails with `encz.ErrManifestMissing` when a database file exists without its manifest.
- Opening fails with `encz.ErrManifestAuthFailed` when the manifest exists but the master key is wrong.
- In-memory paths and direct-key URI compatibility settings are rejected by the package helpers.

## Key Rotation

`encz` uses envelope encryption for file-backed databases:

- the master key derives a KEK with Argon2id
- the KEK decrypts `db.encz`
- the manifest stores the active DEK used to encrypt database and WAL pages

Rotation policy is stored inside the encrypted manifest:

```go
type RotationPolicy struct {
	KEKRotationDays int
	AutoRewrap      bool
	KeepPreviousKey bool
}
```

Defaults for newly created databases:

- `KEKRotationDays`: `7`
- `AutoRewrap`: `true`
- `KeepPreviousKey`: `true`

Behavior:

- `db.SetRotationPolicy(...)` persists new rotation settings into the encrypted manifest.
- `db.ReKey(oldKey, newKey)` re-encrypts the manifest with a new master key without rewriting database pages.
- `db.RotationStatus()` reports the persisted policy and next due time.
