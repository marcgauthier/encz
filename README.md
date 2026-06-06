# encz

`encz` is a Go database driver wrapper around `github.com/mattn/go-sqlite3` that adds transparent page-level encryption to standard SQLite database files and stores manifest-protected key material in a `*.encz` sidecar file.

## Architecture

`encz` registers a custom SQLite VFS named `encz`. For file-backed databases, the user key unlocks a `db.encz` manifest that contains the effective page-encryption key material. SQLite then opens the database through that VFS and page I/O is transformed in place on the flat database file.

- **Storage format**: Standard SQLite database and WAL files on disk, plus an encrypted `db.encz` sidecar manifest.
- **Reserved bytes**: `encz` uses SQLite's per-page reserved space. The current implementation reserves 32 bytes on each page.
- **Encryption**: Page payloads are encrypted with **AES-256-GCM** using a random DEK loaded from the manifest.
- **Per-page metadata**: The final 32 reserved bytes hold 4 bytes of flags, a 12-byte nonce, and a 16-byte authentication tag.

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

## Features

- **SQLite-compatible driver**: Uses the `database/sql` API through a registered `go-sqlite3` driver.
- **Per-page encryption**: AES-256-GCM protection on database pages.
- **WAL-aware VFS**: Handles main database and WAL page I/O through the same VFS layer.
- **Simple integration**: Open encrypted databases with `encz.OpenEncz` or use `OpenWithOptions` for more control. A key is required.
- **Envelope encryption**: The user/master key decrypts the encrypted `db.encz` manifest, which holds the effective page-encryption DEK.
- **Key rotation**: The manifest is rewrapped by default every 7 days without rewriting database pages.

## Requirements

- CGO enabled.
- OpenSSL development/runtime support.
- On Linux AMD64 and Windows AMD64, this repository includes bundled native libraries under `lib/`.
- On other platforms, the native dependencies must be available to the Go toolchain.

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
	// Open an encrypted SQLite database using the encz VFS.
	db, err := encz.OpenEncz("users.db", "Password123Password123Password123")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.SetMaxOpenConns(5)

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		log.Fatal(err)
	}
}
```

- `encz.Open` rejects missing keys with `encz.ErrKeyRequired`.
- `encz.OpenEncz` opens a manifest-backed encrypted database and creates `<db>.encz` when needed.
- `encz.OpenWithOptions` requires `Options.Key` for the manifest-backed path and can also pass options such as `JournalMode: "WAL"`, `BusyTimeoutMillis`, `ManifestPath`, and `RotationPolicy`.
- `encz.RotateManifestKey` rewraps the encrypted manifest with a new master key without rewriting the database pages.
- `encz.MigrateLegacyKeyedDatabase` upgrades an older direct-key database into the manifest-backed format without changing the underlying page key.

## Key Rotation

`encz` uses envelope encryption for file-backed databases:

- the user/master key derives a KEK with Argon2id
- the KEK decrypts `db.encz`
- the manifest stores the active DEK used to encrypt database and WAL pages

Rotation policy is configured with `Options.RotationPolicy`:

```go
type RotationPolicy struct {
    KEKRotationDays int
    AutoRewrap      bool
    KeepPreviousKey bool
}
```

Defaults:

- `KEKRotationDays`: `7`
- `AutoRewrap`: `true`
- `KeepPreviousKey`: `true`

Behavior:

- `AutoRewrap=true` rotates the manifest-wrapping key without rewriting page data.
- `RotateManifestKey` performs an explicit master-key rewrap.
- `MigrateLegacyKeyedDatabase` converts an older direct-key database into the manifest-backed format.

Recommended usage:

- keep `AutoRewrap` enabled for routine maintenance
- use `RotateManifestKey` when changing the master password or KMS-backed wrapping key
- use `MigrateLegacyKeyedDatabase` once when moving an existing database into the new manifest-backed format
