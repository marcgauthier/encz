# encz

`encz` is a Go database driver wrapper around `github.com/mattn/go-sqlite3` that adds transparent page-level encryption to standard SQLite database files.

## Architecture

`encz` registers a custom SQLite VFS named `encz`. When a `crypto_key` is supplied, SQLite opens the database through that VFS and page I/O is transformed in place on the flat database file.

- **Storage format**: Standard SQLite database and WAL files on disk.
- **Reserved bytes**: `encz` uses SQLite's per-page reserved space. The current implementation reserves 32 bytes on each page.
- **Encryption**: Page payloads are encrypted with **AES-256-GCM**.
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
- **Simple integration**: Open encrypted databases with `encz.OpenEncz` or use `OpenWithOptions` for more control.

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

	// For write-heavy workloads, serializing connections is often simpler.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		log.Fatal(err)
	}
}
```

- `encz.Open` opens a plain SQLite database through the same registered driver.
- `encz.OpenEncz` opens a database with `vfs=encz` and a `crypto_key`.
- `encz.OpenWithOptions` can be used to pass options such as `JournalMode: "WAL"` or `BusyTimeoutMillis`.
