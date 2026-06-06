# encz

`encz` is a Go database driver wrapper around `github.com/mattn/go-sqlite3` that marries **SQLite**'s SQL interface with **RocksDB**'s high-performance key-value storage engine. It provides page-level cryptographic encryption and optional page-level compression transparently.

## Architecture & Design

Instead of writing SQLite database pages directly to a traditional flat database file, `encz` intercepts SQLite page reads and writes via a custom VFS extension and routes them to a backing **RocksDB** instance:

- **Storage Mapping**: Each SQLite page is stored in RocksDB as a key-value pair, where the key is the 32-bit page number (`pgno`) and the value contains the page data.
- **Compression**: Page data is optionally compressed (using `zstd` or `deflate`) before encryption. This maximizes storage efficiency.
- **Encryption**: Compressed pages are encrypted using **AES-256-GCM**. Each encrypted page block stores its custom flags (4 bytes), nonce (12 bytes), GCM authentication tag (16 bytes), and the actual encrypted payload.

```
 SQLite Engine (SQL parsing, Query Planning, B-Trees)
                      │
                      ▼
         Custom SQLite VFS Extension (encz)
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
   Compression                  Decryption
(none, zstd, deflate)         (AES-256-GCM)
        │                           ▲
        ▼                           │
   Encryption                  Decompression
  (AES-256-GCM)            (none, zstd, deflate)
        │                           ▲
        └─────────────┬─────────────┘
                      │
                      ▼
                 RocksDB Engine
         (Sorted String Tables (SST) on disk)
```

## Features

- **Hybrid Engine**: SQL query capabilities of SQLite backed by the performant key-value LSM-tree architecture of RocksDB.
- **Strong Encryption**: Secure AES-256-GCM protection on every single page block.
- **Multiple Compression Algorithms**: Supports `zstd` (recommended), `deflate`, and `none` (uncompressed).
- **Concurrent Writes**: Excellent concurrency capabilities. For multi-threaded writes, it is recommended to set `db.SetMaxOpenConns(1)` in Go's `database/sql` pool to serialize commits and prevent transaction locking overhead.
- **Zero-Dependency Setup**: Bundles pre-compiled binary dependencies for Linux and Windows AMD64.

## Requirements

- CGO enabled.
- For **Linux AMD64** and **Windows AMD64**, the native library dependencies (`librocksdb`, `libgflags`, `libzstd`, `libz`) are pre-compiled and bundled directly within the `lib/` directory of this repository. No external library installations are required.
- For other platforms, the dependencies must be available to the Go toolchain (e.g. installed via system package manager).

## Install

```bash
go get github.com/marcgauthier/encz
```

## Usage

```go
package main

import (
	"database/sql"
	"log"

	"github.com/marcgauthier/encz"
)

func main() {
	// Open an encrypted and compressed SQLite+RocksDB database
	// Options: path, key, compression (e.g. "zstd", "deflate", "none")
	db, err := encz.OpenEncz("users.db", "Password123Password123Password123", "zstd")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// For write-heavy workloads with concurrent goroutines, serialize connections:
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		log.Fatal(err)
	}
}
```

- `encz.Open` opens a plain SQLite database through the same registered driver.
- `encz.OpenWithOptions` can be used to pass custom options, such as `JournalMode: "WAL"` or `BusyTimeoutMillis`.
