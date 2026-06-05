# encz

`encz` is a Go wrapper around `github.com/mattn/go-sqlite3` that statically
compiles the SQLite `encz` VFS extension into the process and exposes it
through `database/sql`.

## Features

- Plain SQLite access through a custom driver.
- `encz`-backed encrypted/compressed databases using `vfs=encz`.
- DSN helpers for `crypto_key`, `crypto_compression`, and related URI params.

## Requirements

- CGO enabled.
- Native link dependencies available to the Go toolchain: `libcrypto`,
  `libzstd`, and `libz`.

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
	db, err := encz.OpenEncz("users.db", "secret", "zstd")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		log.Fatal(err)
	}
}
```

`encz.Open` opens a plain SQLite database through the same registered driver.
`encz.OpenWithOptions` can be used when you need extra SQLite URI parameters.
