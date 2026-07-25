module github.com/marcgauthier/SQLiteSeal-benchmark

go 1.25.0

require (
	github.com/marcgauthier/SQLiteSeal v0.0.0
	github.com/mattn/go-sqlite3 v1.14.48
	turso.tech/database/tursogo v0.7.1
)

require (
	github.com/awnumar/memcall v0.4.0 // indirect
	github.com/awnumar/memguard v0.23.0 // indirect
	github.com/ebitengine/purego v0.9.1 // indirect
	github.com/tursodatabase/turso-go-platform-libs v0.7.1 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)

replace github.com/marcgauthier/SQLiteSeal => ../
