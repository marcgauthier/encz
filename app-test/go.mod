module github.com/marcgauthier/SQLiteSeal/app-test

go 1.25.0

require (
	github.com/marcgauthier/SQLiteSeal v0.0.0
	github.com/mattn/go-sqlite3 v1.14.48
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/awnumar/memcall v0.4.0 // indirect
	github.com/awnumar/memguard v0.23.0 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.38.0 // indirect
)

replace github.com/marcgauthier/SQLiteSeal => ..
