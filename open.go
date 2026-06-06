package encz

import "database/sql"

func Open(path string) (*sql.DB, error) {
	return nil, ErrKeyRequired
}

func OpenWithOptions(path string, opts Options) (*sql.DB, error) {
	resolved, err := resolveOpenOptions(path, opts)
	if err != nil {
		return nil, err
	}
	if err := mustRegister(); err != nil {
		return nil, err
	}
	return openDSN(BuildDSN(path, resolved))
}

func OpenEncz(path, key string) (*sql.DB, error) {
	return OpenWithOptions(path, Options{Key: key})
}

func openDSN(dsn string) (*sql.DB, error) {
	db, err := sql.Open(DriverName, dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}
