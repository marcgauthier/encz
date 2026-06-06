package encz

import "database/sql"

func Open(path string) (*sql.DB, error) {
	if err := mustRegister(); err != nil {
		return nil, err
	}
	return openDSN(BuildDSN(path, Options{}))
}

func OpenWithOptions(path string, opts Options) (*sql.DB, error) {
	if err := mustRegister(); err != nil {
		return nil, err
	}
	return openDSN(BuildDSN(path, opts))
}

func OpenEncz(path, key string) (*sql.DB, error) {
	if err := mustRegister(); err != nil {
		return nil, err
	}
	return openDSN(BuildDSN(path, Options{Key: key}))
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
