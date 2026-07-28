package sqliteseal

import (
	"database/sql"
	"fmt"
	"sync"

	sqlite3 "github.com/mattn/go-sqlite3"
)

const (
	DriverName       = "sqliteseal-sqlite3"
	LegacyDriverName = "encz-sqlite3"
)

var (
	registerDriverOnce sync.Once
	registerDriverErr  error
)

func init() {
	registerDriverErr = Register()
}

func Register() error {
	registerDriverOnce.Do(func() {
		if err := registerEncz(); err != nil {
			registerDriverErr = err
			return
		}
		driver := &sqlite3.SQLiteDriver{
			ConnectHook: func(conn *sqlite3.SQLiteConn) error {
				if err := registerEncz(); err != nil {
					return err
				}
				if err := registerReplicationConnection(conn); err != nil {
					return err
				}
				_, err := conn.Exec("PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY", nil)
				return err
			},
		}
		sql.Register(DriverName, driver)
		sql.Register(LegacyDriverName, driver)
	})
	return registerDriverErr
}

func mustRegister() error {
	if err := Register(); err != nil {
		return fmt.Errorf("register %s: %w", DriverName, err)
	}
	return nil
}
