package sqliteseal

import (
	"crypto/subtle"
	"database/sql"
	"sync"

	"github.com/awnumar/memguard"
)

type DB struct {
	*sql.DB

	mu             sync.RWMutex
	path           string
	manifestPath   string
	key            *memguard.LockedBuffer
	registryHandle uint64
	closed         bool
	replication    *replicationRuntime
}

func OpenWithOptions(path string, opts Options) (*DB, error) {
	if err := mustRegister(); err != nil {
		return nil, err
	}
	resolved, manifestPath, registryHandle, err := resolveOpenOptions(path, opts)
	if err != nil {
		return nil, err
	}
	sqlDB, err := openSQLDB(buildDSN(path, resolved))
	if err != nil {
		destroyKeyRegistry(registryHandle)
		return nil, err
	}
	db := &DB{
		DB:             sqlDB,
		path:           path,
		manifestPath:   manifestPath,
		key:            memguard.NewBufferFromBytes([]byte(opts.Key)),
		registryHandle: registryHandle,
	}
	if err := db.openReplication(opts.Replication); err != nil {
		_ = sqlDB.Close()
		destroyKeyRegistry(registryHandle)
		db.key.Destroy()
		return nil, err
	}
	return db, nil
}

// OpenSQLiteSeal opens or creates an encrypted SQLiteSeal database using the
// default options.
func OpenSQLiteSeal(path, key string) (*DB, error) {
	return OpenWithOptions(path, Options{Key: key})
}

// OpenEncz is retained for source compatibility.
// Deprecated: use OpenSQLiteSeal.
func OpenEncz(path, key string) (*DB, error) {
	return OpenSQLiteSeal(path, key)
}

func (db *DB) SQLDB() *sql.DB {
	if db == nil {
		return nil
	}
	return db.DB
}

// ReadPerformanceStats returns a point-in-time snapshot of encrypted page-read metrics.
func (db *DB) ReadPerformanceStats() ReadPerformanceStats {
	if db == nil {
		return ReadPerformanceStats{}
	}
	db.mu.RLock()
	handle, closed := db.registryHandle, db.closed
	db.mu.RUnlock()
	if closed {
		return ReadPerformanceStats{}
	}
	reg, ok := getKeyRegistry(handle)
	if !ok {
		return ReadPerformanceStats{}
	}
	return reg.readStats.snapshot()
}

// ResetReadPerformanceStats clears all encrypted page-read metrics.
func (db *DB) ResetReadPerformanceStats() {
	if db == nil {
		return
	}
	db.mu.RLock()
	handle, closed := db.registryHandle, db.closed
	db.mu.RUnlock()
	if closed {
		return
	}
	if reg, ok := getKeyRegistry(handle); ok {
		reg.readStats.reset()
	}
}

func (db *DB) Close() error {
	if db == nil {
		return nil
	}
	db.mu.Lock()
	if db.closed {
		db.mu.Unlock()
		return nil
	}
	db.closed = true
	if db.key != nil {
		db.key.Destroy()
		db.key = nil
	}
	sqlDB := db.DB
	repl := db.replication
	db.replication = nil
	registryHandle := db.registryHandle
	db.registryHandle = 0
	db.mu.Unlock()
	if repl != nil {
		repl.close()
	}
	err := sqlDB.Close()
	if registryHandle != 0 {
		destroyKeyRegistry(registryHandle)
	}
	return err
}

func (db *DB) ReKey(oldKey, newKey string) error {
	if oldKey == "" || newKey == "" {
		return ErrKeyRequired
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.closed {
		return ErrDBClosed
	}
	if db.key == nil || subtle.ConstantTimeCompare(db.key.Bytes(), []byte(oldKey)) != 1 {
		return ErrCurrentKeyMismatch
	}
	oldKeyBuf := memguard.NewBufferFromBytes([]byte(oldKey))
	defer oldKeyBuf.Destroy()
	newKeyBuf := memguard.NewBufferFromBytes([]byte(newKey))
	defer newKeyBuf.Destroy()

	reg, ok := getKeyRegistry(db.registryHandle)
	if !ok {
		return ErrDBClosed
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()

	return withManifestLock(db.manifestPath, func() error {
		payload, policy, err := loadManifest(db.manifestPath, oldKeyBuf)
		if err != nil {
			return err
		}
		applyKEKRotation(&payload, policy, timeNowUTC())
		if err := saveManifest(db.manifestPath, newKeyBuf, payload); err != nil {
			return err
		}
		nextKey := memguard.NewBufferFromBytes([]byte(newKey))
		if db.key != nil {
			db.key.Destroy()
		}
		db.key = nextKey
		if reg.masterKey != nil {
			reg.masterKey.Destroy()
		}
		reg.masterKey = cloneLockedBuffer(nextKey)
		reg.payload = payload
		reg.policy = policy
		return nil
	})
}

func (db *DB) SetRotationPolicy(policy RotationPolicy) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.closed {
		return ErrDBClosed
	}
	policy, err := validateRotationPolicy(policy)
	if err != nil {
		return err
	}
	reg, ok := getKeyRegistry(db.registryHandle)
	if !ok {
		return ErrDBClosed
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()

	return withManifestLock(db.manifestPath, func() error {
		payload, _, err := loadManifest(db.manifestPath, db.key)
		if err != nil {
			return err
		}
		applyRotationPolicy(&payload, policy)
		if err := saveManifest(db.manifestPath, db.key, payload); err != nil {
			return err
		}
		reg.payload = payload
		reg.policy = policy
		return nil
	})
}

func (db *DB) RotationStatus() (RotationInfo, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	if db.closed {
		return RotationInfo{}, ErrDBClosed
	}
	payload, policy, err := loadManifest(db.manifestPath, db.key)
	if err != nil {
		if manifestMissing(err) {
			return RotationInfo{ManifestPath: db.manifestPath}, ErrManifestMissing
		}
		return RotationInfo{}, err
	}
	return rotationInfoFromPayload(db.manifestPath, payload, policy), nil
}

func openSQLDB(dsn string) (*sql.DB, error) {
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
