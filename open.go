package encz

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
}

func OpenWithOptions(path string, opts Options) (*DB, error) {
	if err := mustRegister(); err != nil {
		return nil, err
	}
	resolved, manifestPath, registryHandle, err := resolveOpenOptions(path, opts)
	if err != nil {
		return nil, err
	}
	sqlDB, err := openSQLDB(BuildDSN(path, resolved))
	if err != nil {
		destroyKeyRegistry(registryHandle)
		return nil, err
	}
	return &DB{
		DB:             sqlDB,
		path:           path,
		manifestPath:   manifestPath,
		key:            memguard.NewBufferFromBytes([]byte(opts.Key)),
		registryHandle: registryHandle,
	}, nil
}

func OpenEncz(path, key string) (*DB, error) {
	return OpenWithOptions(path, Options{Key: key})
}

func (db *DB) SQLDB() *sql.DB {
	if db == nil {
		return nil
	}
	return db.DB
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
	registryHandle := db.registryHandle
	db.registryHandle = 0
	db.mu.Unlock()
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

	payload, policy, err := loadManifest(db.manifestPath, oldKeyBuf)
	if err != nil {
		return err
	}
	now := timeNowUTC()
	applyKEKRotation(&payload, policy, now)
	if err := saveManifest(db.manifestPath, newKeyBuf, payload); err != nil {
		return err
	}
	if db.key != nil {
		db.key.Destroy()
	}
	db.key = memguard.NewBufferFromBytes([]byte(newKey))
	updateKeyRegistryMasterKey(db.registryHandle, db.key)
	return nil
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
	payload, _, err := loadManifest(db.manifestPath, db.key)
	if err != nil {
		return err
	}
	applyRotationPolicy(&payload, policy)
	if err := saveManifest(db.manifestPath, db.key, payload); err != nil {
		return err
	}
	return updateKeyRegistryManifest(db.registryHandle, payload, policy)
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
