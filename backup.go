package encz

import (
	"archive/zip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/awnumar/memguard"
	sqlite3 "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/argon2"
)

const (
	backupArchiveMagic     = "ENCZB1"
	backupArchiveVersion   = 1
	backupArchiveSaltSize  = 16
	backupArchiveNonceSize = 12
	backupArchiveKeySize   = 32
)

var (
	ErrBackupTargetRequired         = errors.New("encz: backup target path is required")
	ErrBackupOutputExists           = errors.New("encz: backup output already exists")
	ErrBackupCompressionUnsupported = errors.New("encz: backup compression is unsupported")
	ErrBackupArchiveInvalid         = errors.New("encz: backup archive is invalid")
)

type BackupOptions struct {
	Compression BackupCompression
}

type BackupCompression string

const (
	BackupCompressionStore   BackupCompression = "store"
	BackupCompressionDeflate BackupCompression = "deflate"
	BackupCompressionZstd    BackupCompression = "zstd"
)

func (db *DB) Backup(toFile string, opts BackupOptions) (err error) {
	if strings.TrimSpace(toFile) == "" {
		return ErrBackupTargetRequired
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	if db.closed {
		return ErrDBClosed
	}

	compression, err := normalizeBackupCompression(opts.Compression)
	if err != nil {
		return err
	}

	manifestExists, err := fileExists(db.manifestPath)
	if err != nil {
		return err
	}
	if !manifestExists {
		return ErrManifestMissing
	}

	payload, _, err := loadManifest(db.manifestPath, db.key)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(toFile), 0o755); err != nil {
		return err
	}
	if exists, err := fileExists(toFile); err != nil {
		return err
	} else if exists {
		return ErrBackupOutputExists
	}

	backupDBPath := backupTempDBPath(db.path, toFile)
	backupManifestPath := manifestPathFor(backupDBPath, Options{})
	zipTempPath := toFile + ".plainzip"

	cleanupPaths := []string{backupManifestPath, backupDBPath, zipTempPath}
	defer func() {
		for _, path := range cleanupPaths {
			_ = os.Remove(path)
		}
		if err != nil {
			_ = os.Remove(toFile)
		}
	}()

	for _, path := range append(cleanupPaths[:0:0], cleanupPaths...) {
		if path == "" {
			continue
		}
		exists, statErr := fileExists(path)
		if statErr != nil {
			return statErr
		}
		if exists {
			return fmt.Errorf("%w: %s", ErrBackupOutputExists, path)
		}
	}

	backupDSN := BuildDSN(backupDBPath, Options{URIParameters: map[string]string{
		"vfs":            "encz",
		"crypto_key_hex": payload.ActiveDEKHex,
	}})
	destDB, err := openSQLDB(backupDSN)
	if err != nil {
		return err
	}
	defer destDB.Close()
	if err := copyDatabasePages(context.Background(), db.DB, destDB); err != nil {
		return err
	}
	if _, err = destDB.Exec(`VACUUM`); err != nil {
		return err
	}

	manifestBytes, err := os.ReadFile(db.manifestPath)
	if err != nil {
		return err
	}
	if err = atomicWriteFile(backupManifestPath, manifestBytes, 0o600); err != nil {
		return err
	}

	if err = writeBackupArchive(zipTempPath, compression, backupDBPath, backupManifestPath); err != nil {
		return err
	}
	return encryptBackupArchive(zipTempPath, toFile, db.key)
}

func normalizeBackupCompression(mode BackupCompression) (BackupCompression, error) {
	switch mode {
	case "", BackupCompressionDeflate:
		return BackupCompressionDeflate, nil
	case BackupCompressionStore:
		return BackupCompressionStore, nil
	case BackupCompressionZstd:
		return "", fmt.Errorf("%w: %s", ErrBackupCompressionUnsupported, mode)
	default:
		return "", fmt.Errorf("%w: %s", ErrBackupCompressionUnsupported, mode)
	}
}

func backupTempDBPath(dbPath, archivePath string) string {
	base := filepath.Base(archivePath)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	if name == "" {
		name = "backup"
	}
	return filepath.Join(filepath.Dir(dbPath), name+".bak")
}

func testBackup(file, masterKey, tempFolder string) error {
	if strings.TrimSpace(file) == "" {
		return ErrBackupTargetRequired
	}
	if strings.TrimSpace(masterKey) == "" {
		return ErrKeyRequired
	}
	if strings.TrimSpace(tempFolder) == "" {
		return fmt.Errorf("encz: backup temp folder is required")
	}

	zipPath, err := decryptBackupArchive(file, masterKey, tempFolder)
	if err != nil {
		return err
	}

	dbPath, manifestPath, err := extractBackupArchive(zipPath, tempFolder)
	if err != nil {
		return err
	}

	keyBuf := memguard.NewBufferFromBytes([]byte(masterKey))
	defer keyBuf.Destroy()

	payload, _, err := loadManifest(manifestPath, keyBuf)
	if err != nil {
		return err
	}

	backupDSN := BuildDSN(dbPath, Options{URIParameters: map[string]string{
		"vfs":            "encz",
		"crypto_key_hex": payload.ActiveDEKHex,
	}})
	opened, err := openSQLDB(backupDSN)
	if err != nil {
		return err
	}
	defer opened.Close()

	var integrity string
	if err := opened.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return err
	}
	if integrity != "ok" {
		return fmt.Errorf("encz: backup integrity check failed: %s", integrity)
	}
	return nil
}

func extractBackupArchive(file, tempFolder string) (dbPath string, manifestPath string, err error) {
	if err := os.MkdirAll(tempFolder, 0o755); err != nil {
		return "", "", err
	}

	r, err := zip.OpenReader(file)
	if err != nil {
		return "", "", err
	}
	defer r.Close()

	for _, f := range r.File {
		target := filepath.Join(tempFolder, f.Name)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return "", "", err
		}
		if err := extractZipEntry(f, target); err != nil {
			return "", "", err
		}
		if strings.HasSuffix(f.Name, ".bak.encz") {
			manifestPath = target
			continue
		}
		if strings.HasSuffix(f.Name, ".bak") {
			dbPath = target
		}
	}

	if dbPath == "" {
		return "", "", fmt.Errorf("encz: backup archive missing .bak database")
	}
	if manifestPath == "" {
		return "", "", ErrManifestMissing
	}
	return dbPath, manifestPath, nil
}

func extractZipEntry(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, rc)
	return err
}

func decryptBackupArchive(file, masterKey, tempFolder string) (string, error) {
	if strings.TrimSpace(tempFolder) == "" {
		return "", fmt.Errorf("encz: backup temp folder is required")
	}
	if err := os.MkdirAll(tempFolder, 0o755); err != nil {
		return "", err
	}
	zipPath := filepath.Join(tempFolder, filepath.Base(file)+".zip")
	keyBuf := memguard.NewBufferFromBytes([]byte(masterKey))
	defer keyBuf.Destroy()
	if err := decryptBackupArchiveToFile(file, zipPath, keyBuf); err != nil {
		return "", err
	}
	return zipPath, nil
}

func encryptBackupArchive(plainZipPath, encryptedPath string, key *memguard.LockedBuffer) error {
	plain, err := os.ReadFile(plainZipPath)
	if err != nil {
		return err
	}
	hdr, kek, err := newBackupArchiveHeader(key)
	if err != nil {
		return err
	}
	sealed, err := sealBackupArchive(kek, hdr, plain)
	if err != nil {
		return err
	}
	buf := make([]byte, 0, backupArchiveHeaderSize()+len(sealed))
	buf = append(buf, []byte(backupArchiveMagic)...)
	buf = append(buf, backupArchiveVersion)
	buf = binary.LittleEndian.AppendUint32(buf, defaultArgonTime)
	buf = binary.LittleEndian.AppendUint32(buf, defaultArgonMemory)
	buf = append(buf, defaultArgonThreads)
	buf = append(buf, hdr.Salt[:]...)
	buf = append(buf, hdr.Nonce[:]...)
	buf = append(buf, sealed...)
	return atomicWriteFile(encryptedPath, buf, 0o600)
}

func decryptBackupArchiveToFile(encryptedPath, zipPath string, key *memguard.LockedBuffer) error {
	blob, err := os.ReadFile(encryptedPath)
	if err != nil {
		return err
	}
	hdr, ciphertext, err := parseBackupArchive(blob)
	if err != nil {
		return err
	}
	kek := deriveBackupArchiveKey(key, hdr)
	plain, err := openBackupArchive(kek, hdr, ciphertext)
	if err != nil {
		return err
	}
	return atomicWriteFile(zipPath, plain, 0o600)
}

func newBackupArchiveHeader(key *memguard.LockedBuffer) (backupArchiveHeader, []byte, error) {
	var hdr backupArchiveHeader
	hdr.Version = backupArchiveVersion
	hdr.ArgonTime = defaultArgonTime
	hdr.ArgonMemory = defaultArgonMemory
	hdr.ArgonThreads = defaultArgonThreads
	if _, err := rand.Read(hdr.Salt[:]); err != nil {
		return hdr, nil, err
	}
	if _, err := rand.Read(hdr.Nonce[:]); err != nil {
		return hdr, nil, err
	}
	return hdr, deriveBackupArchiveKey(key, hdr), nil
}

type backupArchiveHeader struct {
	Version      byte
	ArgonTime    uint32
	ArgonMemory  uint32
	ArgonThreads uint8
	Salt         [backupArchiveSaltSize]byte
	Nonce        [backupArchiveNonceSize]byte
}

func backupArchiveHeaderSize() int {
	return len(backupArchiveMagic) + 1 + 4 + 4 + 1 + backupArchiveSaltSize + backupArchiveNonceSize
}

func parseBackupArchive(blob []byte) (backupArchiveHeader, []byte, error) {
	var hdr backupArchiveHeader
	if len(blob) < backupArchiveHeaderSize()+16 {
		return hdr, nil, ErrBackupArchiveInvalid
	}
	if string(blob[:len(backupArchiveMagic)]) != backupArchiveMagic {
		return hdr, nil, ErrBackupArchiveInvalid
	}
	offset := len(backupArchiveMagic)
	hdr.Version = blob[offset]
	offset++
	if hdr.Version != backupArchiveVersion {
		return hdr, nil, ErrBackupArchiveInvalid
	}
	hdr.ArgonTime = binary.LittleEndian.Uint32(blob[offset:])
	offset += 4
	hdr.ArgonMemory = binary.LittleEndian.Uint32(blob[offset:])
	offset += 4
	hdr.ArgonThreads = blob[offset]
	offset++
	copy(hdr.Salt[:], blob[offset:offset+backupArchiveSaltSize])
	offset += backupArchiveSaltSize
	copy(hdr.Nonce[:], blob[offset:offset+backupArchiveNonceSize])
	offset += backupArchiveNonceSize
	return hdr, blob[offset:], nil
}

func deriveBackupArchiveKey(key *memguard.LockedBuffer, hdr backupArchiveHeader) []byte {
	return argon2.IDKey(key.Bytes(), hdr.Salt[:], hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads, backupArchiveKeySize)
}

func sealBackupArchive(kek []byte, hdr backupArchiveHeader, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, hdr.Nonce[:], plain, backupArchiveAAD(hdr)), nil
}

func openBackupArchive(kek []byte, hdr backupArchiveHeader, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, hdr.Nonce[:], ciphertext, backupArchiveAAD(hdr))
	if err != nil {
		return nil, ErrManifestAuthFailed
	}
	return plain, nil
}

func backupArchiveAAD(hdr backupArchiveHeader) []byte {
	buf := make([]byte, 0, len(backupArchiveMagic)+1+4+4+1+backupArchiveSaltSize)
	buf = append(buf, []byte(backupArchiveMagic)...)
	buf = append(buf, hdr.Version)
	buf = binary.LittleEndian.AppendUint32(buf, hdr.ArgonTime)
	buf = binary.LittleEndian.AppendUint32(buf, hdr.ArgonMemory)
	buf = append(buf, hdr.ArgonThreads)
	buf = append(buf, hdr.Salt[:]...)
	return buf
}

func copyDatabasePages(ctx context.Context, srcDB, destDB *sql.DB) error {
	srcConn, err := srcDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer srcConn.Close()

	destConn, err := destDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer destConn.Close()

	return srcConn.Raw(func(srcRaw any) error {
		srcSQLiteConn, ok := srcRaw.(*sqlite3.SQLiteConn)
		if !ok {
			return fmt.Errorf("encz: unexpected source SQLite connection type %T", srcRaw)
		}
		return destConn.Raw(func(destRaw any) error {
			destSQLiteConn, ok := destRaw.(*sqlite3.SQLiteConn)
			if !ok {
				return fmt.Errorf("encz: unexpected destination SQLite connection type %T", destRaw)
			}
			backup, err := destSQLiteConn.Backup("main", srcSQLiteConn, "main")
			if err != nil {
				return err
			}
			defer backup.Finish()

			done, err := backup.Step(-1)
			if err != nil {
				return err
			}
			if !done {
				return errors.New("encz: backup did not complete")
			}
			return nil
		})
	})
}

func writeBackupArchive(archivePath string, compression BackupCompression, paths ...string) error {
	f, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}

	zw := zip.NewWriter(f)
	closeWithErr := func() error {
		if err := zw.Close(); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	}

	for _, path := range paths {
		if err := addPathToZip(zw, path, compression); err != nil {
			_ = zw.Close()
			_ = f.Close()
			return err
		}
	}

	return closeWithErr()
}

func addPathToZip(zw *zip.Writer, path string, compression BackupCompression) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	hdr, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	hdr.Name = filepath.Base(path)
	switch compression {
	case BackupCompressionStore:
		hdr.Method = zip.Store
	default:
		hdr.Method = zip.Deflate
	}

	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	r, err := os.Open(path)
	if err != nil {
		return err
	}
	defer r.Close()

	_, err = io.Copy(w, r)
	return err
}
