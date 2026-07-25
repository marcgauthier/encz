package encz

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/awnumar/memguard"
)

const (
	maxBackupArchiveSize = int64(8 << 30)
	maxBackupEntrySize   = uint64(8 << 30)
	backupEntryCount     = 2
)

type restoreReplacement struct {
	source string
	target string
	backup string
}

// RestoreBackup authenticates and validates a backup in a private staging
// directory before committing either member to the destination.
func RestoreBackup(file, masterKey, toFolder string, overwriteExistingFile bool) error {
	if strings.TrimSpace(file) == "" {
		return ErrBackupTargetRequired
	}
	if strings.TrimSpace(masterKey) == "" {
		return ErrKeyRequired
	}
	if strings.TrimSpace(toFolder) == "" {
		return fmt.Errorf("encz: restore target folder is required")
	}
	if info, err := os.Lstat(toFolder); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("encz: restore target must be a real directory: %s", toFolder)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(toFolder, 0o700); err != nil {
		return err
	}

	stageDir, err := os.MkdirTemp(toFolder, ".encz-restore-stage-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stageDir)

	zipPath, err := decryptBackupArchive(file, masterKey, stageDir)
	if err != nil {
		return err
	}
	dbPath, manifestPath, err := extractValidatedBackupArchive(zipPath, filepath.Join(stageDir, "payload"))
	if err != nil {
		return err
	}
	if err := validateBackupDatabase(dbPath, manifestPath, masterKey); err != nil {
		return err
	}
	return commitRestoredFiles(toFolder, stageDir, []string{dbPath, manifestPath}, overwriteExistingFile)
}

func extractValidatedBackupArchive(file, destination string) (string, string, error) {
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return "", "", err
	}
	r, err := zip.OpenReader(file)
	if err != nil {
		return "", "", err
	}
	defer r.Close()
	if len(r.File) != backupEntryCount {
		return "", "", fmt.Errorf("%w: expected exactly %d files", ErrBackupArchiveInvalid, backupEntryCount)
	}

	var dbPath, manifestPath string
	for _, entry := range r.File {
		if entry.Name != filepath.Base(entry.Name) || !entry.FileInfo().Mode().IsRegular() {
			return "", "", fmt.Errorf("%w: invalid entry %q", ErrBackupArchiveInvalid, entry.Name)
		}
		if entry.UncompressedSize64 > maxBackupEntrySize {
			return "", "", fmt.Errorf("%w: entry %q exceeds size limit", ErrBackupArchiveInvalid, entry.Name)
		}
		target := filepath.Join(destination, entry.Name)
		switch {
		case strings.HasSuffix(entry.Name, ".bak.encz"):
			if manifestPath != "" {
				return "", "", fmt.Errorf("%w: duplicate manifest", ErrBackupArchiveInvalid)
			}
			manifestPath = target
		case strings.HasSuffix(entry.Name, ".bak"):
			if dbPath != "" {
				return "", "", fmt.Errorf("%w: duplicate database", ErrBackupArchiveInvalid)
			}
			dbPath = target
		default:
			return "", "", fmt.Errorf("%w: unexpected entry %q", ErrBackupArchiveInvalid, entry.Name)
		}
		if err := extractBoundedRegularFile(entry, target); err != nil {
			return "", "", err
		}
	}
	if dbPath == "" {
		return "", "", fmt.Errorf("%w: missing .bak database", ErrBackupArchiveInvalid)
	}
	if manifestPath == "" {
		return "", "", ErrManifestMissing
	}
	if manifestPath != dbPath+".encz" {
		return "", "", fmt.Errorf("%w: database and manifest names do not match", ErrBackupArchiveInvalid)
	}
	return dbPath, manifestPath, nil
}

func extractBoundedRegularFile(entry *zip.File, target string) error {
	rc, err := entry.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		out.Close()
		if !ok {
			os.Remove(target)
		}
	}()
	written, err := io.Copy(out, io.LimitReader(rc, int64(maxBackupEntrySize)+1))
	if err != nil {
		return err
	}
	if written > int64(maxBackupEntrySize) {
		return fmt.Errorf("%w: entry %q exceeds size limit", ErrBackupArchiveInvalid, entry.Name)
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func validateBackupDatabase(dbPath, manifestPath, masterKey string) error {
	key := memguard.NewBufferFromBytes([]byte(masterKey))
	defer key.Destroy()
	payload, policy, err := loadManifest(manifestPath, key)
	if err != nil {
		return err
	}
	handle, err := registerKeyRegistry(manifestPath, key, payload, policy, false)
	if err != nil {
		return err
	}
	defer destroyKeyRegistry(handle)
	opened, err := openSQLDB(buildDSN(dbPath, applyRegistryToOptions(Options{Cipher: payload.Cipher}, handle)))
	if err != nil {
		return err
	}
	var integrity string
	queryErr := opened.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
	closeErr := opened.Close()
	if queryErr != nil {
		return queryErr
	}
	if closeErr != nil {
		return closeErr
	}
	if integrity != "ok" {
		return fmt.Errorf("encz: backup integrity check failed: %s", integrity)
	}
	return nil
}

func commitRestoredFiles(toFolder, stageDir string, sources []string, overwrite bool) error {
	replacements := make([]restoreReplacement, 0, len(sources))
	for i, source := range sources {
		target := filepath.Join(toFolder, filepath.Base(source))
		info, err := os.Lstat(target)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return fmt.Errorf("encz: restore target is not a regular file: %s", target)
			}
			if !overwrite {
				return fmt.Errorf("encz: restore target file already exists: %s", target)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		replacements = append(replacements, restoreReplacement{
			source: source,
			target: target,
			backup: filepath.Join(stageDir, fmt.Sprintf("rollback-%d", i)),
		})
	}

	committed := 0
	for i := range replacements {
		item := &replacements[i]
		if _, err := os.Lstat(item.target); err == nil {
			if err := os.Rename(item.target, item.backup); err != nil {
				rollbackRestoredFiles(replacements, committed)
				return err
			}
		}
		if err := os.Rename(item.source, item.target); err != nil {
			rollbackRestoredFiles(replacements, committed)
			if _, statErr := os.Lstat(item.backup); statErr == nil {
				_ = os.Rename(item.backup, item.target)
			}
			return err
		}
		committed++
	}
	if err := syncParentDir(toFolder); err != nil {
		rollbackRestoredFiles(replacements, committed)
		return err
	}
	for _, item := range replacements {
		if item.backup != "" {
			_ = secureRemoveFile(item.backup)
		}
	}
	return nil
}

func rollbackRestoredFiles(items []restoreReplacement, committed int) {
	for i := committed - 1; i >= 0; i-- {
		_ = os.Remove(items[i].target)
		if _, err := os.Lstat(items[i].backup); err == nil {
			_ = os.Rename(items[i].backup, items[i].target)
		}
	}
}
