package encz

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	manifestMagic                 = "ENCZK1"
	manifestVersion               = 1
	manifestSaltSize              = 16
	manifestNonceSize             = 12
	manifestKEKSize               = 32
	defaultKEKRotationDays        = 7
	defaultArgonTime       uint32 = 3
	defaultArgonMemory     uint32 = 64 * 1024
	defaultArgonThreads    uint8  = 4
)

var (
	ErrKeyRequired        = errors.New("encz: encryption key is required")
	ErrManifestMissing    = errors.New("encz: manifest file is required")
	ErrManifestMismatch   = errors.New("encz: database and manifest files are inconsistent")
	ErrManifestInvalid    = errors.New("encz: manifest is invalid")
	ErrManifestAuthFailed = errors.New("encz: manifest authentication failed")
	ErrAlreadyMigrated    = errors.New("encz: database already uses a manifest")
)

type RotationPolicy struct {
	KEKRotationDays int
	AutoRewrap      bool
	KeepPreviousKey bool
}

type RotationInfo struct {
	ManifestPath         string
	Exists               bool
	KEKRotationDue       bool
	LastKEKRotationAt    time.Time
	NextKEKRotationDueAt time.Time
	KEKRotationDays      int
	ActiveDEKID          string
	HasPreviousKey       bool
}

type manifestHeader struct {
	Version      byte
	ArgonTime    uint32
	ArgonMemory  uint32
	ArgonThreads uint8
	Salt         [manifestSaltSize]byte
	Nonce        [manifestNonceSize]byte
}

type manifestKeySlot struct {
	DEKID    string    `json:"dek_id"`
	DEKHex   string    `json:"dek_hex"`
	StoredAt time.Time `json:"stored_at"`
}

type manifestPayload struct {
	DBUUID               string           `json:"db_uuid"`
	ActiveDEKID          string           `json:"active_dek_id"`
	ActiveDEKHex         string           `json:"active_dek_hex"`
	CreatedAt            time.Time        `json:"created_at"`
	LastKEKRotationAt    time.Time        `json:"last_kek_rotation_at"`
	NextKEKRotationDueAt time.Time        `json:"next_kek_rotation_due_at"`
	KEKRotationDays      int              `json:"kek_rotation_days"`
	PreviousKeySlot      *manifestKeySlot `json:"previous_key_slot,omitempty"`
}

func RotationStatus(path string, opts Options) (RotationInfo, error) {
	if opts.Key == "" {
		return RotationInfo{}, ErrKeyRequired
	}
	if isMemoryPath(path, opts) {
		return RotationInfo{}, errors.New("encz: rotation status is unavailable for in-memory databases")
	}
	manifestPath := manifestPathFor(path, opts)
	payload, _, err := loadManifest(manifestPath, opts.Key)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return RotationInfo{ManifestPath: manifestPath}, ErrManifestMissing
		}
		return RotationInfo{}, err
	}
	return RotationInfo{
		ManifestPath:         manifestPath,
		Exists:               true,
		KEKRotationDue:       time.Now().UTC().After(payload.NextKEKRotationDueAt) || time.Now().UTC().Equal(payload.NextKEKRotationDueAt),
		LastKEKRotationAt:    payload.LastKEKRotationAt,
		NextKEKRotationDueAt: payload.NextKEKRotationDueAt,
		KEKRotationDays:      payload.KEKRotationDays,
		ActiveDEKID:          payload.ActiveDEKID,
		HasPreviousKey:       payload.PreviousKeySlot != nil,
	}, nil
}

func RotateManifestKey(path, oldKey, newKey string, opts Options) error {
	if oldKey == "" || newKey == "" {
		return ErrKeyRequired
	}
	if isMemoryPath(path, opts) {
		return errors.New("encz: manifest rotation is unavailable for in-memory databases")
	}
	manifestPath := manifestPathFor(path, opts)
	payload, policy, err := loadManifest(manifestPath, oldKey)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	applyKEKRotation(&payload, policy, now)
	return saveManifest(manifestPath, newKey, payload)
}

func MigrateLegacyKeyedDatabase(path string, oldKey string, opts Options) error {
	if oldKey == "" || opts.Key == "" {
		return ErrKeyRequired
	}
	if isMemoryPath(path, opts) {
		return errors.New("encz: legacy migration is unavailable for in-memory databases")
	}
	manifestPath := manifestPathFor(path, opts)
	if _, err := os.Stat(manifestPath); err == nil {
		return ErrAlreadyMigrated
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return err
		}
		return err
	}
	if err := mustRegister(); err != nil {
		return err
	}
	legacyOpts := Options{
		Key:               oldKey,
		URIParameters:     cloneURIParameters(opts.URIParameters),
		JournalMode:       opts.JournalMode,
		BusyTimeoutMillis: opts.BusyTimeoutMillis,
	}
	db, err := openDSN(BuildDSN(path, legacyOpts))
	if err != nil {
		return err
	}
	defer db.Close()
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return err
	}
	if integrity != "ok" {
		return fmt.Errorf("encz: legacy database integrity check failed: %s", integrity)
	}
	payload := newManifestPayload(defaultRotationPolicy(opts.RotationPolicy), hex.EncodeToString(legacyDEKFromPassphrase(oldKey)), time.Now().UTC())
	return saveManifest(manifestPath, opts.Key, payload)
}

func resolveOpenOptions(path string, opts Options) (Options, error) {
	if opts.Key == "" {
		if hasDirectKeyConfig(opts) {
			return opts, nil
		}
		return Options{}, ErrKeyRequired
	}
	if isMemoryPath(path, opts) {
		return applyDEKToOptions(opts, hex.EncodeToString(legacyDEKFromPassphrase(opts.Key))), nil
	}
	manifestPath := manifestPathFor(path, opts)
	dbExists, err := fileExists(path)
	if err != nil {
		return Options{}, err
	}
	manifestExists, err := fileExists(manifestPath)
	if err != nil {
		return Options{}, err
	}
	createAllowed := modeAllowsCreate(opts)
	if !dbExists && !manifestExists {
		if !createAllowed {
			return Options{}, os.ErrNotExist
		}
		payload := newManifestPayload(defaultRotationPolicy(opts.RotationPolicy), randomDEKHex(), time.Now().UTC())
		if err := saveManifest(manifestPath, opts.Key, payload); err != nil {
			return Options{}, err
		}
		return applyDEKToOptions(opts, payload.ActiveDEKHex), nil
	}
	if dbExists && !manifestExists {
		return Options{}, ErrManifestMissing
	}
	if !dbExists && manifestExists {
		return Options{}, ErrManifestMismatch
	}
	payload, policy, err := loadManifest(manifestPath, opts.Key)
	if err != nil {
		return Options{}, err
	}
	now := time.Now().UTC()
	if policy.AutoRewrap && (now.After(payload.NextKEKRotationDueAt) || now.Equal(payload.NextKEKRotationDueAt)) {
		applyKEKRotation(&payload, policy, now)
		if err := saveManifest(manifestPath, opts.Key, payload); err != nil {
			return Options{}, err
		}
	}
	return applyDEKToOptions(opts, payload.ActiveDEKHex), nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func modeAllowsCreate(opts Options) bool {
	mode := opts.URIParameters["mode"]
	switch mode {
	case "", "rwc", "memory":
		return true
	default:
		return false
	}
}

func manifestPathFor(path string, opts Options) string {
	if opts.ManifestPath != "" {
		return opts.ManifestPath
	}
	return path + ".encz"
}

func isMemoryPath(path string, opts Options) bool {
	if path == ":memory:" {
		return true
	}
	if opts.URIParameters["mode"] == "memory" {
		return true
	}
	return false
}

func hasDirectKeyConfig(opts Options) bool {
	if len(opts.URIParameters) == 0 {
		return false
	}
	return opts.URIParameters["crypto_key"] != "" || opts.URIParameters["crypto_key_hex"] != "" || opts.URIParameters["crypto_key_env"] != ""
}

func cloneURIParameters(src map[string]string) map[string]string {
	if len(src) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(src)+2)
	for k, v := range src {
		out[k] = v
	}
	return out
}

func applyDEKToOptions(opts Options, dekHex string) Options {
	resolved := opts
	resolved.Key = ""
	resolved.URIParameters = cloneURIParameters(opts.URIParameters)
	resolved.URIParameters["vfs"] = "encz"
	resolved.URIParameters["crypto_key_hex"] = dekHex
	delete(resolved.URIParameters, "crypto_key")
	delete(resolved.URIParameters, "crypto_key_env")
	return resolved
}

func defaultRotationPolicy(policy *RotationPolicy) RotationPolicy {
	out := RotationPolicy{
		KEKRotationDays: defaultKEKRotationDays,
		AutoRewrap:      true,
		KeepPreviousKey: true,
	}
	if policy == nil {
		return out
	}
	if policy.KEKRotationDays > 0 {
		out.KEKRotationDays = policy.KEKRotationDays
	}
	out.AutoRewrap = policy.AutoRewrap
	out.KeepPreviousKey = policy.KeepPreviousKey
	return out
}

func newManifestPayload(policy RotationPolicy, dekHex string, now time.Time) manifestPayload {
	return manifestPayload{
		DBUUID:               randomID(),
		ActiveDEKID:          "dek-" + now.UTC().Format("20060102T150405Z"),
		ActiveDEKHex:         dekHex,
		CreatedAt:            now,
		LastKEKRotationAt:    now,
		NextKEKRotationDueAt: now.Add(time.Duration(policy.KEKRotationDays) * 24 * time.Hour),
		KEKRotationDays:      policy.KEKRotationDays,
	}
}

func applyKEKRotation(payload *manifestPayload, policy RotationPolicy, now time.Time) {
	if policy.KeepPreviousKey {
		payload.PreviousKeySlot = &manifestKeySlot{
			DEKID:    payload.ActiveDEKID,
			DEKHex:   payload.ActiveDEKHex,
			StoredAt: payload.LastKEKRotationAt,
		}
	} else {
		payload.PreviousKeySlot = nil
	}
	payload.LastKEKRotationAt = now
	payload.NextKEKRotationDueAt = now.Add(time.Duration(payload.KEKRotationDays) * 24 * time.Hour)
}

func loadManifest(path string, passphrase string) (manifestPayload, RotationPolicy, error) {
	var payload manifestPayload
	blob, err := os.ReadFile(path)
	if err != nil {
		return payload, RotationPolicy{}, err
	}
	hdr, ciphertext, err := parseManifest(blob)
	if err != nil {
		return payload, RotationPolicy{}, err
	}
	kek := deriveKEK(passphrase, hdr)
	plain, err := decryptManifestPayload(kek, hdr, ciphertext)
	if err != nil {
		return payload, RotationPolicy{}, err
	}
	if err := json.Unmarshal(plain, &payload); err != nil {
		return payload, RotationPolicy{}, ErrManifestInvalid
	}
	if payload.ActiveDEKHex == "" || payload.ActiveDEKID == "" || payload.KEKRotationDays <= 0 {
		return payload, RotationPolicy{}, ErrManifestInvalid
	}
	return payload, RotationPolicy{
		KEKRotationDays: payload.KEKRotationDays,
		AutoRewrap:      true,
		KeepPreviousKey: payload.PreviousKeySlot != nil,
	}, nil
}

func saveManifest(path string, passphrase string, payload manifestPayload) error {
	hdr := manifestHeader{
		Version:      manifestVersion,
		ArgonTime:    defaultArgonTime,
		ArgonMemory:  defaultArgonMemory,
		ArgonThreads: defaultArgonThreads,
	}
	if _, err := rand.Read(hdr.Salt[:]); err != nil {
		return err
	}
	if _, err := rand.Read(hdr.Nonce[:]); err != nil {
		return err
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	kek := deriveKEK(passphrase, hdr)
	sealed, err := encryptManifestPayload(kek, hdr, plain)
	if err != nil {
		return err
	}
	buf := make([]byte, 0, manifestHeaderSize()+len(sealed))
	buf = append(buf, []byte(manifestMagic)...)
	buf = append(buf, hdr.Version)
	buf = binary.LittleEndian.AppendUint32(buf, hdr.ArgonTime)
	buf = binary.LittleEndian.AppendUint32(buf, hdr.ArgonMemory)
	buf = append(buf, hdr.ArgonThreads)
	buf = append(buf, hdr.Salt[:]...)
	buf = append(buf, hdr.Nonce[:]...)
	buf = append(buf, sealed...)
	return atomicWriteFile(path, buf, 0o600)
}

func manifestHeaderSize() int {
	return len(manifestMagic) + 1 + 4 + 4 + 1 + manifestSaltSize + manifestNonceSize
}

func parseManifest(blob []byte) (manifestHeader, []byte, error) {
	var hdr manifestHeader
	if len(blob) < manifestHeaderSize()+16 {
		return hdr, nil, ErrManifestInvalid
	}
	if string(blob[:len(manifestMagic)]) != manifestMagic {
		return hdr, nil, ErrManifestInvalid
	}
	offset := len(manifestMagic)
	hdr.Version = blob[offset]
	offset++
	if hdr.Version != manifestVersion {
		return hdr, nil, ErrManifestInvalid
	}
	hdr.ArgonTime = binary.LittleEndian.Uint32(blob[offset:])
	offset += 4
	hdr.ArgonMemory = binary.LittleEndian.Uint32(blob[offset:])
	offset += 4
	hdr.ArgonThreads = blob[offset]
	offset++
	copy(hdr.Salt[:], blob[offset:offset+manifestSaltSize])
	offset += manifestSaltSize
	copy(hdr.Nonce[:], blob[offset:offset+manifestNonceSize])
	offset += manifestNonceSize
	return hdr, blob[offset:], nil
}

func deriveKEK(passphrase string, hdr manifestHeader) []byte {
	return argon2.IDKey([]byte(passphrase), hdr.Salt[:], hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads, manifestKEKSize)
}

func encryptManifestPayload(kek []byte, hdr manifestHeader, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, hdr.Nonce[:], plain, manifestAAD(hdr)), nil
}

func decryptManifestPayload(kek []byte, hdr manifestHeader, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, hdr.Nonce[:], ciphertext, manifestAAD(hdr))
	if err != nil {
		return nil, ErrManifestAuthFailed
	}
	return plain, nil
}

func manifestAAD(hdr manifestHeader) []byte {
	buf := make([]byte, 0, len(manifestMagic)+1+4+4+1+manifestSaltSize)
	buf = append(buf, []byte(manifestMagic)...)
	buf = append(buf, hdr.Version)
	buf = binary.LittleEndian.AppendUint32(buf, hdr.ArgonTime)
	buf = binary.LittleEndian.AppendUint32(buf, hdr.ArgonMemory)
	buf = append(buf, hdr.ArgonThreads)
	buf = append(buf, hdr.Salt[:]...)
	return buf
}

func randomDEKHex() string {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		panic(err)
	}
	return hex.EncodeToString(dek)
}

func randomID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

func legacyDEKFromPassphrase(passphrase string) []byte {
	sum := sha256.Sum256([]byte(passphrase))
	return sum[:]
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".encz-manifest-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
