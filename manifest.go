package encz

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
)

const (
	manifestMagic                  = "ENCZK3"
	manifestVersion                = 3
	manifestSaltSize               = 16
	manifestNonceSize              = 24
	manifestKEKSize                = 32
	defaultKEKRotationDays         = 7
	defaultDEKRotationHours        = 24
	defaultArgonTime        uint32 = 3
	defaultArgonMemory      uint32 = 64 * 1024
	defaultArgonThreads     uint8  = 4
	maxArgonTime            uint32 = 6
	maxArgonMemory          uint32 = 256 * 1024
	maxArgonThreads         uint8  = 16
)

// testArgonOverride enables fast Argon2id parameters for testing.
// Set to true in test init functions; must not be used in production.
var testArgonOverride bool

func getArgonParams() (uint32, uint32, uint8) {
	if testArgonOverride {
		return 1, 1024, 1
	}
	return defaultArgonTime, defaultArgonMemory, defaultArgonThreads
}

var (
	ErrKeyRequired           = errors.New("encz: encryption key is required")
	ErrManifestMissing       = errors.New("encz: manifest file is required")
	ErrManifestMismatch      = errors.New("encz: database and manifest files are inconsistent")
	ErrManifestInvalid       = errors.New("encz: manifest is invalid")
	ErrManifestAuthFailed    = errors.New("encz: manifest authentication failed")
	ErrDirectKeyUnsupported  = errors.New("encz: direct key configuration is unsupported")
	ErrFileBackedRequired    = errors.New("encz: only file-backed encrypted databases are supported")
	ErrUnsafeJournalMode     = errors.New("encz: on-disk rollback journals are not encrypted; use WAL or MEMORY")
	ErrRotationPolicyInvalid = errors.New("encz: rotation policy is invalid")
	ErrDBClosed              = errors.New("encz: database handle is closed")
	ErrCurrentKeyMismatch    = errors.New("encz: old key does not match the active handle key")
)

type RotationPolicy struct {
	KEKRotationDays  int
	DEKRotationHours int
	AutoRewrap       bool
	KeepPreviousKey  bool
}

type RotationInfo struct {
	ManifestPath         string
	Exists               bool
	KEKRotationDue       bool
	DEKRotationDue       bool
	LastKEKRotationAt    time.Time
	NextKEKRotationDueAt time.Time
	KEKRotationDays      int
	LastDEKRotationAt    time.Time
	NextDEKRotationDueAt time.Time
	DEKRotationHours     int
	ActiveDEKKeyID       uint32
	DEKCount             int
	HasPreviousKey       bool
	AutoRewrap           bool
	KeepPreviousKey      bool
}

type manifestHeader struct {
	Version      byte
	Cipher       Cipher
	ArgonTime    uint32
	ArgonMemory  uint32
	ArgonThreads uint8
	Salt         [manifestSaltSize]byte
	Nonce        [manifestNonceSize]byte
}

type manifestKeySlot struct {
	KeyID    uint32    `json:"key_id"`
	DEKHex   string    `json:"dek_hex"`
	StoredAt time.Time `json:"stored_at"`
}

type manifestDEK struct {
	KeyID     uint32    `json:"key_id"`
	DEKHex    string    `json:"dek_hex"`
	CreatedAt time.Time `json:"created_at"`
}

type manifestPayload struct {
	Cipher               Cipher           `json:"cipher"`
	DBUUID               string           `json:"db_uuid"`
	ActiveDEKKeyID       uint32           `json:"active_dek_key_id"`
	DEKs                 []manifestDEK    `json:"deks"`
	CreatedAt            time.Time        `json:"created_at"`
	LastKEKRotationAt    time.Time        `json:"last_kek_rotation_at"`
	NextKEKRotationDueAt time.Time        `json:"next_kek_rotation_due_at"`
	LastDEKRotationAt    time.Time        `json:"last_dek_rotation_at"`
	NextDEKRotationDueAt time.Time        `json:"next_dek_rotation_due_at"`
	KEKRotationDays      int              `json:"kek_rotation_days"`
	DEKRotationHours     int              `json:"dek_rotation_hours"`
	AutoRewrap           *bool            `json:"auto_rewrap,omitempty"`
	KeepPreviousKey      *bool            `json:"keep_previous_key,omitempty"`
	PreviousKeySlot      *manifestKeySlot `json:"previous_key_slot,omitempty"`
}

func resolveOpenOptions(path string, opts Options) (Options, string, uint64, error) {
	if opts.Key == "" {
		return Options{}, "", 0, ErrKeyRequired
	}
	if hasDirectKeyConfig(opts) {
		return Options{}, "", 0, ErrDirectKeyUnsupported
	}
	if isMemoryPath(path, opts) {
		return Options{}, "", 0, ErrFileBackedRequired
	}
	var err error
	opts, err = secureOpenOptions(opts)
	if err != nil {
		return Options{}, "", 0, err
	}

	manifestPath := manifestPathFor(path, opts)
	keyBuf := memguard.NewBufferFromBytes([]byte(opts.Key))
	defer keyBuf.Destroy()
	requestedCipher := opts.Cipher
	opts.Cipher, err = normalizeCipher(opts.Cipher)
	if err != nil {
		return Options{}, "", 0, err
	}

	var (
		payload manifestPayload
		policy  RotationPolicy
	)

	err = withManifestLock(manifestPath, func() error {
		dbExists, statErr := fileExists(path)
		if statErr != nil {
			return statErr
		}
		manifestExists, statErr := fileExists(manifestPath)
		if statErr != nil {
			return statErr
		}
		if !dbExists && !manifestExists {
			if !modeAllowsCreate(opts) {
				return os.ErrNotExist
			}
			policy, err = normalizeCreateRotationPolicy(opts.RotationPolicy)
			if err != nil {
				return err
			}
			payload, err = newManifestPayload(policy, opts.Cipher, timeNowUTC())
			if err != nil {
				return err
			}
			return saveManifest(manifestPath, keyBuf, payload)
		}
		if dbExists && !manifestExists {
			return ErrManifestMissing
		}
		if !dbExists && manifestExists {
			return ErrManifestMismatch
		}
		payload, policy, err = loadManifest(manifestPath, keyBuf)
		if err != nil {
			return err
		}
		if requestedCipher != "" && requestedCipher != payload.Cipher {
			return ErrCipherMismatch
		}
		opts.Cipher = payload.Cipher
		now := timeNowUTC()
		if policy.AutoRewrap && rotationDue(payload, now) {
			applyKEKRotation(&payload, policy, now)
			return saveManifest(manifestPath, keyBuf, payload)
		}
		return nil
	})
	if err != nil {
		return Options{}, "", 0, err
	}

	handle, err := registerKeyRegistry(manifestPath, keyBuf, payload, policy, true)
	if err != nil {
		return Options{}, "", 0, err
	}
	return applyRegistryToOptions(opts, handle), manifestPath, handle, nil
}

func secureOpenOptions(opts Options) (Options, error) {
	resolved := opts
	resolved.URIParameters = cloneURIParameters(opts.URIParameters)

	requested := opts.JournalMode
	if requested == "" {
		if value := resolved.URIParameters["_journal_mode"]; value != "" {
			requested = value
		}
		if value := resolved.URIParameters["_journal"]; value != "" {
			requested = value
		}
	}
	if requested == "" && resolved.URIParameters["mode"] != "ro" {
		requested = "WAL"
	}
	switch strings.ToUpper(requested) {
	case "", "WAL", "MEMORY":
	default:
		return Options{}, fmt.Errorf("%w: %s", ErrUnsafeJournalMode, requested)
	}
	delete(resolved.URIParameters, "_journal")
	delete(resolved.URIParameters, "_journal_mode")
	resolved.JournalMode = strings.ToUpper(requested)
	return resolved, nil
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
	case "", "rwc":
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
	return opts.URIParameters["mode"] == "memory"
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

func applyRegistryToOptions(opts Options, handle uint64) Options {
	resolved := opts
	resolved.Key = ""
	resolved.URIParameters = cloneURIParameters(opts.URIParameters)
	resolved.URIParameters["vfs"] = "encz"
	resolved.URIParameters["encz_registry"] = strconv.FormatUint(handle, 10)
	id, _ := cipherID(resolved.Cipher)
	resolved.URIParameters["encz_cipher"] = strconv.FormatUint(uint64(id), 10)
	delete(resolved.URIParameters, "crypto_key")
	delete(resolved.URIParameters, "crypto_key_hex")
	delete(resolved.URIParameters, "crypto_key_env")
	return resolved
}

func defaultRotationPolicy() RotationPolicy {
	return RotationPolicy{
		KEKRotationDays:  defaultKEKRotationDays,
		DEKRotationHours: defaultDEKRotationHours,
		AutoRewrap:       true,
		KeepPreviousKey:  true,
	}
}

func normalizeCreateRotationPolicy(policy *RotationPolicy) (RotationPolicy, error) {
	out := defaultRotationPolicy()
	if policy == nil {
		return out, nil
	}
	if policy.KEKRotationDays > 0 {
		out.KEKRotationDays = policy.KEKRotationDays
	} else if policy.KEKRotationDays < 0 {
		return RotationPolicy{}, fmt.Errorf("%w: KEKRotationDays must be greater than zero", ErrRotationPolicyInvalid)
	}
	if policy.DEKRotationHours > 0 {
		out.DEKRotationHours = policy.DEKRotationHours
	} else if policy.DEKRotationHours < 0 {
		return RotationPolicy{}, fmt.Errorf("%w: DEKRotationHours must be greater than zero", ErrRotationPolicyInvalid)
	}
	out.AutoRewrap = policy.AutoRewrap
	out.KeepPreviousKey = policy.KeepPreviousKey
	return out, nil
}

func validateRotationPolicy(policy RotationPolicy) (RotationPolicy, error) {
	out := policy
	if out.KEKRotationDays <= 0 {
		return RotationPolicy{}, fmt.Errorf("%w: KEKRotationDays must be greater than zero", ErrRotationPolicyInvalid)
	}
	if out.DEKRotationHours <= 0 {
		out.DEKRotationHours = defaultDEKRotationHours
	}
	return out, nil
}

func newManifestPayload(policy RotationPolicy, cipher Cipher, now time.Time) (manifestPayload, error) {
	dbUUID, err := randomID()
	if err != nil {
		return manifestPayload{}, err
	}
	dekHex, err := randomDEKHex()
	if err != nil {
		return manifestPayload{}, err
	}
	payload := manifestPayload{
		Cipher:               cipher,
		DBUUID:               dbUUID,
		ActiveDEKKeyID:       0,
		DEKs:                 []manifestDEK{{KeyID: 0, DEKHex: dekHex, CreatedAt: now}},
		CreatedAt:            now,
		LastKEKRotationAt:    now,
		NextKEKRotationDueAt: now.Add(time.Duration(policy.KEKRotationDays) * 24 * time.Hour),
		LastDEKRotationAt:    now,
		NextDEKRotationDueAt: now.Add(time.Duration(policy.DEKRotationHours) * time.Hour),
		KEKRotationDays:      policy.KEKRotationDays,
		DEKRotationHours:     policy.DEKRotationHours,
	}
	applyRotationPolicy(&payload, policy)
	return payload, nil
}

func applyRotationPolicy(payload *manifestPayload, policy RotationPolicy) {
	payload.KEKRotationDays = policy.KEKRotationDays
	payload.DEKRotationHours = policy.DEKRotationHours
	payload.AutoRewrap = boolPtr(policy.AutoRewrap)
	payload.KeepPreviousKey = boolPtr(policy.KeepPreviousKey)
	if !policy.KeepPreviousKey {
		payload.PreviousKeySlot = nil
	}
	if !payload.LastKEKRotationAt.IsZero() {
		payload.NextKEKRotationDueAt = payload.LastKEKRotationAt.Add(time.Duration(policy.KEKRotationDays) * 24 * time.Hour)
	}
	if !payload.LastDEKRotationAt.IsZero() {
		payload.NextDEKRotationDueAt = payload.LastDEKRotationAt.Add(time.Duration(policy.DEKRotationHours) * time.Hour)
	}
}

func applyKEKRotation(payload *manifestPayload, policy RotationPolicy, now time.Time) {
	applyRotationPolicy(payload, policy)
	if policy.KeepPreviousKey {
		active, ok := activeDEKFromPayload(payload)
		if ok {
			payload.PreviousKeySlot = &manifestKeySlot{KeyID: active.KeyID, DEKHex: active.DEKHex, StoredAt: payload.LastKEKRotationAt}
		} else {
			payload.PreviousKeySlot = nil
		}
	} else {
		payload.PreviousKeySlot = nil
	}
	payload.LastKEKRotationAt = now
	payload.NextKEKRotationDueAt = now.Add(time.Duration(policy.KEKRotationDays) * 24 * time.Hour)
}

func loadManifest(path string, passphrase *memguard.LockedBuffer) (manifestPayload, RotationPolicy, error) {
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
	if len(payload.DEKs) == 0 || payload.KEKRotationDays <= 0 {
		return payload, RotationPolicy{}, ErrManifestInvalid
	}
	if payload.Cipher == "" {
		payload.Cipher = hdr.Cipher
	}
	if payload.Cipher != hdr.Cipher {
		return payload, RotationPolicy{}, ErrManifestInvalid
	}
	policy := policyFromPayload(payload)
	if _, ok := activeDEKFromPayload(&payload); !ok {
		return payload, RotationPolicy{}, ErrManifestInvalid
	}
	if payload.LastKEKRotationAt.IsZero() {
		payload.LastKEKRotationAt = payload.CreatedAt
	}
	if payload.NextKEKRotationDueAt.IsZero() {
		payload.NextKEKRotationDueAt = payload.LastKEKRotationAt.Add(time.Duration(policy.KEKRotationDays) * 24 * time.Hour)
	}
	if payload.LastDEKRotationAt.IsZero() {
		payload.LastDEKRotationAt = payload.CreatedAt
	}
	if payload.NextDEKRotationDueAt.IsZero() {
		payload.NextDEKRotationDueAt = payload.LastDEKRotationAt.Add(time.Duration(policy.DEKRotationHours) * time.Hour)
	}
	return payload, policy, nil
}

func saveManifest(path string, passphrase *memguard.LockedBuffer, payload manifestPayload) error {
	t, m, thr := getArgonParams()
	hdr := manifestHeader{
		Version:      manifestVersion,
		Cipher:       payload.Cipher,
		ArgonTime:    t,
		ArgonMemory:  m,
		ArgonThreads: thr,
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
	id, err := cipherID(hdr.Cipher)
	if err != nil {
		return err
	}
	buf = append(buf, hdr.Version, byte(id))
	buf = binary.LittleEndian.AppendUint32(buf, hdr.ArgonTime)
	buf = binary.LittleEndian.AppendUint32(buf, hdr.ArgonMemory)
	buf = append(buf, hdr.ArgonThreads)
	buf = append(buf, hdr.Salt[:]...)
	buf = append(buf, hdr.Nonce[:]...)
	buf = append(buf, sealed...)
	return atomicWriteFile(path, buf, 0o600)
}

func manifestHeaderSize() int {
	return len(manifestMagic) + 1 + 1 + 4 + 4 + 1 + manifestSaltSize + manifestNonceSize
}

func parseManifest(blob []byte) (manifestHeader, []byte, error) {
	var hdr manifestHeader
	if len(blob) < manifestHeaderSize()+16 {
		return hdr, nil, ErrManifestInvalid
	}
	if string(blob[:len(manifestMagic)]) != manifestMagic {
		if len(blob) >= 6 && string(blob[:6]) == "ENCZK2" {
			return hdr, nil, ErrLegacyFormatUnsupported
		}
		return hdr, nil, ErrManifestInvalid
	}
	offset := len(manifestMagic)
	hdr.Version = blob[offset]
	offset++
	if hdr.Version != manifestVersion {
		if hdr.Version == 2 {
			return hdr, nil, ErrLegacyFormatUnsupported
		}
		return hdr, nil, ErrManifestInvalid
	}
	parsedCipher, err := cipherFromID(uint32(blob[offset]))
	hdr.Cipher = parsedCipher
	if err != nil {
		return hdr, nil, ErrManifestInvalid
	}
	offset++
	hdr.ArgonTime = binary.LittleEndian.Uint32(blob[offset:])
	offset += 4
	hdr.ArgonMemory = binary.LittleEndian.Uint32(blob[offset:])
	offset += 4
	hdr.ArgonThreads = blob[offset]
	offset++
	if err := validateArgonParams(hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads); err != nil {
		return manifestHeader{}, nil, ErrManifestInvalid
	}
	copy(hdr.Salt[:], blob[offset:offset+manifestSaltSize])
	offset += manifestSaltSize
	copy(hdr.Nonce[:], blob[offset:offset+manifestNonceSize])
	offset += manifestNonceSize
	return hdr, blob[offset:], nil
}

func validateArgonParams(timeCost, memoryCost uint32, threads uint8) error {
	if timeCost < 1 || timeCost > maxArgonTime {
		return ErrManifestInvalid
	}
	if memoryCost < 8 || memoryCost > maxArgonMemory {
		return ErrManifestInvalid
	}
	if threads < 1 || threads > maxArgonThreads {
		return ErrManifestInvalid
	}
	return nil
}

func deriveKEK(passphrase *memguard.LockedBuffer, hdr manifestHeader) []byte {
	return argon2.IDKey(passphrase.Bytes(), hdr.Salt[:], hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads, manifestKEKSize)
}

func encryptManifestPayload(kek []byte, hdr manifestHeader, plain []byte) ([]byte, error) {
	aead, err := newCipherAEAD(hdr.Cipher, kek)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, hdr.Nonce[:aead.NonceSize()], plain, manifestAAD(hdr)), nil
}

func decryptManifestPayload(kek []byte, hdr manifestHeader, ciphertext []byte) ([]byte, error) {
	aead, err := newCipherAEAD(hdr.Cipher, kek)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, hdr.Nonce[:aead.NonceSize()], ciphertext, manifestAAD(hdr))
	if err != nil {
		return nil, ErrManifestAuthFailed
	}
	return plain, nil
}

func manifestAAD(hdr manifestHeader) []byte {
	buf := make([]byte, 0, len(manifestMagic)+1+1+4+4+1+manifestSaltSize)
	buf = append(buf, []byte(manifestMagic)...)
	id, _ := cipherID(hdr.Cipher)
	buf = append(buf, hdr.Version, byte(id))
	buf = binary.LittleEndian.AppendUint32(buf, hdr.ArgonTime)
	buf = binary.LittleEndian.AppendUint32(buf, hdr.ArgonMemory)
	buf = append(buf, hdr.ArgonThreads)
	buf = append(buf, hdr.Salt[:]...)
	return buf
}

func randomDEKHex() (string, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return "", err
	}
	return hex.EncodeToString(dek), nil
}

func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func activeDEKFromPayload(payload *manifestPayload) (manifestDEK, bool) {
	for _, dek := range payload.DEKs {
		if dek.KeyID == payload.ActiveDEKKeyID {
			return dek, true
		}
	}
	return manifestDEK{}, false
}

func nextManifestKeyID(payload manifestPayload) uint32 {
	var maxID uint32
	for _, dek := range payload.DEKs {
		if dek.KeyID > maxID {
			maxID = dek.KeyID
		}
	}
	return maxID + 1
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
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
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return syncParentDir(dir)
}

func syncParentDir(dir string) error {
	// Windows does not support syncing directory handles. The manifest data has
	// already been flushed and renamed atomically, so retain that behavior while
	// skipping the Unix-specific directory metadata durability step.
	if runtime.GOOS == "windows" {
		return nil
	}
	h, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer h.Close()
	if err := h.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return err
	}
	return nil
}

func policyFromPayload(payload manifestPayload) RotationPolicy {
	policy := defaultRotationPolicy()
	policy.KEKRotationDays = payload.KEKRotationDays
	if payload.DEKRotationHours > 0 {
		policy.DEKRotationHours = payload.DEKRotationHours
	}
	policy.AutoRewrap = storedBool(payload.AutoRewrap, policy.AutoRewrap)
	policy.KeepPreviousKey = storedBool(payload.KeepPreviousKey, payload.PreviousKeySlot != nil || policy.KeepPreviousKey)
	return policy
}

func storedBool(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func boolPtr(v bool) *bool {
	return &v
}

func rotationDue(payload manifestPayload, now time.Time) bool {
	return now.After(payload.NextKEKRotationDueAt) || now.Equal(payload.NextKEKRotationDueAt)
}

func dekRotationDue(payload manifestPayload, now time.Time) bool {
	return now.After(payload.NextDEKRotationDueAt) || now.Equal(payload.NextDEKRotationDueAt)
}

func rotationInfoFromPayload(manifestPath string, payload manifestPayload, policy RotationPolicy) RotationInfo {
	now := timeNowUTC()
	return RotationInfo{
		ManifestPath:         manifestPath,
		Exists:               true,
		KEKRotationDue:       rotationDue(payload, now),
		DEKRotationDue:       dekRotationDue(payload, now),
		LastKEKRotationAt:    payload.LastKEKRotationAt,
		NextKEKRotationDueAt: payload.NextKEKRotationDueAt,
		KEKRotationDays:      payload.KEKRotationDays,
		LastDEKRotationAt:    payload.LastDEKRotationAt,
		NextDEKRotationDueAt: payload.NextDEKRotationDueAt,
		DEKRotationHours:     payload.DEKRotationHours,
		ActiveDEKKeyID:       payload.ActiveDEKKeyID,
		DEKCount:             len(payload.DEKs),
		HasPreviousKey:       payload.PreviousKeySlot != nil,
		AutoRewrap:           policy.AutoRewrap,
		KeepPreviousKey:      policy.KeepPreviousKey,
	}
}

func manifestMissing(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

func timeNowUTC() time.Time {
	return time.Now().UTC()
}
