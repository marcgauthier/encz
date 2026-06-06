package encz

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/awnumar/memguard"
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
	ErrKeyRequired           = errors.New("encz: encryption key is required")
	ErrManifestMissing       = errors.New("encz: manifest file is required")
	ErrManifestMismatch      = errors.New("encz: database and manifest files are inconsistent")
	ErrManifestInvalid       = errors.New("encz: manifest is invalid")
	ErrManifestAuthFailed    = errors.New("encz: manifest authentication failed")
	ErrDirectKeyUnsupported  = errors.New("encz: direct key configuration is unsupported")
	ErrFileBackedRequired    = errors.New("encz: only file-backed encrypted databases are supported")
	ErrRotationPolicyInvalid = errors.New("encz: rotation policy is invalid")
	ErrDBClosed              = errors.New("encz: database handle is closed")
	ErrCurrentKeyMismatch    = errors.New("encz: old key does not match the active handle key")
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
	AutoRewrap           bool
	KeepPreviousKey      bool
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
	AutoRewrap           *bool            `json:"auto_rewrap,omitempty"`
	KeepPreviousKey      *bool            `json:"keep_previous_key,omitempty"`
	PreviousKeySlot      *manifestKeySlot `json:"previous_key_slot,omitempty"`
}

func resolveOpenOptions(path string, opts Options) (Options, string, error) {
	if opts.Key == "" {
		return Options{}, "", ErrKeyRequired
	}
	if hasDirectKeyConfig(opts) {
		return Options{}, "", ErrDirectKeyUnsupported
	}
	if isMemoryPath(path, opts) {
		return Options{}, "", ErrFileBackedRequired
	}

	manifestPath := manifestPathFor(path, opts)
	dbExists, err := fileExists(path)
	if err != nil {
		return Options{}, "", err
	}
	manifestExists, err := fileExists(manifestPath)
	if err != nil {
		return Options{}, "", err
	}
	createAllowed := modeAllowsCreate(opts)

	keyBuf := memguard.NewBufferFromBytes([]byte(opts.Key))
	defer keyBuf.Destroy()

	if !dbExists && !manifestExists {
		if !createAllowed {
			return Options{}, "", os.ErrNotExist
		}
		policy, err := normalizeCreateRotationPolicy(opts.RotationPolicy)
		if err != nil {
			return Options{}, "", err
		}
		payload, err := newManifestPayload(policy, timeNowUTC())
		if err != nil {
			return Options{}, "", err
		}
		if err := saveManifest(manifestPath, keyBuf, payload); err != nil {
			return Options{}, "", err
		}
		return applyDEKToOptions(opts, payload.ActiveDEKHex), manifestPath, nil
	}
	if dbExists && !manifestExists {
		return Options{}, "", ErrManifestMissing
	}
	if !dbExists && manifestExists {
		return Options{}, "", ErrManifestMismatch
	}

	payload, policy, err := loadManifest(manifestPath, keyBuf)
	if err != nil {
		return Options{}, "", err
	}
	now := timeNowUTC()
	if policy.AutoRewrap && rotationDue(payload, now) {
		applyKEKRotation(&payload, policy, now)
		if err := saveManifest(manifestPath, keyBuf, payload); err != nil {
			return Options{}, "", err
		}
	}
	return applyDEKToOptions(opts, payload.ActiveDEKHex), manifestPath, nil
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

func defaultRotationPolicy() RotationPolicy {
	return RotationPolicy{
		KEKRotationDays: defaultKEKRotationDays,
		AutoRewrap:      true,
		KeepPreviousKey: true,
	}
}

func normalizeCreateRotationPolicy(policy *RotationPolicy) (RotationPolicy, error) {
	out := defaultRotationPolicy()
	if policy == nil {
		return out, nil
	}
	if policy.KEKRotationDays <= 0 {
		return RotationPolicy{}, fmt.Errorf("%w: KEKRotationDays must be greater than zero", ErrRotationPolicyInvalid)
	}
	out.KEKRotationDays = policy.KEKRotationDays
	out.AutoRewrap = policy.AutoRewrap
	out.KeepPreviousKey = policy.KeepPreviousKey
	return out, nil
}

func validateRotationPolicy(policy RotationPolicy) (RotationPolicy, error) {
	if policy.KEKRotationDays <= 0 {
		return RotationPolicy{}, fmt.Errorf("%w: KEKRotationDays must be greater than zero", ErrRotationPolicyInvalid)
	}
	return policy, nil
}

func newManifestPayload(policy RotationPolicy, now time.Time) (manifestPayload, error) {
	dbUUID, err := randomID()
	if err != nil {
		return manifestPayload{}, err
	}
	dekHex, err := randomDEKHex()
	if err != nil {
		return manifestPayload{}, err
	}
	payload := manifestPayload{
		DBUUID:               dbUUID,
		ActiveDEKID:          "dek-" + now.UTC().Format("20060102T150405Z"),
		ActiveDEKHex:         dekHex,
		CreatedAt:            now,
		LastKEKRotationAt:    now,
		NextKEKRotationDueAt: now.Add(time.Duration(policy.KEKRotationDays) * 24 * time.Hour),
		KEKRotationDays:      policy.KEKRotationDays,
	}
	applyRotationPolicy(&payload, policy)
	return payload, nil
}

func applyRotationPolicy(payload *manifestPayload, policy RotationPolicy) {
	payload.KEKRotationDays = policy.KEKRotationDays
	payload.AutoRewrap = boolPtr(policy.AutoRewrap)
	payload.KeepPreviousKey = boolPtr(policy.KeepPreviousKey)
	if !policy.KeepPreviousKey {
		payload.PreviousKeySlot = nil
	}
	if !payload.LastKEKRotationAt.IsZero() {
		payload.NextKEKRotationDueAt = payload.LastKEKRotationAt.Add(time.Duration(policy.KEKRotationDays) * 24 * time.Hour)
	}
}

func applyKEKRotation(payload *manifestPayload, policy RotationPolicy, now time.Time) {
	applyRotationPolicy(payload, policy)
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
	if payload.ActiveDEKHex == "" || payload.ActiveDEKID == "" || payload.KEKRotationDays <= 0 {
		return payload, RotationPolicy{}, ErrManifestInvalid
	}
	policy := policyFromPayload(payload)
	if payload.LastKEKRotationAt.IsZero() {
		payload.LastKEKRotationAt = payload.CreatedAt
	}
	if payload.NextKEKRotationDueAt.IsZero() {
		payload.NextKEKRotationDueAt = payload.LastKEKRotationAt.Add(time.Duration(policy.KEKRotationDays) * 24 * time.Hour)
	}
	return payload, policy, nil
}

func saveManifest(path string, passphrase *memguard.LockedBuffer, payload manifestPayload) error {
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

func deriveKEK(passphrase *memguard.LockedBuffer, hdr manifestHeader) []byte {
	return argon2.IDKey(passphrase.Bytes(), hdr.Salt[:], hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads, manifestKEKSize)
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

func rotationInfoFromPayload(manifestPath string, payload manifestPayload, policy RotationPolicy) RotationInfo {
	now := timeNowUTC()
	return RotationInfo{
		ManifestPath:         manifestPath,
		Exists:               true,
		KEKRotationDue:       rotationDue(payload, now),
		LastKEKRotationAt:    payload.LastKEKRotationAt,
		NextKEKRotationDueAt: payload.NextKEKRotationDueAt,
		KEKRotationDays:      payload.KEKRotationDays,
		ActiveDEKID:          payload.ActiveDEKID,
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
