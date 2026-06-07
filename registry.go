package encz

import (
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/awnumar/memguard"
)

type keyRegistry struct {
	mu               sync.RWMutex
	manifestPath     string
	masterKey        *memguard.LockedBuffer
	payload          manifestPayload
	policy           RotationPolicy
	keys             map[uint32]*memguard.LockedBuffer
	allowDEKRotation bool
}

var (
	keyRegistrySeq atomic.Uint64
	keyRegistryMu  sync.RWMutex
	keyRegistries  = make(map[uint64]*keyRegistry)
)

func cloneLockedBuffer(src *memguard.LockedBuffer) *memguard.LockedBuffer {
	if src == nil {
		return nil
	}
	dup := append([]byte(nil), src.Bytes()...)
	return memguard.NewBufferFromBytes(dup)
}

func registerKeyRegistry(manifestPath string, masterKey *memguard.LockedBuffer, payload manifestPayload, policy RotationPolicy, allowDEKRotation bool) (uint64, error) {
	keys, err := buildRegistryKeyBuffers(payload)
	if err != nil {
		return 0, err
	}
	reg := &keyRegistry{
		manifestPath:     manifestPath,
		masterKey:        cloneLockedBuffer(masterKey),
		payload:          payload,
		policy:           policy,
		keys:             keys,
		allowDEKRotation: allowDEKRotation,
	}
	handle := keyRegistrySeq.Add(1)
	keyRegistryMu.Lock()
	keyRegistries[handle] = reg
	keyRegistryMu.Unlock()
	return handle, nil
}

func getKeyRegistry(handle uint64) (*keyRegistry, bool) {
	keyRegistryMu.RLock()
	defer keyRegistryMu.RUnlock()
	reg, ok := keyRegistries[handle]
	return reg, ok
}

func destroyKeyRegistry(handle uint64) {
	keyRegistryMu.Lock()
	reg, ok := keyRegistries[handle]
	if ok {
		delete(keyRegistries, handle)
	}
	keyRegistryMu.Unlock()
	if !ok {
		return
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if reg.masterKey != nil {
		reg.masterKey.Destroy()
		reg.masterKey = nil
	}
	for _, buf := range reg.keys {
		if buf != nil {
			buf.Destroy()
		}
	}
	reg.keys = nil
}

func updateKeyRegistryMasterKey(handle uint64, masterKey *memguard.LockedBuffer) {
	reg, ok := getKeyRegistry(handle)
	if !ok {
		return
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if reg.masterKey != nil {
		reg.masterKey.Destroy()
	}
	reg.masterKey = cloneLockedBuffer(masterKey)
}

func updateKeyRegistryManifest(handle uint64, payload manifestPayload, policy RotationPolicy) error {
	reg, ok := getKeyRegistry(handle)
	if !ok {
		return nil
	}
	keys, err := buildRegistryKeyBuffers(payload)
	if err != nil {
		return err
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	for _, buf := range reg.keys {
		if buf != nil {
			buf.Destroy()
		}
	}
	reg.keys = keys
	reg.payload = payload
	reg.policy = policy
	return nil
}

func buildRegistryKeyBuffers(payload manifestPayload) (map[uint32]*memguard.LockedBuffer, error) {
	keys := make(map[uint32]*memguard.LockedBuffer, len(payload.DEKs))
	for _, dek := range payload.DEKs {
		decoded, err := hex.DecodeString(dek.DEKHex)
		if err != nil || len(decoded) != 32 {
			for _, buf := range keys {
				if buf != nil {
					buf.Destroy()
				}
			}
			return nil, ErrManifestInvalid
		}
		keys[dek.KeyID] = memguard.NewBufferFromBytes(decoded)
	}
	if _, ok := keys[payload.ActiveDEKKeyID]; !ok {
		for _, buf := range keys {
			if buf != nil {
				buf.Destroy()
			}
		}
		return nil, ErrManifestInvalid
	}
	return keys, nil
}

func (r *keyRegistry) fillKey(keyID uint32, out []byte) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	buf, ok := r.keys[keyID]
	if !ok || buf == nil || len(out) < 32 {
		return false
	}
	copy(out, buf.Bytes())
	return true
}

func (r *keyRegistry) fillActiveKey(out []byte) (uint32, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.allowDEKRotation && dekRotationDue(r.payload, timeNowUTC()) {
		if err := r.rotateActiveDEKLocked(timeNowUTC()); err != nil {
			return 0, false
		}
	}

	buf, ok := r.keys[r.payload.ActiveDEKKeyID]
	if !ok || buf == nil || len(out) < 32 {
		return 0, false
	}
	copy(out, buf.Bytes())
	return r.payload.ActiveDEKKeyID, true
}

func (r *keyRegistry) rotateActiveDEKLocked(now time.Time) error {
	nextID := nextManifestKeyID(r.payload)
	dekHex, err := randomDEKHex()
	if err != nil {
		return err
	}
	decoded, err := hex.DecodeString(dekHex)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("%w: invalid generated DEK", ErrManifestInvalid)
	}

	nextPayload := r.payload
	nextPayload.DEKs = append(append([]manifestDEK(nil), r.payload.DEKs...), manifestDEK{
		KeyID:     nextID,
		DEKHex:    dekHex,
		CreatedAt: now,
	})
	nextPayload.ActiveDEKKeyID = nextID
	nextPayload.LastDEKRotationAt = now
	nextPayload.NextDEKRotationDueAt = now.Add(time.Duration(r.policy.DEKRotationHours) * time.Hour)
	if err := saveManifest(r.manifestPath, r.masterKey, nextPayload); err != nil {
		return err
	}

	r.payload = nextPayload
	r.keys[nextID] = memguard.NewBufferFromBytes(decoded)
	return nil
}
