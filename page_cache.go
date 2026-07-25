package sqliteseal

import (
	"bytes"
	"container/list"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultDecryptedPageCacheBytes is the default plaintext page-cache budget
	// for each DB handle. Map/list overhead is not included in the budget.
	DefaultDecryptedPageCacheBytes int64 = 128 << 20
	// DisableDecryptedPageCache disables the plaintext page cache.
	DisableDecryptedPageCache int64 = -1
)

type pageCacheKey struct {
	wal      bool
	pageNo   uint32
	offset   int64
	pageSize uint32
}

type pageCacheEntry struct {
	key   pageCacheKey
	page  []byte
	token []byte
}

type decryptedPageCache struct {
	mu       sync.Mutex
	maxBytes int64
	used     int64
	lru      list.List
	entries  map[pageCacheKey]*list.Element
	stats    *readStats
}

func newDecryptedPageCache(maxBytes int64, stats *readStats) *decryptedPageCache {
	if maxBytes <= 0 {
		return nil
	}
	return &decryptedPageCache{
		maxBytes: maxBytes,
		entries:  make(map[pageCacheKey]*list.Element),
		stats:    stats,
	}
}

func (c *decryptedPageCache) candidate(key pageCacheKey, page, token []byte) (int, bool) {
	if c == nil || len(page) != int(key.pageSize) {
		return 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	elem := c.entries[key]
	if elem == nil {
		c.stats.cacheMiss()
		return 0, false
	}
	entry := elem.Value.(*pageCacheEntry)
	if len(token) < len(entry.token) {
		c.stats.cacheMiss()
		return 0, false
	}
	copy(page, entry.page)
	copy(token, entry.token)
	c.lru.MoveToFront(elem)
	return len(entry.token), true
}

func (c *decryptedPageCache) confirm(key pageCacheKey, expected, actual []byte) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	elem := c.entries[key]
	if elem == nil {
		c.stats.cacheMiss()
		return false
	}
	entry := elem.Value.(*pageCacheEntry)
	if bytes.Equal(entry.token, expected) && bytes.Equal(expected, actual) {
		c.stats.cacheHit()
		return true
	}
	c.removeElementLocked(elem, false)
	c.stats.cacheInvalidation()
	c.stats.cacheMiss()
	return false
}

func (c *decryptedPageCache) put(key pageCacheKey, page, token []byte) {
	if c == nil || len(page) != int(key.pageSize) || int64(len(page)) > c.maxBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old := c.entries[key]; old != nil {
		c.removeElementLocked(old, false)
	}
	entry := &pageCacheEntry{
		key:   key,
		page:  append([]byte(nil), page...),
		token: append([]byte(nil), token...),
	}
	c.entries[key] = c.lru.PushFront(entry)
	c.used += int64(len(entry.page))
	for c.used > c.maxBytes {
		c.removeElementLocked(c.lru.Back(), true)
	}
}

func (c *decryptedPageCache) invalidate(key pageCacheKey) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem := c.entries[key]; elem != nil {
		c.removeElementLocked(elem, false)
		c.stats.cacheInvalidation()
	}
}

func (c *decryptedPageCache) clearKind(wal bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := uint64(0)
	for key, elem := range c.entries {
		if key.wal == wal {
			c.removeElementLocked(elem, false)
			n++
		}
	}
	c.stats.addCacheInvalidations(n)
}

func (c *decryptedPageCache) clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := uint64(len(c.entries))
	for elem := c.lru.Back(); elem != nil; elem = c.lru.Back() {
		c.removeElementLocked(elem, false)
	}
	c.stats.addCacheInvalidations(n)
}

func (c *decryptedPageCache) removeElementLocked(elem *list.Element, eviction bool) {
	if elem == nil {
		return
	}
	entry := elem.Value.(*pageCacheEntry)
	delete(c.entries, entry.key)
	c.lru.Remove(elem)
	c.used -= int64(len(entry.page))
	clear(entry.page)
	clear(entry.token)
	if eviction {
		c.stats.cacheEviction()
	}
}

type readStats struct {
	enabled bool

	pageRequests       atomic.Uint64
	cacheHits          atomic.Uint64
	cacheMisses        atomic.Uint64
	cacheEvictions     atomic.Uint64
	cacheInvalidations atomic.Uint64
	physicalReads      atomic.Uint64
	physicalReadBytes  atomic.Uint64
	physicalReadNanos  atomic.Uint64
	aeadOpenCalls      atomic.Uint64
	aeadOpenNanos      atomic.Uint64
	aeadOpenFailures   atomic.Uint64
	scratchAllocations atomic.Uint64
	copyBytes          atomic.Uint64
}

// ReadPerformanceStats is a point-in-time snapshot of encrypted page-read
// activity. Timing collection is disabled unless explicitly requested.
type ReadPerformanceStats struct {
	Enabled            bool
	PageRequests       uint64
	CacheHits          uint64
	CacheMisses        uint64
	CacheEvictions     uint64
	CacheInvalidations uint64
	PhysicalReads      uint64
	PhysicalReadBytes  uint64
	PhysicalReadTime   time.Duration
	AEADOpenCalls      uint64
	AEADOpenTime       time.Duration
	AEADOpenFailures   uint64
	ScratchAllocations uint64
	CopyBytes          uint64
}

func (s *readStats) cacheHit() {
	if s != nil && s.enabled {
		s.cacheHits.Add(1)
	}
}
func (s *readStats) cacheMiss() {
	if s != nil && s.enabled {
		s.cacheMisses.Add(1)
	}
}
func (s *readStats) cacheEviction() {
	if s != nil && s.enabled {
		s.cacheEvictions.Add(1)
	}
}
func (s *readStats) cacheInvalidation() { s.addCacheInvalidations(1) }
func (s *readStats) addCacheInvalidations(n uint64) {
	if s != nil && s.enabled {
		s.cacheInvalidations.Add(n)
	}
}

func (s *readStats) snapshot() ReadPerformanceStats {
	if s == nil {
		return ReadPerformanceStats{}
	}
	return ReadPerformanceStats{
		Enabled:            s.enabled,
		PageRequests:       s.pageRequests.Load(),
		CacheHits:          s.cacheHits.Load(),
		CacheMisses:        s.cacheMisses.Load(),
		CacheEvictions:     s.cacheEvictions.Load(),
		CacheInvalidations: s.cacheInvalidations.Load(),
		PhysicalReads:      s.physicalReads.Load(),
		PhysicalReadBytes:  s.physicalReadBytes.Load(),
		PhysicalReadTime:   time.Duration(s.physicalReadNanos.Load()),
		AEADOpenCalls:      s.aeadOpenCalls.Load(),
		AEADOpenTime:       time.Duration(s.aeadOpenNanos.Load()),
		AEADOpenFailures:   s.aeadOpenFailures.Load(),
		ScratchAllocations: s.scratchAllocations.Load(),
		CopyBytes:          s.copyBytes.Load(),
	}
}

func (s *readStats) reset() {
	if s == nil {
		return
	}
	s.pageRequests.Store(0)
	s.cacheHits.Store(0)
	s.cacheMisses.Store(0)
	s.cacheEvictions.Store(0)
	s.cacheInvalidations.Store(0)
	s.physicalReads.Store(0)
	s.physicalReadBytes.Store(0)
	s.physicalReadNanos.Store(0)
	s.aeadOpenCalls.Store(0)
	s.aeadOpenNanos.Store(0)
	s.aeadOpenFailures.Store(0)
	s.scratchAllocations.Store(0)
	s.copyBytes.Store(0)
}

type cachedAEAD struct {
	pool sync.Pool
}
