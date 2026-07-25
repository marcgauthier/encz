package sqliteseal

/*
#include <stdint.h>
*/
import "C"

import (
	"time"
	"unsafe"
)

func pageKey(wal C.int, pageNo C.uint, offset C.longlong, pageSize C.uint) pageCacheKey {
	return pageCacheKey{
		wal:      wal != 0,
		pageNo:   uint32(pageNo),
		offset:   int64(offset),
		pageSize: uint32(pageSize),
	}
}

//export enczGoAEADOpenCached
func enczGoAEADOpenCached(handle C.ulonglong, keyID C.uint, nonce, sealed, out, aad *C.uchar, sealedLen, plainLen, aadLen C.int) C.int {
	if nonce == nil || sealed == nil || out == nil || aad == nil || sealedLen < 0 || plainLen < 0 || aadLen < 0 {
		return 0
	}
	reg, ok := getKeyRegistry(uint64(handle))
	if !ok {
		return 0
	}
	aead, entry, ok := reg.acquirePageAEAD(uint32(keyID))
	if !ok {
		return 0
	}
	defer entry.pool.Put(aead)
	var start time.Time
	if reg.readStats.enabled {
		start = time.Now()
	}
	opened, err := aead.Open(
		unsafe.Slice((*byte)(unsafe.Pointer(out)), int(plainLen))[:0],
		unsafe.Slice((*byte)(unsafe.Pointer(nonce)), aead.NonceSize()),
		unsafe.Slice((*byte)(unsafe.Pointer(sealed)), int(sealedLen)),
		unsafe.Slice((*byte)(unsafe.Pointer(aad)), int(aadLen)),
	)
	if reg.readStats.enabled {
		reg.readStats.aeadOpenCalls.Add(1)
		reg.readStats.aeadOpenNanos.Add(uint64(time.Since(start)))
	}
	if err != nil || len(opened) != int(plainLen) {
		if reg.readStats.enabled {
			reg.readStats.aeadOpenFailures.Add(1)
		}
		return 0
	}
	return 1
}

//export enczGoPageCacheCandidate
func enczGoPageCacheCandidate(handle C.ulonglong, wal C.int, pageNo C.uint, offset C.longlong, pageSize C.uint, pageOut, tokenOut *C.uchar, tokenCap C.int, tokenLen *C.int) C.int {
	reg, ok := getKeyRegistry(uint64(handle))
	if !ok || pageOut == nil || tokenOut == nil || tokenLen == nil || tokenCap <= 0 {
		return 0
	}
	if reg.readStats.enabled {
		reg.readStats.pageRequests.Add(1)
	}
	page := unsafe.Slice((*byte)(unsafe.Pointer(pageOut)), int(pageSize))
	token := unsafe.Slice((*byte)(unsafe.Pointer(tokenOut)), int(tokenCap))
	n, found := reg.pageCache.candidate(pageKey(wal, pageNo, offset, pageSize), page, token)
	if !found {
		return 0
	}
	*tokenLen = C.int(n)
	return 1
}

//export enczGoPageCacheConfirm
func enczGoPageCacheConfirm(handle C.ulonglong, wal C.int, pageNo C.uint, offset C.longlong, pageSize C.uint, expected, actual *C.uchar, tokenLen C.int) C.int {
	reg, ok := getKeyRegistry(uint64(handle))
	if !ok || expected == nil || actual == nil || tokenLen <= 0 {
		return 0
	}
	want := unsafe.Slice((*byte)(unsafe.Pointer(expected)), int(tokenLen))
	got := unsafe.Slice((*byte)(unsafe.Pointer(actual)), int(tokenLen))
	if reg.pageCache.confirm(pageKey(wal, pageNo, offset, pageSize), want, got) {
		return 1
	}
	return 0
}

//export enczGoPageCachePut
func enczGoPageCachePut(handle C.ulonglong, wal C.int, pageNo C.uint, offset C.longlong, pageSize C.uint, page, token *C.uchar, tokenLen C.int) {
	reg, ok := getKeyRegistry(uint64(handle))
	if !ok || page == nil || token == nil || tokenLen <= 0 {
		return
	}
	reg.pageCache.put(
		pageKey(wal, pageNo, offset, pageSize),
		unsafe.Slice((*byte)(unsafe.Pointer(page)), int(pageSize)),
		unsafe.Slice((*byte)(unsafe.Pointer(token)), int(tokenLen)),
	)
}

//export enczGoPageCacheInvalidate
func enczGoPageCacheInvalidate(handle C.ulonglong, wal C.int, pageNo C.uint, offset C.longlong, pageSize C.uint) {
	if reg, ok := getKeyRegistry(uint64(handle)); ok {
		reg.pageCache.invalidate(pageKey(wal, pageNo, offset, pageSize))
	}
}

//export enczGoPageCacheClear
func enczGoPageCacheClear(handle C.ulonglong, wal C.int) {
	if reg, ok := getKeyRegistry(uint64(handle)); ok {
		if wal < 0 {
			reg.pageCache.clear()
		} else {
			reg.pageCache.clearKind(wal != 0)
		}
	}
}

//export enczGoReadStatsEnabled
func enczGoReadStatsEnabled(handle C.ulonglong) C.int {
	if reg, ok := getKeyRegistry(uint64(handle)); ok && reg.readStats.enabled {
		return 1
	}
	return 0
}

//export enczGoRecordReadIO
func enczGoRecordReadIO(handle C.ulonglong, reads, bytesRead, nanos, scratchAllocs, copyBytes C.ulonglong) {
	reg, ok := getKeyRegistry(uint64(handle))
	if !ok || !reg.readStats.enabled {
		return
	}
	reg.readStats.physicalReads.Add(uint64(reads))
	reg.readStats.physicalReadBytes.Add(uint64(bytesRead))
	reg.readStats.physicalReadNanos.Add(uint64(nanos))
	reg.readStats.scratchAllocations.Add(uint64(scratchAllocs))
	reg.readStats.copyBytes.Add(uint64(copyBytes))
}
