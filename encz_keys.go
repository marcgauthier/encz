package encz

/*
#include <stdint.h>
*/
import "C"

import "unsafe"

//export enczGoFillKey
func enczGoFillKey(handle C.ulonglong, keyID C.uint, out *C.uchar) C.int {
	reg, ok := getKeyRegistry(uint64(handle))
	if !ok || out == nil {
		return 0
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(out)), 32)
	if !reg.fillKey(uint32(keyID), dst) {
		return 0
	}
	return 1
}

//export enczGoFillActiveKey
func enczGoFillActiveKey(handle C.ulonglong, outKeyID *C.uint, out *C.uchar) C.int {
	reg, ok := getKeyRegistry(uint64(handle))
	if !ok || out == nil || outKeyID == nil {
		return 0
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(out)), 32)
	keyID, ok := reg.fillActiveKey(dst)
	if !ok {
		return 0
	}
	*outKeyID = C.uint(keyID)
	return 1
}
