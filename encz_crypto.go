package sqliteseal

/*
#include <stdint.h>
*/
import "C"

import "unsafe"

//export enczGoAEADSeal
func enczGoAEADSeal(cipherID C.uint, key, nonce, out, tag, plain, aad *C.uchar, plainLen, aadLen C.int) C.int {
	if key == nil || nonce == nil || out == nil || tag == nil || plain == nil || aad == nil || plainLen < 0 || aadLen < 0 {
		return 0
	}
	algorithm, err := cipherFromID(uint32(cipherID))
	if err != nil {
		return 0
	}
	aead, err := newCipherAEAD(algorithm, unsafe.Slice((*byte)(unsafe.Pointer(key)), 32))
	if err != nil {
		return 0
	}
	n := aead.NonceSize()
	dst := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(plainLen)+aead.Overhead())
	sealed := aead.Seal(dst[:0], unsafe.Slice((*byte)(unsafe.Pointer(nonce)), n), unsafe.Slice((*byte)(unsafe.Pointer(plain)), int(plainLen)), unsafe.Slice((*byte)(unsafe.Pointer(aad)), int(aadLen)))
	if len(sealed) != len(dst) {
		return 0
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(tag)), aead.Overhead()), sealed[int(plainLen):])
	return 1
}

//export enczGoAEADOpen
func enczGoAEADOpen(cipherID C.uint, key, nonce, tag, out, ciphertext, aad *C.uchar, ciphertextLen, aadLen C.int) C.int {
	if key == nil || nonce == nil || out == nil || tag == nil || ciphertext == nil || aad == nil || ciphertextLen < 0 || aadLen < 0 {
		return 0
	}
	algorithm, err := cipherFromID(uint32(cipherID))
	if err != nil {
		return 0
	}
	aead, err := newCipherAEAD(algorithm, unsafe.Slice((*byte)(unsafe.Pointer(key)), 32))
	if err != nil {
		return 0
	}
	plainLen := int(ciphertextLen)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(out)), plainLen)
	sealed := make([]byte, plainLen+aead.Overhead())
	copy(sealed, unsafe.Slice((*byte)(unsafe.Pointer(ciphertext)), int(ciphertextLen)))
	copy(sealed[plainLen:], unsafe.Slice((*byte)(unsafe.Pointer(tag)), aead.Overhead()))
	opened, err := aead.Open(dst[:0], unsafe.Slice((*byte)(unsafe.Pointer(nonce)), aead.NonceSize()), sealed, unsafe.Slice((*byte)(unsafe.Pointer(aad)), int(aadLen)))
	if err != nil || len(opened) != plainLen {
		return 0
	}
	return 1
}
