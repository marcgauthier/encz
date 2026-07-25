package encz

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// Cipher identifies the authenticated encryption algorithm used by an encz
// database and all of its associated encrypted containers.
type Cipher string

const (
	CipherAES256GCM         Cipher = "aes-256-gcm"
	CipherChaCha20Poly1305  Cipher = "chacha20-poly1305"
	CipherXChaCha20Poly1305 Cipher = "xchacha20-poly1305"
	CipherChaChaPoly        Cipher = CipherChaCha20Poly1305
	CipherXChaChaPoly       Cipher = CipherXChaCha20Poly1305
	defaultCipher                  = CipherAES256GCM
)

const (
	cipherIDAES256GCM uint32 = iota + 1
	cipherIDChaCha20Poly1305
	cipherIDXChaCha20Poly1305
)

var (
	ErrCipherUnsupported       = errors.New("encz: unsupported cipher")
	ErrCipherMismatch          = errors.New("encz: requested cipher does not match database cipher")
	ErrLegacyFormatUnsupported = errors.New("encz: legacy Monocypher format is unsupported")
)

func normalizeCipher(value Cipher) (Cipher, error) {
	if value == "" {
		return defaultCipher, nil
	}
	switch value {
	case CipherAES256GCM, CipherChaCha20Poly1305, CipherXChaCha20Poly1305:
		return value, nil
	default:
		return "", ErrCipherUnsupported
	}
}

func cipherID(value Cipher) (uint32, error) {
	value, err := normalizeCipher(value)
	if err != nil {
		return 0, err
	}
	switch value {
	case CipherAES256GCM:
		return cipherIDAES256GCM, nil
	case CipherChaCha20Poly1305:
		return cipherIDChaCha20Poly1305, nil
	default:
		return cipherIDXChaCha20Poly1305, nil
	}
}

func cipherFromID(id uint32) (Cipher, error) {
	switch id {
	case cipherIDAES256GCM:
		return CipherAES256GCM, nil
	case cipherIDChaCha20Poly1305:
		return CipherChaCha20Poly1305, nil
	case cipherIDXChaCha20Poly1305:
		return CipherXChaCha20Poly1305, nil
	default:
		return "", ErrCipherUnsupported
	}
}

func newCipherAEAD(value Cipher, key []byte) (cipher.AEAD, error) {
	value, err := normalizeCipher(value)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, ErrCipherUnsupported
	}
	switch value {
	case CipherAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case CipherChaCha20Poly1305:
		return chacha20poly1305.New(key)
	case CipherXChaCha20Poly1305:
		return chacha20poly1305.NewX(key)
	default:
		return nil, ErrCipherUnsupported
	}
}
