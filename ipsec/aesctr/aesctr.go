// Package aesctr implements the AES counter construction used by RFC 3686.
package aesctr

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	SaltSize = 4
	IVSize   = 8
)

// Crypt encrypts or decrypts src using the RFC 3686 counter block layout.
func Crypt(key, salt, iv, src []byte) ([]byte, error) {
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("AES-CTR salt length = %d, want %d", len(salt), SaltSize)
	}
	if len(iv) != IVSize {
		return nil, fmt.Errorf("AES-CTR IV length = %d, want %d", len(iv), IVSize)
	}
	if uint64(len(src)) > uint64(^uint32(0))*uint64(aes.BlockSize) {
		return nil, errors.New("AES-CTR input exceeds 32-bit counter space")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES-CTR cipher: %w", err)
	}
	counter := make([]byte, aes.BlockSize)
	copy(counter[:SaltSize], salt)
	copy(counter[SaltSize:SaltSize+IVSize], iv)
	binary.BigEndian.PutUint32(counter[SaltSize+IVSize:], 1)
	out := make([]byte, len(src))
	cipher.NewCTR(block, counter).XORKeyStream(out, src)
	return out, nil
}
