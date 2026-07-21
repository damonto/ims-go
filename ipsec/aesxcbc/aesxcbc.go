// Package aesxcbc implements the AES-XCBC algorithms used by IPsec and IKE.
package aesxcbc

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const (
	KeySize = 16
	Size    = aes.BlockSize
)

var errInvalidKeySize = errors.New("AES-XCBC key must be 16 bytes")

// MAC returns the 128-bit AES-XCBC-MAC defined by RFC 3566.
func MAC(key, message []byte) ([Size]byte, error) {
	if len(key) != KeySize {
		return [Size]byte{}, errInvalidKeySize
	}

	keyCipher, err := aes.NewCipher(key)
	if err != nil {
		return [Size]byte{}, err
	}
	k1 := deriveKey(keyCipher, 0x01)
	k2 := deriveKey(keyCipher, 0x02)
	k3 := deriveKey(keyCipher, 0x03)

	macCipher, err := aes.NewCipher(k1[:])
	if err != nil {
		return [Size]byte{}, err
	}

	var state [Size]byte
	lastStart := len(message) - len(message)%Size
	if len(message) > 0 && len(message)%Size == 0 {
		lastStart -= Size
	}
	for offset := 0; offset < lastStart; offset += Size {
		block := xorBlock(message[offset:offset+Size], state[:])
		macCipher.Encrypt(state[:], block[:])
	}

	var last [Size]byte
	complete := len(message) > 0 && len(message)-lastStart == Size
	if complete {
		copy(last[:], message[lastStart:])
		xorInPlace(last[:], k2[:])
	} else {
		copy(last[:], message[lastStart:])
		last[len(message)-lastStart] = 0x80
		xorInPlace(last[:], k3[:])
	}
	xorInPlace(last[:], state[:])
	macCipher.Encrypt(state[:], last[:])
	return state, nil
}

// PRF returns AES-XCBC-PRF-128 as defined by RFC 4434.
func PRF(key, message []byte) ([Size]byte, error) {
	var normalized [KeySize]byte
	switch {
	case len(key) <= KeySize:
		copy(normalized[:], key)
	default:
		shortened, err := MAC(normalized[:], key)
		if err != nil {
			return [Size]byte{}, err
		}
		normalized = shortened
	}
	return MAC(normalized[:], message)
}

func deriveKey(blockCipher cipher.Block, value byte) [Size]byte {
	input := [Size]byte{}
	for i := range input {
		input[i] = value
	}
	var key [Size]byte
	blockCipher.Encrypt(key[:], input[:])
	return key
}

func xorBlock(left, right []byte) [Size]byte {
	var result [Size]byte
	for i := range Size {
		result[i] = left[i] ^ right[i]
	}
	return result
}

func xorInPlace(dst, value []byte) {
	for i := range Size {
		dst[i] ^= value[i]
	}
}
