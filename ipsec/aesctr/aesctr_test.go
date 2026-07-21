package aesctr

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestCryptRFC3686(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		salt       string
		iv         string
		plaintext  string
		ciphertext string
	}{
		{
			name:       "128 bit key",
			key:        "ae6852f8121067cc4bf7a5765577f39e",
			salt:       "00000030",
			iv:         "0000000000000000",
			plaintext:  "53696e676c6520626c6f636b206d7367",
			ciphertext: "e4095d4fb7a7b3792d6175a3261311b8",
		},
		{
			name:       "192 bit key",
			key:        "16af5b145fc9f579c175f93e3bfb0eed863d06ccfdb78515",
			salt:       "00000048",
			iv:         "36733c147d6d93cb",
			plaintext:  "53696e676c6520626c6f636b206d7367",
			ciphertext: "4b55384fe259c9c84e7935a003cbe928",
		},
		{
			name:       "256 bit key",
			key:        "776beff2851db06f4c8a0542c8696f6c6a81af1eec96b4d37fc1d689e6c1c104",
			salt:       "00000060",
			iv:         "db5672c97aa8f0b2",
			plaintext:  "53696e676c6520626c6f636b206d7367",
			ciphertext: "145ad01dbf824ec7560863dc71e3e0c0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := decodeHex(t, tt.key)
			salt := decodeHex(t, tt.salt)
			iv := decodeHex(t, tt.iv)
			plaintext := decodeHex(t, tt.plaintext)
			want := decodeHex(t, tt.ciphertext)
			got, err := Crypt(key, salt, iv, plaintext)
			if err != nil {
				t.Fatalf("Crypt() error = %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("Crypt() = %x, want %x", got, want)
			}
			decrypted, err := Crypt(key, salt, iv, got)
			if err != nil {
				t.Fatalf("Crypt(decrypt) error = %v", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("Crypt(decrypt) = %x, want %x", decrypted, plaintext)
			}
		})
	}
}

func TestCryptRejectsInvalidParameters(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
		salt []byte
		iv   []byte
	}{
		{name: "invalid key", key: make([]byte, 15), salt: make([]byte, SaltSize), iv: make([]byte, IVSize)},
		{name: "invalid salt", key: make([]byte, 16), salt: make([]byte, SaltSize-1), iv: make([]byte, IVSize)},
		{name: "invalid IV", key: make([]byte, 16), salt: make([]byte, SaltSize), iv: make([]byte, IVSize-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Crypt(tt.key, tt.salt, tt.iv, nil); err == nil {
				t.Fatal("Crypt() error = nil, want parameter error")
			}
		})
	}
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString(%q): %v", value, err)
	}
	return decoded
}
