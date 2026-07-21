package aesxcbc

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestMACRFC3566(t *testing.T) {
	key := decodeHex(t, "000102030405060708090a0b0c0d0e0f")
	tests := []struct {
		name    string
		message []byte
		want    string
	}{
		{name: "empty", want: "75f0251d528ac01c4573dfd584d79f29"},
		{name: "three bytes", message: decodeHex(t, "000102"), want: "5b376580ae2f19afe7219ceef172756f"},
		{name: "one block", message: decodeHex(t, "000102030405060708090a0b0c0d0e0f"), want: "d2a246fa349b68a79998a4394ff7a263"},
		{name: "twenty bytes", message: decodeHex(t, "000102030405060708090a0b0c0d0e0f10111213"), want: "47f51b4564966215b8985c63055ed308"},
		{name: "two blocks", message: decodeHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), want: "f54f0ec8d2b9f3d36807734bd5283fd4"},
		{name: "thirty four bytes", message: decodeHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"), want: "becbb3bccdb518a30677d5481fb6b4d8"},
		{name: "one thousand zero bytes", message: make([]byte, 1000), want: "f0dafee895db30253761103b5d84528f"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MAC(key, tt.message)
			if err != nil {
				t.Fatalf("MAC() error = %v", err)
			}
			want := decodeHex(t, tt.want)
			if !bytes.Equal(got[:], want) {
				t.Fatalf("MAC() = %x, want %x", got, want)
			}
		})
	}
}

func TestPRFRFC4434(t *testing.T) {
	message := decodeHex(t, "000102030405060708090a0b0c0d0e0f10111213")
	tests := []struct {
		name string
		key  string
		want string
	}{
		{name: "sixteen byte key", key: "000102030405060708090a0b0c0d0e0f", want: "47f51b4564966215b8985c63055ed308"},
		{name: "short key", key: "00010203040506070809", want: "0fa087af7d866e7653434e602fdde835"},
		{name: "long key", key: "000102030405060708090a0b0c0d0e0fedcb", want: "8cd3c93ae598a9803006ffb67c40e9e4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PRF(decodeHex(t, tt.key), message)
			if err != nil {
				t.Fatalf("PRF() error = %v", err)
			}
			want := decodeHex(t, tt.want)
			if !bytes.Equal(got[:], want) {
				t.Fatalf("PRF() = %x, want %x", got, want)
			}
		})
	}
}

func TestMACRejectsInvalidKeyLength(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{name: "empty"},
		{name: "short", key: make([]byte, KeySize-1)},
		{name: "long", key: make([]byte, KeySize+1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := MAC(tt.key, nil); err == nil {
				t.Fatal("MAC() error = nil, want invalid key length")
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
