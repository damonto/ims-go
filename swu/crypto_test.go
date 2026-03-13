package swu

import (
	"bytes"
	"math/big"
	"testing"
)

func TestSharedSecretPreservesGroupLength(t *testing.T) {
	crypto := &ikeCrypto{
		private:       big.NewInt(1),
		groupPrime:    big.NewInt(257),
		groupByteSize: 2,
	}

	got, err := crypto.sharedSecret([]byte{0x01})
	if err != nil {
		t.Fatalf("sharedSecret() error = %v", err)
	}
	want := []byte{0x00, 0x01}
	if !bytes.Equal(got, want) {
		t.Fatalf("sharedSecret() = %x, want %x", got, want)
	}
}

func TestPRFPlusRejectsOversizeOutput(t *testing.T) {
	crypto := &ikeCrypto{prf: transformPRFHMACSHA1}
	_, err := crypto.prfPlus([]byte("key"), []byte("seed"), crypto.prfLength()*255+1)
	if err == nil {
		t.Fatal("prfPlus() error = nil, want non-nil")
	}
}
