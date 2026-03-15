package tunnel

import "testing"

func TestNewConnectCryptoStateUses32ByteNonce(t *testing.T) {
	crypto, _, _, nonceI, err := newConnectCryptoState(transformDH1024MODP)
	if err != nil {
		t.Fatalf("newConnectCryptoState() error = %v", err)
	}
	if len(nonceI) != 32 {
		t.Fatalf("len(nonceI) = %d, want 32", len(nonceI))
	}
	if len(crypto.nonceI) != 32 {
		t.Fatalf("len(crypto.nonceI) = %d, want 32", len(crypto.nonceI))
	}
}
