package ims

import (
	"bytes"
	"testing"

	"github.com/damonto/ims-client/usim"
)

func TestParseSecurityHeader(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  SecurityParam
	}{
		{"single", "ipsec-3gpp;alg=hmac-md5-96;ealg=null;mod=trans;port-c=5062;port-s=5060;prot=esp;spi-c=10;spi-s=20", SecurityParam{Mechanism: "ipsec-3gpp", Alg: "hmac-md5-96", EAlg: "null", Mod: "trans", PortC: 5062, PortS: 5060, Prot: "esp", SPIC: 10, SPIS: 20}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got SecurityParams
			if err := got.UnmarshalText([]byte(tt.value)); err != nil {
				t.Fatalf("UnmarshalText() error = %v", err)
			}
			if len(got) != 1 || got[0] != tt.want {
				t.Fatalf("UnmarshalText() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestComputeAKAResponse(t *testing.T) {
	res := usim.AKAResult{RES: bytes.Repeat([]byte{0x11}, 8)}
	nonce := "AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI="
	got, err := computeAKAResponse("001010123456789@ims.mnc001.mcc001.3gppnetwork.org", "ims.mnc001.mcc001.3gppnetwork.org", "sip:ims.mnc001.mcc001.3gppnetwork.org", nonce, res)
	if err != nil {
		t.Fatalf("computeAKAResponse() error = %v", err)
	}
	if got == "" {
		t.Fatal("computeAKAResponse() = empty, want non-empty")
	}
}

func TestParseAuthInfo(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "empty", value: "", want: ""},
		{name: "nextnonce", value: `nextnonce="abc",rspauth="def"`, want: "abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got AuthInfo
			if err := got.UnmarshalText([]byte(tt.value)); err != nil {
				t.Fatalf("UnmarshalText() error = %v", err)
			}
			if got.NextNonce != tt.want {
				t.Fatalf("UnmarshalText() nextnonce = %q, want %q", got.NextNonce, tt.want)
			}
		})
	}
}
