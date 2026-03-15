package security

import (
	"bytes"
	"context"
	"testing"

	"github.com/damonto/ims-client/usim"
)

type stubAKAProvider struct{}

func (stubAKAProvider) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	return usim.AKAResult{
		RES: []byte("password"),
		IK:  []byte("client-test-ik"),
	}, nil
}

func TestParamUnmarshalText(t *testing.T) {
	var got Params
	err := got.UnmarshalText([]byte("ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=5062;port-s=5060;prot=esp;spi-c=10;spi-s=20"))
	if err != nil {
		t.Fatalf("UnmarshalText() error = %v", err)
	}
	want := Param{
		Mechanism: "ipsec-3gpp",
		Alg:       "hmac-sha-1-96",
		EAlg:      "null",
		Mod:       "trans",
		PortC:     5062,
		PortS:     5060,
		Prot:      "esp",
		SPIC:      10,
		SPIS:      20,
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("UnmarshalText() = %+v, want %+v", got, want)
	}
}

func TestNormalizeParam(t *testing.T) {
	tests := []struct {
		name string
		in   Param
		ok   bool
		want Param
	}{
		{
			name: "normalizes alias",
			in: Param{
				Mechanism: "ipsec-3gpp",
				Alg:       "hmac-sha-1-96",
				EAlg:      "null",
				Mod:       "trans",
				PortC:     5062,
				PortS:     5060,
				Prot:      "esp",
				SPIC:      10,
				SPIS:      20,
			},
			ok: true,
			want: Param{
				Mechanism: "ipsec-3gpp",
				Alg:       "hmac-sha1-96",
				EAlg:      "null",
				Mod:       "trans",
				PortC:     5062,
				PortS:     5060,
				Prot:      "esp",
				SPIC:      10,
				SPIS:      20,
			},
		},
		{
			name: "defaults omitted protocol",
			in: Param{
				Mechanism: "ipsec-3gpp",
				Alg:       "hmac-sha-1-96",
				EAlg:      "null",
				PortC:     5062,
				PortS:     5060,
				SPIC:      10,
				SPIS:      20,
			},
			ok: true,
			want: Param{
				Mechanism: "ipsec-3gpp",
				Alg:       "hmac-sha1-96",
				EAlg:      "null",
				Mod:       "trans",
				PortC:     5062,
				PortS:     5060,
				Prot:      "esp",
				SPIC:      10,
				SPIS:      20,
			},
		},
		{
			name: "rejects removed md5 integrity algorithm",
			in: Param{
				Mechanism: "ipsec-3gpp",
				Alg:       "hmac-md5-96",
				EAlg:      "null",
				Mod:       "trans",
				PortC:     5062,
				PortS:     5060,
				Prot:      "esp",
				SPIC:      10,
				SPIS:      20,
			},
			ok: false,
		},
		{
			name: "rejects incompatible mechanism",
			in: Param{
				Mechanism: "tls",
				Alg:       "hmac-sha-1-96",
				EAlg:      "null",
				Mod:       "trans",
				PortC:     5062,
				PortS:     5060,
				Prot:      "esp",
				SPIC:      10,
				SPIS:      20,
			},
			ok: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NormalizeParam(tt.in)
			if ok != tt.ok {
				t.Fatalf("NormalizeParam() ok = %t, want %t", ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Fatalf("NormalizeParam() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestChallengeUnmarshalText(t *testing.T) {
	var got Challenge
	err := got.UnmarshalText([]byte(`Digest realm="ims.example",nonce="abc",algorithm=AKAv1-MD5,qop="auth,auth-int"`))
	if err != nil {
		t.Fatalf("UnmarshalText() error = %v", err)
	}
	if got.Realm != "ims.example" || got.Nonce != "abc" || got.Algorithm != "AKAv1-MD5" {
		t.Fatalf("UnmarshalText() = %+v", got)
	}
	qop, err := got.SelectedQOP()
	if err != nil {
		t.Fatalf("SelectedQOP() error = %v", err)
	}
	if qop != "auth" {
		t.Fatalf("SelectedQOP() = %q, want auth", qop)
	}
}

func TestInfoUnmarshalText(t *testing.T) {
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
			var got Info
			if err := got.UnmarshalText([]byte(tt.value)); err != nil {
				t.Fatalf("UnmarshalText() error = %v", err)
			}
			if got.NextNonce != tt.want {
				t.Fatalf("UnmarshalText() nextnonce = %q, want %q", got.NextNonce, tt.want)
			}
		})
	}
}

func TestBuildAKAAuthorization(t *testing.T) {
	challenge := Challenge{
		Realm: "ims.mnc001.mcc001.3gppnetwork.org",
		Nonce: "AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=",
		QOP:   "auth",
	}

	got, err := BuildAKAAuthorization(context.Background(), stubAKAProvider{}, Identity{
		PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
		RegisterURI:     "sip:ims.mnc001.mcc001.3gppnetwork.org",
		Realm:           "ims.mnc001.mcc001.3gppnetwork.org",
	}, challenge, 1)
	if err != nil {
		t.Fatalf("BuildAKAAuthorization() error = %v", err)
	}
	if got.Authorization.Response == "" {
		t.Fatal("Authorization.Response = empty, want non-empty")
	}
	if got.Authorization.QOP != "auth" {
		t.Fatalf("Authorization.QOP = %q, want auth", got.Authorization.QOP)
	}
	if got.Authorization.NonceCount != "00000001" {
		t.Fatalf("Authorization.NonceCount = %q, want 00000001", got.Authorization.NonceCount)
	}
	if !bytes.Equal(got.IntegrityKey, []byte("client-test-ik")) {
		t.Fatalf("IntegrityKey = %q, want %q", got.IntegrityKey, []byte("client-test-ik"))
	}
	text, err := got.Authorization.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	if !bytes.Contains(text, []byte(`algorithm=AKAv1-MD5`)) {
		t.Fatalf("MarshalText() = %q", text)
	}
}
