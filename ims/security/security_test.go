package security

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"testing"

	"github.com/damonto/uicc-go/usim"
)

type stubAKAProvider struct{}

func (stubAKAProvider) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	return usim.AKAResult{
		RES: []byte("password"),
		CK:  []byte("client-test-ck"),
		IK:  []byte("client-test-ik"),
	}, nil
}

type orderAKAProvider struct {
	firstRAND []byte
	firstAUTN []byte
	first     usim.AKAResult
	firstErr  error
}

func (p orderAKAProvider) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	if bytes.Equal(rand, p.firstRAND) && bytes.Equal(autn, p.firstAUTN) {
		return p.first, p.firstErr
	}
	return usim.AKAResult{
		RES: []byte("password"),
		CK:  []byte("client-test-ck"),
		IK:  []byte("client-test-ik"),
	}, nil
}

type fixedAKAProvider struct {
	result usim.AKAResult
	calls  int
}

func (p *fixedAKAProvider) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	p.calls++
	return p.result, nil
}

func TestParamUnmarshalText(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  Params
	}{
		{
			name:  "compact",
			value: "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=5062;port-s=5060;prot=esp;spi-c=310;spi-s=320",
			want: Params{{
				Mechanism: "ipsec-3gpp",
				Alg:       "hmac-sha-1-96",
				EAlg:      "null",
				Mod:       "trans",
				PortC:     5062,
				PortS:     5060,
				Prot:      "esp",
				SPIC:      310,
				SPIS:      320,
			}},
		},
		{
			name:  "optional whitespace",
			value: " ipsec-3gpp ; alg = hmac-sha-1-96 ; ealg = null ; mod = trans ; port-c = 5062 ; port-s= 5060 ; prot = esp ; spi-c = 2291967259 ; spi-s = 320 ; q = 0.9 ",
			want: Params{{
				Mechanism: "ipsec-3gpp",
				Alg:       "hmac-sha-1-96",
				EAlg:      "null",
				Mod:       "trans",
				PortC:     5062,
				PortS:     5060,
				Prot:      "esp",
				SPIC:      2291967259,
				SPIS:      320,
				Q:         "0.9",
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Params
			if err := got.UnmarshalText([]byte(tt.value)); err != nil {
				t.Fatalf("UnmarshalText() error = %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("len(UnmarshalText()) = %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("UnmarshalText()[%d] = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParamsString(t *testing.T) {
	tests := []struct {
		name string
		in   Params
		want string
	}{
		{
			name: "multiple mechanisms",
			in: Params{
				{Mechanism: "ipsec-3gpp", Alg: "hmac-sha-1-96", EAlg: "null", Mod: "trans", PortC: 5062, PortS: 5063, Prot: "esp", SPIC: 310, SPIS: 320},
				{Mechanism: "ipsec-3gpp", Alg: "hmac-sha-1-96", EAlg: "aes-cbc", Mod: "trans", PortC: 5062, PortS: 5063, Prot: "esp", SPIC: 310, SPIS: 320},
			},
			want: "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=5062;port-s=5063;prot=esp;spi-c=310;spi-s=320,ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;mod=trans;port-c=5062;port-s=5063;prot=esp;spi-c=310;spi-s=320",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.String(); got != tt.want {
				t.Fatalf("Params.String() = %q, want %q", got, tt.want)
			}
		})
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
				SPIC:      310,
				SPIS:      320,
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
				SPIC:      310,
				SPIS:      320,
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
				SPIC:      310,
				SPIS:      320,
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
				SPIC:      310,
				SPIS:      320,
			},
		},
		{
			name: "defaults omitted encryption algorithm",
			in: Param{
				Mechanism: "ipsec-3gpp",
				Alg:       "hmac-sha-1-96",
				Mod:       "trans",
				PortC:     5062,
				PortS:     5060,
				SPIC:      310,
				SPIS:      320,
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
				SPIC:      310,
				SPIS:      320,
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
				SPIC:      310,
				SPIS:      320,
			},
			ok: false,
		},
		{
			name: "rejects security header sha256 integrity algorithm",
			in: Param{
				Mechanism: "ipsec-3gpp",
				Alg:       "hmac-sha-256-128",
				EAlg:      "null",
				Mod:       "trans",
				PortC:     5062,
				PortS:     5060,
				Prot:      "esp",
				SPIC:      310,
				SPIS:      320,
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
				SPIC:      310,
				SPIS:      320,
			},
			ok: false,
		},
		{
			name: "rejects zero protected client port",
			in: Param{
				Mechanism: "ipsec-3gpp",
				Alg:       "hmac-sha-1-96",
				EAlg:      "null",
				Mod:       "trans",
				PortS:     5060,
				Prot:      "esp",
				SPIC:      310,
				SPIS:      320,
			},
			ok: false,
		},
		{
			name: "rejects reserved client spi",
			in: Param{
				Mechanism: "ipsec-3gpp",
				Alg:       "hmac-sha-1-96",
				EAlg:      "null",
				Mod:       "trans",
				PortC:     5062,
				PortS:     5060,
				Prot:      "esp",
				SPIC:      255,
				SPIS:      320,
			},
			ok: false,
		},
		{
			name: "rejects reserved server spi",
			in: Param{
				Mechanism: "ipsec-3gpp",
				Alg:       "hmac-sha-1-96",
				EAlg:      "null",
				Mod:       "trans",
				PortC:     5062,
				PortS:     5060,
				Prot:      "esp",
				SPIC:      310,
				SPIS:      255,
			},
			ok: false,
		},
		{
			name: "rejects out of range protected server port",
			in: Param{
				Mechanism: "ipsec-3gpp",
				Alg:       "hmac-sha-1-96",
				EAlg:      "null",
				Mod:       "trans",
				PortC:     5062,
				PortS:     65536,
				Prot:      "esp",
				SPIC:      310,
				SPIS:      320,
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
	tests := []struct {
		name    string
		value   string
		wantAlg string
		wantErr bool
	}{
		{
			name:    "ak v1",
			value:   `Digest realm="ims.example",nonce="abc",algorithm=AKAv1-MD5,qop="auth,auth-int"`,
			wantAlg: AlgorithmAKAv1MD5,
		},
		{
			name:    "missing algorithm",
			value:   `Digest realm="ims.example",nonce="abc",qop="auth"`,
			wantErr: true,
		},
		{
			name:    "ak v2",
			value:   `Digest realm="ims.example",nonce="abc",algorithm=AKAv2-MD5,qop="auth,auth-int"`,
			wantAlg: AlgorithmAKAv2MD5,
		},
		{
			name:    "ak v2 sha256",
			value:   `Digest realm="ims.example",nonce="abc",algorithm=AKAv2-SHA-256,qop="auth,auth-int"`,
			wantAlg: AlgorithmAKAv2SHA256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Challenge
			err := got.UnmarshalText([]byte(tt.value))
			if tt.wantErr {
				if err == nil {
					t.Fatal("UnmarshalText() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalText() error = %v", err)
			}
			if got.Realm != "ims.example" || got.Nonce != "abc" || got.Algorithm != tt.wantAlg {
				t.Fatalf("UnmarshalText() = %+v", got)
			}
			qop, err := got.SelectedQOP()
			if err != nil {
				t.Fatalf("SelectedQOP() error = %v", err)
			}
			if qop != "auth" {
				t.Fatalf("SelectedQOP() = %q, want auth", qop)
			}
		})
	}
}

func TestInfoUnmarshalText(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  Info
	}{
		{name: "empty", value: "", want: Info{}},
		{
			name:  "digest fields",
			value: `nextnonce="abc",qop=auth,rspauth="def",cnonce="1234",nc=00000001`,
			want: Info{
				NextNonce:  "abc",
				QOP:        "auth",
				RSPAuth:    "def",
				CNonce:     "1234",
				NonceCount: "00000001",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Info
			if err := got.UnmarshalText([]byte(tt.value)); err != nil {
				t.Fatalf("UnmarshalText() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("UnmarshalText() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestInfoMarshalText(t *testing.T) {
	tests := []struct {
		name string
		info Info
		want string
	}{
		{name: "empty", info: Info{}, want: ""},
		{
			name: "digest fields",
			info: Info{
				NextNonce:  "abc",
				QOP:        "auth",
				RSPAuth:    "def",
				CNonce:     "1234",
				NonceCount: "00000001",
			},
			want: `nextnonce="abc",qop=auth,rspauth="def",cnonce="1234",nc=00000001`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.info.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("MarshalText() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildAKAAuthorization(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
	}{
		{name: "AKAv1-MD5", algorithm: AlgorithmAKAv1MD5},
		{name: "AKAv2-MD5", algorithm: AlgorithmAKAv2MD5},
		{name: "AKAv2-SHA-256", algorithm: AlgorithmAKAv2SHA256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge := Challenge{
				Realm:     "ims.mnc001.mcc001.3gppnetwork.org",
				Nonce:     "AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=",
				Algorithm: tt.algorithm,
				QOP:       "auth",
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
			if got.Authorization.Algorithm != tt.algorithm {
				t.Fatalf("Authorization.Algorithm = %q, want %q", got.Authorization.Algorithm, tt.algorithm)
			}
			if got.Authorization.QOP != "auth" {
				t.Fatalf("Authorization.QOP = %q, want auth", got.Authorization.QOP)
			}
			if got.Authorization.NonceCount != "00000001" {
				t.Fatalf("Authorization.NonceCount = %q, want 00000001", got.Authorization.NonceCount)
			}
			if tt.algorithm == AlgorithmAKAv1MD5 {
				if !bytes.Equal(got.IntegrityKey, []byte("client-test-ik")) {
					t.Fatalf("IntegrityKey = %X, want original IK", got.IntegrityKey)
				}
				if !bytes.Equal(got.EncryptionKey, []byte("client-test-ck")) {
					t.Fatalf("EncryptionKey = %X, want original CK", got.EncryptionKey)
				}
			}
			if len(got.IntegrityKey) == 0 || len(got.EncryptionKey) == 0 {
				t.Fatalf("security keys = CK:%X IK:%X, want non-empty", got.EncryptionKey, got.IntegrityKey)
			}
			text, err := got.Authorization.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			if !bytes.Contains(text, []byte(`algorithm=`+tt.algorithm)) {
				t.Fatalf("MarshalText() = %q", text)
			}
		})
	}
}

func TestVerifyAuthenticationInfoRspauth(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		newHash   func() hash.Hash
		mutate    func(*Info, Authorization)
		wantErr   bool
	}{
		{
			name:      "valid AKAv1 response auth",
			algorithm: AlgorithmAKAv1MD5,
			newHash:   md5.New,
		},
		{
			name:      "valid AKAv2 SHA-256 response auth",
			algorithm: AlgorithmAKAv2SHA256,
			newHash:   sha256.New,
		},
		{
			name:      "rejects rspauth mismatch",
			algorithm: AlgorithmAKAv1MD5,
			newHash:   md5.New,
			mutate: func(info *Info, auth Authorization) {
				info.RSPAuth = "00000000000000000000000000000000"
			},
			wantErr: true,
		},
		{
			name:      "rejects cnonce mismatch",
			algorithm: AlgorithmAKAv1MD5,
			newHash:   md5.New,
			mutate: func(info *Info, auth Authorization) {
				info.CNonce = "different"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const password = "password"
			auth, err := BuildDigestAuthorization(Identity{
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				RegisterURI:     "sip:ims.mnc001.mcc001.3gppnetwork.org",
				Realm:           "ims.mnc001.mcc001.3gppnetwork.org",
			}, Challenge{
				Realm:     "ims.mnc001.mcc001.3gppnetwork.org",
				Nonce:     "AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=",
				Algorithm: tt.algorithm,
				QOP:       "auth",
			}, 1, password)
			if err != nil {
				t.Fatalf("BuildDigestAuthorization() error = %v", err)
			}
			rspauth, err := computeAKAResponse(tt.newHash, "", auth.Username, auth.Realm, auth.URI, auth.Nonce, password, auth.QOP, auth.CNonce, auth.NonceCount)
			if err != nil {
				t.Fatalf("computeAKAResponse() error = %v", err)
			}
			info := Info{
				QOP:        auth.QOP,
				RSPAuth:    rspauth,
				CNonce:     auth.CNonce,
				NonceCount: auth.NonceCount,
			}
			if tt.mutate != nil {
				tt.mutate(&info, auth)
			}
			err = VerifyAuthenticationInfo(auth, info, password)
			if tt.wantErr && err == nil {
				t.Fatal("VerifyAuthenticationInfo() error = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("VerifyAuthenticationInfo() error = %v", err)
			}
		})
	}
}

func TestAKAv2DigestMaterial(t *testing.T) {
	tests := []struct {
		name      string
		algorithm akaAlgorithm
		want      string
		wantCK    string
		wantIK    string
	}{
		{
			name:      "MD5",
			algorithm: akaAlgorithm{name: AlgorithmAKAv2MD5, version: 2, hash: md5.New},
			want:      "TtuwzaqZ7soUouuSCdSNaQ==",
			wantCK:    "6522558715b39bc95c9e5d20c33c80cc",
			wantIK:    "4b52e9b1e62283ceaddd232105a50d12",
		},
		{
			name:      "SHA-256",
			algorithm: akaAlgorithm{name: AlgorithmAKAv2SHA256, version: 2, hash: sha256.New},
			want:      "jZXL3KmEQP/njEp8Bo6Vc3mBYB4tF/l+pYRQKkpaVOQ=",
			wantCK:    "dc2d28bd98a85c3e210e37ed76c39df320c0f30245fd6638befe27dfa3eee11e",
			wantIK:    "81f3ce5e9f4d2f1daeef6cc196b072305de46146970e3aee4050d7dcd26cfc6b",
		},
	}

	aka := usim.AKAResult{
		RES: []byte("password"),
		CK:  []byte("client-test-ck"),
		IK:  []byte("client-test-ik"),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, ck, ik := akaDigestMaterial(tt.algorithm, aka)
			if password != tt.want {
				t.Fatalf("akaDigestMaterial() password = %q, want %q", password, tt.want)
			}
			if hex.EncodeToString(ck) != tt.wantCK {
				t.Fatalf("akaDigestMaterial() CK = %X, want %s", ck, tt.wantCK)
			}
			if hex.EncodeToString(ik) != tt.wantIK {
				t.Fatalf("akaDigestMaterial() IK = %X, want %s", ik, tt.wantIK)
			}
		})
	}
}

func TestBuildAKAAuthorizationRetriesReversedNonceOrder(t *testing.T) {
	tests := []struct {
		name     string
		first    usim.AKAResult
		firstErr error
	}{
		{
			name:     "first order returns error",
			firstErr: errors.New("authentication rejected"),
		},
		{
			name: "first order returns incomplete security material",
			first: usim.AKAResult{
				RES: []byte("password"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge := Challenge{
				Realm:     "one.att.net",
				Nonce:     "AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=",
				Algorithm: "AKAv1-MD5",
				QOP:       "auth",
			}

			got, err := BuildAKAAuthorization(context.Background(), orderAKAProvider{
				firstRAND: bytes.Repeat([]byte{0x01}, 16),
				firstAUTN: bytes.Repeat([]byte{0x02}, 16),
				first:     tt.first,
				firstErr:  tt.firstErr,
			}, Identity{
				PrivateIdentity: "310280123456789@private.att.net",
				RegisterURI:     "sip:one.att.net",
				Realm:           "one.att.net",
			}, challenge, 1)
			if err != nil {
				t.Fatalf("BuildAKAAuthorization() error = %v", err)
			}
			if got.Authorization.Response == "" {
				t.Fatal("Authorization.Response = empty, want non-empty")
			}
			if len(got.EncryptionKey) == 0 || len(got.IntegrityKey) == 0 {
				t.Fatalf("security keys = CK:%X IK:%X, want non-empty", got.EncryptionKey, got.IntegrityKey)
			}
		})
	}
}

func TestBuildAKAAuthorizationReportsUSIMChallengeFailure(t *testing.T) {
	auts := []byte{0x33, 0xd5, 0x8d, 0x39, 0x61, 0x9c, 0x21, 0x33, 0x67, 0xe3, 0x76, 0x11, 0x53, 0x15}
	tests := []struct {
		name     string
		result   usim.AKAResult
		wantAUTS []byte
		wantSync bool
	}{
		{
			name:     "synchronization failure keeps AUTS",
			result:   usim.AKAResult{AUTS: auts},
			wantAUTS: auts,
			wantSync: true,
		},
		{
			name:   "network authentication reject",
			result: usim.AKAResult{Reject: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &fixedAKAProvider{result: tt.result}
			_, err := BuildAKAAuthorization(context.Background(), provider, Identity{
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				RegisterURI:     "sip:ims.mnc001.mcc001.3gppnetwork.org",
				Realm:           "ims.mnc001.mcc001.3gppnetwork.org",
			}, Challenge{
				Realm:     "ims.mnc001.mcc001.3gppnetwork.org",
				Nonce:     "AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=",
				Algorithm: "AKAv1-MD5",
				QOP:       "auth",
			}, 1)
			var failure *AKAChallengeFailure
			if !errors.As(err, &failure) {
				t.Fatalf("BuildAKAAuthorization() error = %v, want AKAChallengeFailure", err)
			}
			if failure.SynchronizationFailure() != tt.wantSync {
				t.Fatalf("SynchronizationFailure() = %t, want %t", failure.SynchronizationFailure(), tt.wantSync)
			}
			if !bytes.Equal(failure.AUTS, tt.wantAUTS) {
				t.Fatalf("AUTS = %X, want %X", failure.AUTS, tt.wantAUTS)
			}
			if provider.calls != 1 {
				t.Fatalf("AKA calls = %d, want no reversed retry after USIM challenge failure", provider.calls)
			}
		})
	}
}
