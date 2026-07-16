package eapaka

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func TestAKAMessageRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		message AKAMessage
	}{
		{
			name: "identity request",
			message: AKAMessage{
				Code:       eapCodeRequest,
				Identifier: 7,
				Subtype:    akaSubtypeIdentity,
				Attributes: []AKAAttribute{{Type: akaAttrRAND, Value: []byte{0x00, 0x00}}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.message.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			var got AKAMessage
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.Code != tt.message.Code || got.Identifier != tt.message.Identifier || got.Subtype != tt.message.Subtype {
				t.Fatalf("AKAMessage = %+v, want %+v", got, tt.message)
			}
		})
	}
}

func TestAKAMessageMarshalBinaryUsesAKAPrimeType(t *testing.T) {
	message := AKAMessage{
		Code:       eapCodeResponse,
		Identifier: 0x10,
		EAPType:    eapTypeAKAPrime,
		Subtype:    akaSubtypeIdentity,
		Attributes: []AKAAttribute{buildAKAStringAttribute(akaAttrIdentity, "6123456789012345")},
	}
	want := []byte{
		0x02, 0x10, 0x00, 0x1c,
		0x32, 0x05, 0x00, 0x00,
		0x0e, 0x05, 0x00, 0x10,
		0x36, 0x31, 0x32, 0x33,
		0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x30, 0x31,
		0x32, 0x33, 0x34, 0x35,
	}

	got, err := message.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("MarshalBinary() = % X, want % X", got, want)
	}

	var parsed AKAMessage
	if err := parsed.UnmarshalBinary(got); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	if parsed.EAPType != eapTypeAKAPrime {
		t.Fatalf("EAPType = %d, want %d", parsed.EAPType, eapTypeAKAPrime)
	}
}

func TestAKAMessageMarshalBinaryRejectsUnsupportedEAPType(t *testing.T) {
	tests := []struct {
		name    string
		eapType byte
	}{
		{name: "identity", eapType: eapTypeIdentity},
		{name: "unknown", eapType: 255},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := AKAMessage{Code: eapCodeResponse, Identifier: 1, EAPType: tt.eapType, Subtype: akaSubtypeChallenge}
			if _, err := message.MarshalBinary(); err == nil {
				t.Fatal("MarshalBinary() error = nil, want error")
			}
		})
	}
}

func TestAKAMessageVerifyMACRejectsInvalidAttributeLength(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
	}{
		{name: "truncated", value: make([]byte, akaMACAttributeLen-4)},
		{name: "too long", value: make([]byte, akaMACAttributeLen+4)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := AKAMessage{
				Code:       eapCodeRequest,
				Identifier: 1,
				Subtype:    akaSubtypeChallenge,
				Attributes: []AKAAttribute{{Type: akaAttrMAC, Value: tt.value}},
			}
			if err := message.VerifyMAC(bytes.Repeat([]byte{0x11}, akaKAutLen), nil); err == nil {
				t.Fatal("VerifyMAC() error = nil, want error")
			}
		})
	}
}

func TestAKAMessageSignedMACValidatesKeyAndAttributes(t *testing.T) {
	tests := []struct {
		name      string
		prime     bool
		key       []byte
		attrs     []AKAAttribute
		wantErr   bool
		verifyKey []byte
	}{
		{name: "aka key", key: bytes.Repeat([]byte{0x11}, akaKAutLen), verifyKey: bytes.Repeat([]byte{0x11}, akaKAutLen)},
		{name: "aka empty key", wantErr: true},
		{name: "aka short key", key: bytes.Repeat([]byte{0x11}, akaKAutLen-1), wantErr: true},
		{name: "aka long key", key: bytes.Repeat([]byte{0x11}, akaKAutLen+1), wantErr: true},
		{name: "aka prime key", prime: true, key: bytes.Repeat([]byte{0x22}, akaPrimeKAutLen), verifyKey: bytes.Repeat([]byte{0x22}, akaPrimeKAutLen)},
		{name: "aka prime rejects aka key", prime: true, key: bytes.Repeat([]byte{0x22}, akaKAutLen), wantErr: true},
		{
			name:    "existing mac",
			key:     bytes.Repeat([]byte{0x11}, akaKAutLen),
			attrs:   []AKAAttribute{{Type: akaAttrMAC, Value: make([]byte, akaMACAttributeLen)}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := AKAMessage{Code: eapCodeResponse, Identifier: 1, Subtype: akaSubtypeChallenge, Attributes: tt.attrs}
			var wire []byte
			var err error
			if tt.prime {
				message.EAPType = eapTypeAKAPrime
				wire, err = message.MarshalSignedSHA256(tt.key, nil)
			} else {
				wire, err = message.MarshalSigned(tt.key, nil)
			}
			if tt.wantErr {
				if err == nil {
					t.Fatal("MarshalSigned() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("MarshalSigned() error = %v", err)
			}
			if tt.prime {
				err = VerifyMessageMACSHA256(wire, tt.verifyKey, nil)
			} else {
				err = VerifyMessageMAC(wire, tt.verifyKey, nil)
			}
			if err != nil {
				t.Fatalf("VerifyMessageMAC() error = %v", err)
			}
		})
	}
}

func TestAKAMessageVerifyMACRejectsWrongKeyLength(t *testing.T) {
	tests := []struct {
		name  string
		prime bool
		key   []byte
	}{
		{name: "aka empty key"},
		{name: "aka prime key used for aka", key: make([]byte, akaPrimeKAutLen)},
		{name: "aka key used for aka prime", prime: true, key: make([]byte, akaKAutLen)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := AKAMessage{Code: eapCodeRequest, Identifier: 1, Subtype: akaSubtypeChallenge, Attributes: []AKAAttribute{{Type: akaAttrMAC, Value: make([]byte, akaMACAttributeLen)}}}
			var err error
			if tt.prime {
				err = message.VerifyMACSHA256(tt.key, nil)
			} else {
				err = message.VerifyMAC(tt.key, nil)
			}
			if err == nil {
				t.Fatal("VerifyMAC() error = nil, want error")
			}
		})
	}
}

func TestDeriveAKAPrimeCKIK(t *testing.T) {
	tests := []struct {
		name        string
		ck          []byte
		ik          []byte
		networkName []byte
		sqnXorAK    []byte
		wantCK      []byte
		wantIK      []byte
		wantErr     bool
	}{
		{
			name:        "reference challenge state vector",
			ck:          mustHex(t, "00112233445566778899AABBCCDDEEFF"),
			ik:          mustHex(t, "FFEEDDCCBBAA99887766554433221100"),
			networkName: []byte("foo:bar"),
			sqnXorAK:    mustHex(t, "0123456789AB"),
			wantCK:      mustHex(t, "3F7B2687E2000F35F4AD0796E579CC90"),
			wantIK:      mustHex(t, "CCE648C28E26FAD3FC2749B790249F1E"),
		},
		{
			name:        "rfc 5448 appendix c case 1",
			ck:          mustHex(t, "5349fbe098649f948f5d2e973a81c00f"),
			ik:          mustHex(t, "9744871ad32bf9bbd1dd5ce54e3e2e5a"),
			networkName: []byte("WLAN"),
			sqnXorAK:    mustHex(t, "bb52e91c747a"),
			wantCK:      mustHex(t, "0093962d0dd84aa5684b045c9edffa04"),
			wantIK:      mustHex(t, "ccfc230ca74fcc96c0a5d61164f5a76c"),
		},
		{
			name:     "empty network name",
			ck:       bytes.Repeat([]byte{0x11}, akaPrimeCKLen),
			ik:       bytes.Repeat([]byte{0x22}, akaPrimeIKLen),
			sqnXorAK: bytes.Repeat([]byte{0x33}, akaPrimeSQNXorAKLen),
			wantErr:  true,
		},
		{
			name:        "network name exceeds TS 24.302 limit",
			ck:          bytes.Repeat([]byte{0x11}, akaPrimeCKLen),
			ik:          bytes.Repeat([]byte{0x22}, akaPrimeIKLen),
			networkName: bytes.Repeat([]byte{'a'}, akaNetworkNameMaxLen+1),
			sqnXorAK:    bytes.Repeat([]byte{0x33}, akaPrimeSQNXorAKLen),
			wantErr:     true,
		},
		{
			name:        "network name is invalid UTF-8",
			ck:          bytes.Repeat([]byte{0x11}, akaPrimeCKLen),
			ik:          bytes.Repeat([]byte{0x22}, akaPrimeIKLen),
			networkName: []byte{0xff},
			sqnXorAK:    bytes.Repeat([]byte{0x33}, akaPrimeSQNXorAKLen),
			wantErr:     true,
		},
		{
			name:        "network name contains NUL",
			ck:          bytes.Repeat([]byte{0x11}, akaPrimeCKLen),
			ik:          bytes.Repeat([]byte{0x22}, akaPrimeIKLen),
			networkName: []byte{'W', 0, 'L', 'A', 'N'},
			sqnXorAK:    bytes.Repeat([]byte{0x33}, akaPrimeSQNXorAKLen),
			wantErr:     true,
		},
		{
			name:        "network name is not NFKC-normalized",
			ck:          bytes.Repeat([]byte{0x11}, akaPrimeCKLen),
			ik:          bytes.Repeat([]byte{0x22}, akaPrimeIKLen),
			networkName: []byte("ＷＬＡＮ"),
			sqnXorAK:    bytes.Repeat([]byte{0x33}, akaPrimeSQNXorAKLen),
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCK, gotIK, err := DeriveAKAPrimeCKIK(tt.ck, tt.ik, tt.networkName, tt.sqnXorAK)
			if tt.wantErr {
				if err == nil {
					t.Fatal("DeriveAKAPrimeCKIK() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("DeriveAKAPrimeCKIK() error = %v", err)
			}
			if !bytes.Equal(gotCK, tt.wantCK) {
				t.Fatalf("CK' = % X, want % X", gotCK, tt.wantCK)
			}
			if !bytes.Equal(gotIK, tt.wantIK) {
				t.Fatalf("IK' = % X, want % X", gotIK, tt.wantIK)
			}
		})
	}
}

func TestDeriveAKAKeys(t *testing.T) {
	tests := []struct {
		name     string
		identity []byte
		ik       []byte
		ck       []byte
		want     AKAKeys
	}{
		{
			name:     "reference challenge state vector",
			identity: []byte("0123456789012345@example.net"),
			ik:       mustHex(t, "FFEEDDCCBBAA99887766554433221100"),
			ck:       mustHex(t, "00112233445566778899AABBCCDDEEFF"),
			want: AKAKeys{
				MK:   mustHex(t, "C795BCD5EDDEAC8B9BD9195806B7BBC009BFA6C0"),
				ENCR: mustHex(t, "71BAE1A432C1F0FFB7AAA26D4AEF0BEB"),
				AUT:  mustHex(t, "CB56F10A6D3C504BA90F59429250804E"),
				MSK: mustHex(t, "E4237E44C082407369B03162EA2B2F2A3EE168668A4F0FF6008D74CE42BD162C"+
					"C73ED09007BA517D1D8EC0D1396BFA58197105B9AA09C160C9BE01A6E4954E38"),
				EMSK: mustHex(t, "3CD8C2F54645ADA653877D740E11E20A8AB42DCEAC6A5A7061B855EF61723937"+
					"C956892B9C8350948FFA54EFB1D379BC048165F71415008E301CEE90E14C17B0"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeriveAKAKeys(tt.identity, tt.ik, tt.ck)
			if err != nil {
				t.Fatalf("DeriveAKAKeys() error = %v", err)
			}
			assertAKAKeys(t, got, tt.want)
		})
	}
}

func TestDeriveAKAKeysValidation(t *testing.T) {
	tests := []struct {
		name     string
		identity []byte
		ik       []byte
		ck       []byte
	}{
		{
			name: "empty identity",
			ik:   bytes.Repeat([]byte{0x11}, akaVectorLen),
			ck:   bytes.Repeat([]byte{0x22}, akaVectorLen),
		},
		{
			name:     "identity is invalid UTF-8",
			identity: []byte{0xff},
			ik:       bytes.Repeat([]byte{0x11}, akaVectorLen),
			ck:       bytes.Repeat([]byte{0x22}, akaVectorLen),
		},
		{
			name:     "identity contains NUL",
			identity: []byte{'u', 0, 's', 'e', 'r'},
			ik:       bytes.Repeat([]byte{0x11}, akaVectorLen),
			ck:       bytes.Repeat([]byte{0x22}, akaVectorLen),
		},
		{
			name:     "short ik",
			identity: []byte("0123456789012345@example.net"),
			ik:       bytes.Repeat([]byte{0x11}, akaVectorLen-1),
			ck:       bytes.Repeat([]byte{0x22}, akaVectorLen),
		},
		{
			name:     "short ck",
			identity: []byte("0123456789012345@example.net"),
			ik:       bytes.Repeat([]byte{0x11}, akaVectorLen),
			ck:       bytes.Repeat([]byte{0x22}, akaVectorLen-1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DeriveAKAKeys(tt.identity, tt.ik, tt.ck); err == nil {
				t.Fatal("DeriveAKAKeys() error = nil, want error")
			}
		})
	}
}

func TestDeriveAKAPrimeKeys(t *testing.T) {
	tests := []struct {
		name        string
		identity    []byte
		ck          []byte
		ik          []byte
		networkName []byte
		sqnXorAK    []byte
		want        AKAPrimeKeys
	}{
		{
			name:        "reference challenge state vector",
			identity:    []byte("test@example.net"),
			ck:          mustHex(t, "00112233445566778899AABBCCDDEEFF"),
			ik:          mustHex(t, "FFEEDDCCBBAA99887766554433221100"),
			networkName: []byte("foo:bar"),
			sqnXorAK:    mustHex(t, "0123456789AB"),
			want: AKAPrimeKeys{
				CKPrime: mustHex(t, "3F7B2687E2000F35F4AD0796E579CC90"),
				IKPrime: mustHex(t, "CCE648C28E26FAD3FC2749B790249F1E"),
				ENCR:    mustHex(t, "DE28640565A622858710686E8F025621"),
				AUT:     mustHex(t, "53F9D86DCCC9C98335217001F9A54A8626891249A2F709B4AD278D22948E8B29"),
				RE:      mustHex(t, "0CADD87FB7401CE386808DD8D53254C5E7C4C231A0D7E274C1997CAD953E4280"),
				MSK: mustHex(t, "339843B76C5F5255F18BDCF17143A308756BAD1D17AFF7E19C3AA4BFBE7ECE44"+
					"EFC2D4295BD7E403A0B1B515FE5F2C248FD02D69CB57BA4388BBFEC0D99966CB"),
				EMSK: mustHex(t, "238AED9A36A1A0059119A31083C2BC33618994BA467E84CDB27983D7E8A2B2B"+
					"F912456886858CF1E3A7EE55FD0990A0A1A18035D82A8C9D38AB35758B5103F97"),
			},
		},
		{
			name:        "rfc 5448 appendix c case 1",
			identity:    []byte("0555444333222111"),
			ck:          mustHex(t, "5349fbe098649f948f5d2e973a81c00f"),
			ik:          mustHex(t, "9744871ad32bf9bbd1dd5ce54e3e2e5a"),
			networkName: []byte("WLAN"),
			sqnXorAK:    mustHex(t, "bb52e91c747a"),
			want: AKAPrimeKeys{
				CKPrime: mustHex(t, "0093962d0dd84aa5684b045c9edffa04"),
				IKPrime: mustHex(t, "ccfc230ca74fcc96c0a5d61164f5a76c"),
				ENCR:    mustHex(t, "766fa0a6c317174b812d52fbcd11a179"),
				AUT:     mustHex(t, "0842ea722ff6835bfa2032499fc3ec23c2f0e388b4f07543ffc677f1696d71ea"),
				RE:      mustHex(t, "cf83aa8bc7e0aced892acc98e76a9b2095b558c7795c7094715cb3393aa7d17a"),
				MSK: mustHex(t, "67c42d9aa56c1b79e295e3459fc3d187d42be0bf818d3070e362c5e967a4d544"+
					"e8ecfe19358ab3039aff03b7c930588c055babee58a02650b067ec4e9347c75a"),
				EMSK: mustHex(t, "f861703cd775590e16c7679ea3874ada866311de290764d760cf76df647ea01c"+
					"313f69924bdd7650ca9bac141ea075c4ef9e8029c0e290cdbad5638b63bc23fb"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeriveAKAPrimeKeys(tt.identity, tt.ck, tt.ik, tt.networkName, tt.sqnXorAK)
			if err != nil {
				t.Fatalf("DeriveAKAPrimeKeys() error = %v", err)
			}
			assertAKAPrimeKeys(t, got, tt.want)
		})
	}
}

func TestDeriveAKAPrimeKeysValidatesIdentity(t *testing.T) {
	tests := []struct {
		name     string
		identity []byte
	}{
		{name: "empty"},
		{name: "invalid UTF-8", identity: []byte{0xff}},
		{name: "contains NUL", identity: []byte{'u', 0, 's', 'e', 'r'}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeriveAKAPrimeKeys(
				tt.identity,
				bytes.Repeat([]byte{0x11}, akaPrimeCKLen),
				bytes.Repeat([]byte{0x22}, akaPrimeIKLen),
				[]byte("WLAN"),
				bytes.Repeat([]byte{0x33}, akaPrimeSQNXorAKLen),
			)
			if err == nil {
				t.Fatal("DeriveAKAPrimeKeys() error = nil, want error")
			}
		})
	}
}

func TestDeriveAKAPrimeFastReauthKeys(t *testing.T) {
	msk, emsk, err := DeriveAKAPrimeFastReauthKeys(
		[]byte("reauth@example.net"),
		7,
		mustHex(t, "00112233445566778899aabbccddeeff"),
		mustHex(t, "333A148B074FC01B2D0F17ABB741B2EA1968899A152CC9F2B6CBE728A9A31BC1"),
	)
	if err != nil {
		t.Fatalf("DeriveAKAPrimeFastReauthKeys() error = %v", err)
	}
	wantMSK := mustHex(t, "028c0c2df6d9d8da8ad35ba4dc7004280f3c042f3cbbcbfdacaf9bee3366aa59"+
		"b86bf520171d613eb0927858a2e5b043d3681bfe4e86c71b497cff7eb3d56814")
	wantEMSK := mustHex(t, "a2a85144a4e8fef8c58d3c0f4ad5ff818c6f65d4a8a1f16725befb7b75f72674"+
		"afbb0ec2514f0550b5ba592521c541eb205c645c4e4a27f0cfc8ae8fdf9cd7b4")
	if !bytes.Equal(msk, wantMSK) {
		t.Fatalf("MSK = % X, want % X", msk, wantMSK)
	}
	if !bytes.Equal(emsk, wantEMSK) {
		t.Fatalf("EMSK = % X, want % X", emsk, wantEMSK)
	}

	fullMK := bytes.Repeat([]byte{0x77}, akaPrimeKEncrLen+akaPrimeKAutLen+akaPrimeKReLen+akaPrimeMSKLen+akaPrimeEMSKLen)
	copy(fullMK[akaPrimeKEncrLen+akaPrimeKAutLen:], mustHex(t, "333A148B074FC01B2D0F17ABB741B2EA1968899A152CC9F2B6CBE728A9A31BC1"))
	fromMKMSK, fromMKEMSK, err := DeriveAKAPrimeFastReauthKeysFromMK([]byte("reauth@example.net"), 7, mustHex(t, "00112233445566778899aabbccddeeff"), fullMK)
	if err != nil {
		t.Fatalf("DeriveAKAPrimeFastReauthKeysFromMK() error = %v", err)
	}
	if !bytes.Equal(fromMKMSK, wantMSK) || !bytes.Equal(fromMKEMSK, wantEMSK) {
		t.Fatalf("DeriveAKAPrimeFastReauthKeysFromMK() = % X, % X; want % X, % X", fromMKMSK, fromMKEMSK, wantMSK, wantEMSK)
	}
}

func TestDeriveFastReauthKeysValidatesInputs(t *testing.T) {
	tests := []struct {
		name     string
		identity []byte
		nonceS   []byte
		mk       []byte
		wantErr  bool
	}{
		{name: "valid", identity: []byte("reauth@example.net"), nonceS: make([]byte, akaVectorLen), mk: make([]byte, sha1.Size)},
		{name: "empty identity", nonceS: make([]byte, akaVectorLen), mk: make([]byte, sha1.Size), wantErr: true},
		{name: "identity is invalid UTF-8", identity: []byte{0xff}, nonceS: make([]byte, akaVectorLen), mk: make([]byte, sha1.Size), wantErr: true},
		{name: "identity contains NUL", identity: []byte{'u', 0, 's', 'e', 'r'}, nonceS: make([]byte, akaVectorLen), mk: make([]byte, sha1.Size), wantErr: true},
		{name: "short nonce", identity: []byte("reauth@example.net"), nonceS: make([]byte, akaVectorLen-1), mk: make([]byte, sha1.Size), wantErr: true},
		{name: "short mk", identity: []byte("reauth@example.net"), nonceS: make([]byte, akaVectorLen), mk: make([]byte, sha1.Size-1), wantErr: true},
		{name: "long mk", identity: []byte("reauth@example.net"), nonceS: make([]byte, akaVectorLen), mk: make([]byte, sha1.Size+1), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := DeriveFastReauthKeys(tt.identity, 1, tt.nonceS, tt.mk)
			if tt.wantErr && err == nil {
				t.Fatal("DeriveFastReauthKeys() error = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("DeriveFastReauthKeys() error = %v", err)
			}
		})
	}
}

func TestEAPPacketUnmarshalBinaryValidation(t *testing.T) {
	tests := []struct {
		name    string
		wire    []byte
		wantErr bool
	}{
		{name: "request with type", wire: []byte{eapCodeRequest, 1, 0, 5, eapTypeAKA}},
		{name: "success length four", wire: []byte{eapCodeSuccess, 1, 0, 4}},
		{name: "success with type data", wire: []byte{eapCodeSuccess, 1, 0, 5, eapTypeAKA}, wantErr: true},
		{name: "failure with type data", wire: []byte{eapCodeFailure, 1, 0, 5, eapTypeAKA}, wantErr: true},
		{name: "request missing type", wire: []byte{eapCodeRequest, 1, 0, 4}, wantErr: true},
		{name: "trailing bytes", wire: []byte{eapCodeRequest, 1, 0, 5, eapTypeAKA, 0}, wantErr: true},
		{name: "invalid code", wire: []byte{9, 1, 0, 4}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got EAPPacket
			err := got.UnmarshalBinary(tt.wire)
			if tt.wantErr {
				if err == nil {
					t.Fatal("UnmarshalBinary() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
		})
	}
}

func TestEAPPacketMarshalBinaryValidation(t *testing.T) {
	tests := []struct {
		name    string
		packet  EAPPacket
		wantErr bool
	}{
		{name: "request with type", packet: EAPPacket{Code: eapCodeRequest, Identifier: 1, Type: eapTypeAKA, HasType: true}},
		{name: "success without type data", packet: EAPPacket{Code: eapCodeSuccess, Identifier: 1}},
		{name: "request missing type", packet: EAPPacket{Code: eapCodeRequest, Identifier: 1}, wantErr: true},
		{name: "success with type", packet: EAPPacket{Code: eapCodeSuccess, Identifier: 1, Type: eapTypeAKA, HasType: true}, wantErr: true},
		{name: "failure with data", packet: EAPPacket{Code: eapCodeFailure, Identifier: 1, Data: []byte{0}}, wantErr: true},
		{name: "oversized request", packet: EAPPacket{Code: eapCodeRequest, Identifier: 1, Type: eapTypeAKA, HasType: true, Data: make([]byte, eapMaxLen)}, wantErr: true},
		{name: "invalid code", packet: EAPPacket{Code: 9, Identifier: 1}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.packet.MarshalBinary()
			if tt.wantErr && err == nil {
				t.Fatal("MarshalBinary() error = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
		})
	}
}

func TestBuildEAPIdentityResponse(t *testing.T) {
	tests := []struct {
		name     string
		id       byte
		identity string
		wantErr  bool
	}{
		{name: "success", id: 4, identity: "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org"},
		{name: "empty identity", id: 4, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := BuildEAPIdentityResponse(tt.id, tt.identity)
			if tt.wantErr {
				if err == nil {
					t.Fatal("BuildEAPIdentityResponse() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildEAPIdentityResponse() error = %v", err)
			}
			var got EAPPacket
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.Code != eapCodeResponse || got.Identifier != tt.id || !got.HasType || got.Type != eapTypeIdentity {
				t.Fatalf("EAPPacket = %+v", got)
			}
			if string(got.Data) != tt.identity {
				t.Fatalf("identity = %q, want %q", string(got.Data), tt.identity)
			}
		})
	}
}

func TestBuildEAPNakResponse(t *testing.T) {
	tests := []struct {
		name         string
		id           byte
		desiredTypes []byte
		wantErr      bool
		wantWire     []byte
	}{
		{
			name:         "aka desired",
			id:           0x10,
			desiredTypes: []byte{eapTypeAKA},
			wantWire:     []byte{eapCodeResponse, 0x10, 0x00, 0x06, eapTypeNak, eapTypeAKA},
		},
		{
			name:    "empty desired types",
			id:      0x10,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := BuildEAPNakResponse(tt.id, tt.desiredTypes...)
			if tt.wantErr {
				if err == nil {
					t.Fatal("BuildEAPNakResponse() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildEAPNakResponse() error = %v", err)
			}
			if !bytes.Equal(wire, tt.wantWire) {
				t.Fatalf("wire = % X, want % X", wire, tt.wantWire)
			}
		})
	}
}

func TestBuildEAPNotificationResponse(t *testing.T) {
	wire, err := BuildEAPNotificationResponse(0x22)
	if err != nil {
		t.Fatalf("BuildEAPNotificationResponse() error = %v", err)
	}
	want := []byte{eapCodeResponse, 0x22, 0x00, 0x05, eapTypeNotification}
	if !bytes.Equal(wire, want) {
		t.Fatalf("wire = % X, want % X", wire, want)
	}
}

func TestAKAAttributeMarshalBinaryValidation(t *testing.T) {
	tests := []struct {
		name    string
		attr    AKAAttribute
		wantErr bool
	}{
		{name: "minimum aligned value", attr: AKAAttribute{Type: akaAttrResultInd, Value: []byte{0x00, 0x00}}},
		{name: "maximum encodable value", attr: AKAAttribute{Type: akaAttrCheckcode, Value: make([]byte, akaAttributeMaxWireLen-2)}},
		{name: "unaligned value", attr: AKAAttribute{Type: akaAttrCheckcode, Value: []byte{0x00, 0x00, 0x00}}, wantErr: true},
		{name: "oversized value", attr: AKAAttribute{Type: akaAttrCheckcode, Value: make([]byte, akaAttributeMaxWireLen+2)}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.attr.MarshalBinary()
			if tt.wantErr && err == nil {
				t.Fatal("MarshalBinary() error = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
		})
	}
}

func TestAKAMessageUnmarshalBinaryDuplicateAttributeHandling(t *testing.T) {
	tests := []struct {
		name    string
		attr    AKAAttribute
		wantErr bool
	}{
		{
			name:    "known duplicate is rejected",
			attr:    AKAAttribute{Type: akaAttrCheckcode, Value: []byte{0x00, 0x00}},
			wantErr: true,
		},
		{
			name: "unknown skippable duplicate is preserved for higher layer ignore",
			attr: AKAAttribute{Type: 200, Value: []byte{0x00, 0x00}},
		},
		{
			name: "kdf duplicate is preserved for aka prime negotiation validation",
			attr: AKAAttribute{Type: akaAttrKDF, Value: []byte{0x00, byte(akaPrimeKDFDefault)}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first, err := tt.attr.MarshalBinary()
			if err != nil {
				t.Fatalf("first MarshalBinary() error = %v", err)
			}
			second, err := tt.attr.MarshalBinary()
			if err != nil {
				t.Fatalf("second MarshalBinary() error = %v", err)
			}
			packet := EAPPacket{
				Code:       eapCodeRequest,
				Identifier: 3,
				Type:       eapTypeAKA,
				HasType:    true,
				Data:       append(append([]byte{akaSubtypeChallenge, 0x00, 0x00}, first...), second...),
			}
			wire, err := packet.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}

			var got AKAMessage
			err = got.UnmarshalBinary(wire)
			if tt.wantErr {
				if err == nil {
					t.Fatal("UnmarshalBinary() error = nil, want duplicate attribute error")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if len(got.Attributes) != 2 {
				t.Fatalf("attributes = %d, want 2", len(got.Attributes))
			}
		})
	}
}

func TestAKAMessageMarshalBinaryDuplicateAttributeHandling(t *testing.T) {
	tests := []struct {
		name    string
		attr    AKAAttribute
		wantErr bool
	}{
		{name: "known duplicate", attr: AKAAttribute{Type: akaAttrCheckcode, Value: []byte{0x00, 0x00}}, wantErr: true},
		{name: "unknown skippable duplicate", attr: AKAAttribute{Type: 200, Value: []byte{0x00, 0x00}}},
		{name: "repeatable kdf", attr: AKAAttribute{Type: akaAttrKDF, Value: []byte{0x00, byte(akaPrimeKDFDefault)}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := AKAMessage{
				Code:       eapCodeRequest,
				Identifier: 1,
				Subtype:    akaSubtypeChallenge,
				Attributes: []AKAAttribute{tt.attr, tt.attr},
			}
			_, err := message.MarshalBinary()
			if tt.wantErr && err == nil {
				t.Fatal("MarshalBinary() error = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
		})
	}
}

func TestBuildAKAIdentityResponse(t *testing.T) {
	tests := []struct {
		name     string
		id       byte
		identity string
		wantErr  bool
	}{
		{name: "success", id: 3, identity: "001010123456789"},
		{name: "empty", id: 3, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := BuildAKAIdentityResponse(tt.id, tt.identity)
			if tt.wantErr {
				if err == nil {
					t.Fatal("BuildAKAIdentityResponse() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildAKAIdentityResponse() error = %v", err)
			}
			var got AKAMessage
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.Code != eapCodeResponse || got.Subtype != akaSubtypeIdentity {
				t.Fatalf("AKAMessage = %+v", got)
			}
		})
	}
}

func TestBuildAKAPrimeKDFSelection(t *testing.T) {
	tests := []struct {
		name string
		id   byte
		kdf  uint16
	}{
		{name: "default kdf", id: 7, kdf: akaPrimeKDFDefault},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := BuildAKAPrimeKDFSelection(tt.id, tt.kdf)
			if err != nil {
				t.Fatalf("BuildAKAPrimeKDFSelection() error = %v", err)
			}
			var got AKAMessage
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.Code != eapCodeResponse || got.Identifier != tt.id || got.EAPType != eapTypeAKAPrime || got.Subtype != akaSubtypeChallenge {
				t.Fatalf("AKAMessage = %+v", got)
			}
			if len(got.Attributes) != 1 || got.Attributes[0].Type != akaAttrKDF {
				t.Fatalf("Attributes = %+v, want only AT_KDF", got.Attributes)
			}
			kdf, err := KDFFromAttribute(&got.Attributes[0])
			if err != nil {
				t.Fatalf("KDFFromAttribute() error = %v", err)
			}
			if kdf.Version != tt.kdf {
				t.Fatalf("KDF = %d, want %d", kdf.Version, tt.kdf)
			}
		})
	}
}

func TestBuildAKAResponsePadsATRESValueToFourByteBoundary(t *testing.T) {
	wire, err := BuildAKAResponse(3, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, bytes.Repeat([]byte{0x11}, akaKAutLen))
	if err != nil {
		t.Fatalf("BuildAKAResponse() error = %v", err)
	}

	var message AKAMessage
	if err := message.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	resAttr := FindAttribute(message.Attributes, akaAttrRES)
	if resAttr == nil {
		t.Fatal("AT_RES is missing")
	}
	if got, want := len(resAttr.Value), 10; got != want {
		t.Fatalf("len(AT_RES value) = %d, want %d", got, want)
	}
	if tail := resAttr.Value[8:]; !bytes.Equal(tail, []byte{0x00, 0x00}) {
		t.Fatalf("AT_RES padding = % X, want 00 00", tail)
	}
}

func TestBuildAKAResponseValidatesRESLength(t *testing.T) {
	tests := []struct {
		name       string
		res        []byte
		missingKey bool
		wantErr    bool
	}{
		{name: "minimum", res: bytes.Repeat([]byte{0x11}, akaRESMinLen)},
		{name: "maximum", res: bytes.Repeat([]byte{0x11}, akaRESMaxLen)},
		{name: "too short", res: bytes.Repeat([]byte{0x11}, akaRESMinLen-1), wantErr: true},
		{name: "too long", res: bytes.Repeat([]byte{0x11}, akaRESMaxLen+1), wantErr: true},
		{name: "missing authentication key", res: bytes.Repeat([]byte{0x11}, akaRESMinLen), missingKey: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			autKey := bytes.Repeat([]byte{0x22}, akaKAutLen)
			if tt.missingKey {
				autKey = nil
			}
			_, err := BuildAKAResponse(3, tt.res, autKey)
			if tt.wantErr && err == nil {
				t.Fatal("BuildAKAResponse() error = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("BuildAKAResponse() error = %v", err)
			}
		})
	}
}

func TestBuildChallengeResponsePacketWithCheckcode(t *testing.T) {
	checkcode := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x66}, 20)...)
	wire, err := BuildChallengeResponsePacketWithCheckcode(3, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, bytes.Repeat([]byte{0x11}, 16), false, checkcode)
	if err != nil {
		t.Fatalf("BuildChallengeResponsePacketWithCheckcode() error = %v", err)
	}

	var got AKAMessage
	if err := got.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	attr := FindAttribute(got.Attributes, akaAttrCheckcode)
	if attr == nil {
		t.Fatal("AT_CHECKCODE is missing")
	}
	if !bytes.Equal(attr.Value, checkcode) {
		t.Fatalf("AT_CHECKCODE = % X, want % X", attr.Value, checkcode)
	}
	resAttr := FindAttribute(got.Attributes, akaAttrRES)
	if resAttr == nil {
		t.Fatal("AT_RES is missing")
	}
	if got, want := len(resAttr.Value), 10; got != want {
		t.Fatalf("len(AT_RES value) = %d, want %d", got, want)
	}
}

func TestBuildChallengeResponsePacketWithOptionsIPMS(t *testing.T) {
	tests := []struct {
		name    string
		opts    ChallengeResponseOptions
		wantErr bool
	}{
		{
			name: "nbm only",
			opts: ChallengeResponseOptions{
				Identifier:   3,
				RES:          []byte{0x01, 0x02, 0x03, 0x04},
				AUTKey:       bytes.Repeat([]byte{0x11}, 16),
				UseResultInd: true,
				IPMSSupport:  IPMSSupportNBMOnly,
			},
		},
		{
			name: "requires result indication",
			opts: ChallengeResponseOptions{
				Identifier:  3,
				RES:         []byte{0x01, 0x02, 0x03, 0x04},
				AUTKey:      bytes.Repeat([]byte{0x11}, 16),
				IPMSSupport: IPMSSupportNBMOnly,
			},
			wantErr: true,
		},
		{
			name: "invalid ipms support",
			opts: ChallengeResponseOptions{
				Identifier:   3,
				RES:          []byte{0x01, 0x02, 0x03, 0x04},
				AUTKey:       bytes.Repeat([]byte{0x11}, 16),
				UseResultInd: true,
				IPMSSupport:  15,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := BuildChallengeResponsePacketWithOptions(tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Fatal("BuildChallengeResponsePacketWithOptions() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildChallengeResponsePacketWithOptions() error = %v", err)
			}
			var got AKAMessage
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if attr := FindAttribute(got.Attributes, akaAttrResultInd); attr == nil {
				t.Fatal("AT_RESULT_IND is missing")
			}
			attr := FindAttribute(got.Attributes, akaAttrIPMSInd)
			if attr == nil {
				t.Fatal("AT_IPMS_IND is missing")
			}
			if !bytes.Equal(attr.Value, []byte{0x00, byte(IPMSSupportNBMOnly)}) {
				t.Fatalf("AT_IPMS_IND = % X, want 00 02", attr.Value)
			}
		})
	}
}

func TestBuildChallengeResponsePacketWithCheckcodeValidation(t *testing.T) {
	tests := []struct {
		name      string
		checkcode []byte
		wantErr   bool
	}{
		{name: "omitted"},
		{name: "empty checkcode marker", checkcode: []byte{0x00, 0x00}},
		{name: "sha1 checkcode", checkcode: append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x66}, sha1.Size)...)},
		{name: "short aligned semantic length", checkcode: []byte{0x00, 0x00, 0x66, 0x66, 0x66, 0x66}, wantErr: true},
		{name: "missing reserved bytes", checkcode: bytes.Repeat([]byte{0x66}, sha1.Size), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildChallengeResponsePacketWithCheckcode(3, []byte{0x01, 0x02, 0x03, 0x04}, bytes.Repeat([]byte{0x11}, 16), false, tt.checkcode)
			if tt.wantErr {
				if err == nil {
					t.Fatal("BuildChallengeResponsePacketWithCheckcode() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildChallengeResponsePacketWithCheckcode() error = %v", err)
			}
		})
	}
}

func TestAKAChallengeUnmarshalBinary(t *testing.T) {
	randValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x11}, 16)...)
	autnValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x22}, 16)...)
	macValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x55}, 16)...)
	ivValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x33}, 16)...)
	encryptedValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x44}, 16)...)
	checkcodeValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x66}, 20)...)
	invalidCheckcodeValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x66}, 4)...)
	resultIndValue := []byte{0x00, 0x00}
	biddingValue := []byte{0x80, 0x00}
	shortRandValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x11}, 12)...)
	invalidEncryptedValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x44}, 12)...)

	tests := []struct {
		name    string
		attrs   []AKAAttribute
		wantErr bool
	}{
		{
			name: "valid",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
			},
		},
		{
			name: "valid with result indication",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrResultInd, Value: resultIndValue},
			},
		},
		{
			name: "valid with bidding attribute",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrBidding, Value: biddingValue},
			},
		},
		{
			name: "valid with unknown skippable attribute",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: 200, Value: []byte{0x00, 0x00}},
			},
		},
		{
			name: "duplicate rand",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
			},
			wantErr: true,
		},
		{
			name: "missing mac",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
			},
			wantErr: true,
		},
		{
			name: "duplicate autn",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
			},
			wantErr: true,
		},
		{
			name: "short rand",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: shortRandValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
			},
			wantErr: true,
		},
		{
			name: "unexpected identity request attribute",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrAnyIDReq, Value: []byte{0x00, 0x00}},
			},
			wantErr: true,
		},
		{
			name: "next pseudonym is not allowed at challenge top level",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				buildAKAStringAttribute(akaAttrNextPseudonym, "pseudonym"),
			},
			wantErr: true,
		},
		{
			name: "ipms result is not allowed in challenge",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrIPMSRes, Value: []byte{0x00, byte(IPMSSelectionNBM)}},
			},
			wantErr: true,
		},
		{
			name: "valid with checkcode",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrCheckcode, Value: checkcodeValue},
			},
		},
		{
			name: "invalid checkcode length",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrCheckcode, Value: invalidCheckcodeValue},
			},
			wantErr: true,
		},
		{
			name: "duplicate result indication",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrResultInd, Value: resultIndValue},
				{Type: akaAttrResultInd, Value: resultIndValue},
			},
			wantErr: true,
		},
		{
			name: "duplicate iv",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrIV, Value: ivValue},
				{Type: akaAttrIV, Value: ivValue},
				{Type: akaAttrEncryptedData, Value: encryptedValue},
			},
			wantErr: true,
		},
		{
			name: "duplicate encrypted data",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrIV, Value: ivValue},
				{Type: akaAttrEncryptedData, Value: encryptedValue},
				{Type: akaAttrEncryptedData, Value: encryptedValue},
			},
			wantErr: true,
		},
		{
			name: "iv without encrypted data",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrIV, Value: ivValue},
			},
			wantErr: true,
		},
		{
			name: "encrypted data without iv",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrEncryptedData, Value: encryptedValue},
			},
			wantErr: true,
		},
		{
			name: "invalid encrypted data length",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrIV, Value: ivValue},
				{Type: akaAttrEncryptedData, Value: invalidEncryptedValue},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := marshalAKAMessageUncheckedForTest(t, AKAMessage{
				Code:       eapCodeRequest,
				Identifier: 5,
				Subtype:    akaSubtypeChallenge,
				Attributes: tt.attrs,
			})
			var challenge AKAChallenge
			err := challenge.UnmarshalBinary(wire)
			if tt.wantErr {
				if err == nil {
					t.Fatal("UnmarshalBinary() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if len(challenge.RAND) != akaVectorLen || len(challenge.AUTN) != akaVectorLen {
				t.Fatalf("challenge = %+v", challenge)
			}
		})
	}
}

func TestAKAChallengeUnmarshalBinaryAKAPrimeKDFValidation(t *testing.T) {
	randValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x11}, 16)...)
	autnValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x22}, 16)...)
	macValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x55}, 16)...)
	networkName := []byte("example.net")
	kdfInputValue := buildAKAStringAttribute(akaAttrKDFInput, string(networkName)).Value
	emptyKDFInputValue := buildAKAStringAttribute(akaAttrKDFInput, "").Value
	kdfValue := []byte{0x00, byte(akaPrimeKDFDefault)}
	unsupportedKDFValue := []byte{0x00, 0x02}

	tests := []struct {
		name        string
		eapType     byte
		attrs       []AKAAttribute
		wantNetwork []byte
		wantKDF     uint16
		wantErr     bool
		wantAuthErr bool
	}{
		{
			name:    "valid aka prime challenge",
			eapType: eapTypeAKAPrime,
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrKDFInput, Value: kdfInputValue},
				{Type: akaAttrKDF, Value: kdfValue},
				{Type: akaAttrMAC, Value: macValue},
			},
			wantNetwork: networkName,
			wantKDF:     akaPrimeKDFDefault,
		},
		{
			name:    "missing kdf",
			eapType: eapTypeAKAPrime,
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrKDFInput, Value: kdfInputValue},
				{Type: akaAttrMAC, Value: macValue},
			},
			wantErr:     true,
			wantAuthErr: true,
		},
		{
			name:    "missing kdf input",
			eapType: eapTypeAKAPrime,
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrKDF, Value: kdfValue},
				{Type: akaAttrMAC, Value: macValue},
			},
			wantErr:     true,
			wantAuthErr: true,
		},
		{
			name:    "unsupported kdf",
			eapType: eapTypeAKAPrime,
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrKDFInput, Value: kdfInputValue},
				{Type: akaAttrKDF, Value: unsupportedKDFValue},
				{Type: akaAttrMAC, Value: macValue},
			},
			wantErr:     true,
			wantAuthErr: true,
		},
		{
			name:    "empty network name",
			eapType: eapTypeAKAPrime,
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrKDFInput, Value: emptyKDFInputValue},
				{Type: akaAttrKDF, Value: kdfValue},
				{Type: akaAttrMAC, Value: macValue},
			},
			wantErr:     true,
			wantAuthErr: true,
		},
		{
			name:    "kdf input is rejected for aka",
			eapType: eapTypeAKA,
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrKDFInput, Value: kdfInputValue},
				{Type: akaAttrMAC, Value: macValue},
			},
			wantErr: true,
		},
		{
			name:    "bidding is rejected for aka prime",
			eapType: eapTypeAKAPrime,
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrKDFInput, Value: kdfInputValue},
				{Type: akaAttrKDF, Value: kdfValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrBidding, Value: []byte{0x80, 0x00}},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := AKAMessage{
				Code:       eapCodeRequest,
				Identifier: 5,
				EAPType:    tt.eapType,
				Subtype:    akaSubtypeChallenge,
				Attributes: tt.attrs,
			}.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			var challenge AKAChallenge
			err = challenge.UnmarshalBinary(wire)
			if tt.wantErr {
				if err == nil {
					t.Fatal("UnmarshalBinary() error = nil, want error")
				}
				if got := errors.Is(err, ErrAKAPrimeAuthenticationFailure); got != tt.wantAuthErr {
					t.Fatalf("errors.Is(ErrAKAPrimeAuthenticationFailure) = %t, want %t", got, tt.wantAuthErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if challenge.EAPType != tt.eapType {
				t.Fatalf("EAPType = %d, want %d", challenge.EAPType, tt.eapType)
			}
			if challenge.KDF != tt.wantKDF {
				t.Fatalf("KDF = %d, want %d", challenge.KDF, tt.wantKDF)
			}
			if !bytes.Equal(challenge.NetworkName, tt.wantNetwork) {
				t.Fatalf("NetworkName = % X, want % X", challenge.NetworkName, tt.wantNetwork)
			}
		})
	}
}

func TestAKAChallengeAMFSeparationBitSet(t *testing.T) {
	tests := []struct {
		name string
		autn []byte
		want bool
	}{
		{name: "set", autn: []byte{0, 0, 0, 0, 0, 0, akaAMFSeparationBitMask, 0}, want: true},
		{name: "clear", autn: []byte{0, 0, 0, 0, 0, 0, 0x7f, 0}},
		{name: "short"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			autn := append([]byte(nil), tt.autn...)
			if len(autn) != 0 {
				autn = append(autn, make([]byte, akaVectorLen-len(autn))...)
			}
			got := (AKAChallenge{AUTN: autn}).AMFSeparationBitSet()
			if got != tt.want {
				t.Fatalf("AMFSeparationBitSet() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestTrustIndicationUnmarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		wire    []byte
		want    TrustRelationship
		wantErr bool
	}{
		{name: "trusted", wire: []byte{akaAttrTrustInd, 0x01, 0x00, byte(TrustRelationshipTrusted)}, want: TrustRelationshipTrusted},
		{name: "untrusted", wire: []byte{akaAttrTrustInd, 0x01, 0x00, byte(TrustRelationshipUntrusted)}, want: TrustRelationshipUntrusted},
		{name: "reserved octet is not zero", wire: []byte{akaAttrTrustInd, 0x01, 0x01, byte(TrustRelationshipTrusted)}, wantErr: true},
		{name: "unknown relationship", wire: []byte{akaAttrTrustInd, 0x01, 0x00, 0x03}, wantErr: true},
		{name: "wrong attribute", wire: []byte{akaAttrIPMSRes, 0x01, 0x00, byte(TrustRelationshipTrusted)}, wantErr: true},
		{name: "invalid length", wire: []byte{akaAttrTrustInd, 0x02, 0x00, byte(TrustRelationshipTrusted), 0x00, 0x00, 0x00, 0x00}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TrustIndication
			err := got.UnmarshalBinary(tt.wire)
			if tt.wantErr {
				if err == nil {
					t.Fatal("UnmarshalBinary() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.Relationship != tt.want {
				t.Fatalf("Relationship = %d, want %d", got.Relationship, tt.want)
			}
		})
	}
}

func TestBuildNotificationResponsePacket(t *testing.T) {
	autKey := bytes.Repeat([]byte{0x11}, 16)
	encrKey := bytes.Repeat([]byte{0x22}, 16)

	tests := []struct {
		name          string
		notification  AKANotification
		fastReauth    bool
		wantMAC       bool
		wantEncrypted bool
		wantErr       bool
	}{
		{
			name:          "protected full auth omits encrypted counter attrs",
			notification:  AKANotification{Code: akaNotificationSuccess, Success: true, Protected: true},
			fastReauth:    false,
			wantMAC:       true,
			wantEncrypted: false,
		},
		{
			name:          "protected fast reauth includes encrypted counter attrs",
			notification:  AKANotification{Code: akaNotificationSuccess, Success: true, Protected: true},
			fastReauth:    true,
			wantMAC:       true,
			wantEncrypted: true,
		},
		{
			name:          "pre-challenge failure omits protection attrs",
			notification:  AKANotification{Code: 0x4000, Protected: false},
			fastReauth:    false,
			wantMAC:       false,
			wantEncrypted: false,
		},
		{
			name:         "protected flag mismatch",
			notification: AKANotification{Code: akaNotificationSuccess, Success: true},
			wantErr:      true,
		},
		{
			name:         "success flag mismatch",
			notification: AKANotification{Code: akaNotificationSuccess, Protected: true},
			wantErr:      true,
		},
		{
			name:         "success cannot be pre-challenge",
			notification: AKANotification{Code: 0xc000, Success: true},
			wantErr:      true,
		},
		{
			name:         "pre-challenge cannot be fast reauth",
			notification: AKANotification{Code: 0x4000},
			fastReauth:   true,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := BuildNotificationResponsePacket(7, tt.notification, tt.fastReauth, 3, autKey, encrKey)
			if tt.wantErr {
				if err == nil {
					t.Fatal("BuildNotificationResponsePacket() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildNotificationResponsePacket() error = %v", err)
			}

			var got AKAMessage
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			if hasMAC := HasAttribute(got.Attributes, akaAttrMAC); hasMAC != tt.wantMAC {
				t.Fatalf("HasAttribute(AT_MAC) = %v, want %v", hasMAC, tt.wantMAC)
			}
			hasIV := HasAttribute(got.Attributes, akaAttrIV)
			hasEncrypted := HasAttribute(got.Attributes, akaAttrEncryptedData)
			if hasIV != tt.wantEncrypted {
				t.Fatalf("HasAttribute(AT_IV) = %v, want %v", hasIV, tt.wantEncrypted)
			}
			if hasEncrypted != tt.wantEncrypted {
				t.Fatalf("HasAttribute(AT_ENCR_DATA) = %v, want %v", hasEncrypted, tt.wantEncrypted)
			}
		})
	}
}

func TestAKANotificationUnmarshalAttributes(t *testing.T) {
	tests := []struct {
		name    string
		attrs   []AKAAttribute
		want    AKANotification
		wantErr bool
	}{
		{
			name: "success after challenge",
			attrs: []AKAAttribute{
				{Type: akaAttrNotification, Value: []byte{0x80, 0x00}},
				{Type: akaAttrMAC, Value: append([]byte{0x00, 0x00}, make([]byte, akaMACLen)...)},
			},
			want: AKANotification{Code: akaNotificationSuccess, Success: true, Protected: true},
		},
		{
			name:  "pre challenge failure",
			attrs: []AKAAttribute{{Type: akaAttrNotification, Value: []byte{0x40, 0x00}}},
			want:  AKANotification{Code: 0x4000, Protected: false},
		},
		{
			name:    "missing",
			wantErr: true,
		},
		{
			name: "duplicate",
			attrs: []AKAAttribute{
				{Type: akaAttrNotification, Value: []byte{0x80, 0x00}},
				{Type: akaAttrNotification, Value: []byte{0x80, 0x00}},
			},
			wantErr: true,
		},
		{
			name:    "invalid length",
			attrs:   []AKAAttribute{{Type: akaAttrNotification, Value: []byte{0x80, 0x00, 0x00, 0x00}}},
			wantErr: true,
		},
		{
			name:    "success pre challenge",
			attrs:   []AKAAttribute{{Type: akaAttrNotification, Value: []byte{0xc0, 0x00}}},
			wantErr: true,
		},
		{
			name: "unknown non-skippable",
			attrs: []AKAAttribute{
				{Type: akaAttrNotification, Value: []byte{0x80, 0x00}},
				{Type: 9, Value: []byte{0x00, 0x00}},
			},
			wantErr: true,
		},
		{
			name: "known attribute from another subtype",
			attrs: []AKAAttribute{
				{Type: akaAttrNotification, Value: []byte{0x80, 0x00}},
				{Type: akaAttrMAC, Value: append([]byte{0x00, 0x00}, make([]byte, akaMACLen)...)},
				{Type: akaAttrResultInd, Value: []byte{0x00, 0x00}},
			},
			wantErr: true,
		},
		{
			name:    "protected notification without mac",
			attrs:   []AKAAttribute{{Type: akaAttrNotification, Value: []byte{0x80, 0x00}}},
			wantErr: true,
		},
		{
			name: "pre-challenge notification with mac",
			attrs: []AKAAttribute{
				{Type: akaAttrNotification, Value: []byte{0x40, 0x00}},
				{Type: akaAttrMAC, Value: append([]byte{0x00, 0x00}, make([]byte, akaMACLen)...)},
			},
			wantErr: true,
		},
		{
			name: "invalid mac length",
			attrs: []AKAAttribute{
				{Type: akaAttrNotification, Value: []byte{0x80, 0x00}},
				{Type: akaAttrMAC, Value: append([]byte{0x00, 0x00}, make([]byte, akaMACLen-4)...)},
			},
			wantErr: true,
		},
		{
			name: "invalid iv length",
			attrs: []AKAAttribute{
				{Type: akaAttrNotification, Value: []byte{0x80, 0x00}},
				{Type: akaAttrMAC, Value: append([]byte{0x00, 0x00}, make([]byte, akaMACLen)...)},
				{Type: akaAttrIV, Value: append([]byte{0x00, 0x00}, make([]byte, akaVectorLen-4)...)},
				{Type: akaAttrEncryptedData, Value: append([]byte{0x00, 0x00}, make([]byte, aes.BlockSize)...)},
			},
			wantErr: true,
		},
		{
			name: "unaligned encrypted data",
			attrs: []AKAAttribute{
				{Type: akaAttrNotification, Value: []byte{0x80, 0x00}},
				{Type: akaAttrMAC, Value: append([]byte{0x00, 0x00}, make([]byte, akaMACLen)...)},
				{Type: akaAttrIV, Value: append([]byte{0x00, 0x00}, make([]byte, akaVectorLen)...)},
				{Type: akaAttrEncryptedData, Value: append([]byte{0x00, 0x00}, make([]byte, aes.BlockSize-4)...)},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got AKANotification
			err := got.UnmarshalAttributes(tt.attrs)
			if tt.wantErr {
				if err == nil {
					t.Fatal("UnmarshalAttributes() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalAttributes() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("AKANotification = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestBiddingMarshalBinary(t *testing.T) {
	tests := []struct {
		name string
		in   Bidding
		want []byte
	}{
		{name: "supports aka prime", in: Bidding{SupportsAKAPrime: true}, want: []byte{akaAttrBidding, 0x01, 0x80, 0x00}},
		{name: "does not support aka prime", in: Bidding{}, want: []byte{akaAttrBidding, 0x01, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.in.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("MarshalBinary() = % X, want % X", got, tt.want)
			}
		})
	}
}

func TestBiddingUnmarshalBinary(t *testing.T) {
	tests := []struct {
		name        string
		wire        []byte
		wantSupport bool
		wantErr     bool
	}{
		{name: "supports aka prime", wire: []byte{akaAttrBidding, 0x01, 0x80, 0x00}, wantSupport: true},
		{name: "does not support aka prime", wire: []byte{akaAttrBidding, 0x01, 0x00, 0x00}},
		{name: "reserved bits ignored", wire: []byte{akaAttrBidding, 0x01, 0x40, 0x00}},
		{name: "wrong attribute", wire: []byte{akaAttrResultInd, 0x01, 0x00, 0x00}, wantErr: true},
		{name: "invalid length", wire: []byte{akaAttrBidding, 0x02, 0x00, 0x00}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Bidding
			err := got.UnmarshalBinary(tt.wire)
			if tt.wantErr {
				if err == nil {
					t.Fatal("UnmarshalBinary() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.SupportsAKAPrime != tt.wantSupport {
				t.Fatalf("SupportsAKAPrime = %t, want %t", got.SupportsAKAPrime, tt.wantSupport)
			}
		})
	}
}

func TestKDFInputMarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		in      KDFInput
		want    []byte
		wantErr bool
	}{
		{
			name: "reference network name vector",
			in:   KDFInput{NetworkName: []byte("example.net")},
			want: mustHex(t, "1704000B6578616D706C652E6E657400"),
		},
		{
			name:    "empty network name",
			in:      KDFInput{},
			wantErr: true,
		},
		{
			name:    "network name exceeds 24.302 limit",
			in:      KDFInput{NetworkName: bytes.Repeat([]byte("a"), akaNetworkNameMaxLen+1)},
			wantErr: true,
		},
		{name: "invalid UTF-8", in: KDFInput{NetworkName: []byte{0xff}}, wantErr: true},
		{name: "embedded NUL", in: KDFInput{NetworkName: []byte{'W', 0, 'L', 'A', 'N'}}, wantErr: true},
		{name: "not NFKC-normalized", in: KDFInput{NetworkName: []byte("ＷＬＡＮ")}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.in.MarshalBinary()
			if tt.wantErr {
				if err == nil {
					t.Fatal("MarshalBinary() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("MarshalBinary() = % X, want % X", got, tt.want)
			}
		})
	}
}

func TestKDFInputUnmarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		wire    []byte
		want    []byte
		wantErr bool
	}{
		{name: "reference network name vector", wire: mustHex(t, "1704000B6578616D706C652E6E657400"), want: []byte("example.net")},
		{name: "empty network name", wire: mustHex(t, "17010000"), wantErr: true},
		{name: "wrong attribute", wire: mustHex(t, "18010001"), wantErr: true},
		{name: "truncated actual length", wire: mustHex(t, "1704000D6578616D706C652E6E657400"), wantErr: true},
		{name: "network name exceeds 24.302 limit", wire: mustKDFInputWire(t, bytes.Repeat([]byte("a"), akaNetworkNameMaxLen+1)), wantErr: true},
		{name: "invalid UTF-8", wire: mustHex(t, "17020001FF000000"), wantErr: true},
		{name: "embedded NUL", wire: mustKDFInputWire(t, []byte{'W', 0, 'L', 'A', 'N'}), wantErr: true},
		{name: "not NFKC-normalized", wire: mustKDFInputWire(t, []byte("ＷＬＡＮ")), wantErr: true},
		{name: "non-zero padding", wire: mustHex(t, "1702000161000001"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got KDFInput
			err := got.UnmarshalBinary(tt.wire)
			if tt.wantErr {
				if err == nil {
					t.Fatal("UnmarshalBinary() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if !bytes.Equal(got.NetworkName, tt.want) {
				t.Fatalf("NetworkName = % X, want % X", got.NetworkName, tt.want)
			}
		})
	}
}

func TestKDFMarshalBinary(t *testing.T) {
	got, err := (KDF{Version: akaPrimeKDFDefault}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	want := mustHex(t, "18010001")
	if !bytes.Equal(got, want) {
		t.Fatalf("MarshalBinary() = % X, want % X", got, want)
	}
}

func TestKDFUnmarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		wire    []byte
		want    uint16
		wantErr bool
	}{
		{name: "default kdf", wire: mustHex(t, "18010001"), want: akaPrimeKDFDefault},
		{name: "wrong attribute", wire: mustHex(t, "17010000"), wantErr: true},
		{name: "invalid length", wire: mustHex(t, "1802000100000000"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got KDF
			err := got.UnmarshalBinary(tt.wire)
			if tt.wantErr {
				if err == nil {
					t.Fatal("UnmarshalBinary() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.Version != tt.want {
				t.Fatalf("Version = %d, want %d", got.Version, tt.want)
			}
		})
	}
}

func TestIPMSIndicationMarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		ind     IPMSIndication
		want    []byte
		wantErr bool
	}{
		{name: "nbm only", ind: IPMSIndication{Support: IPMSSupportNBMOnly}, want: []byte{akaAttrIPMSInd, 0x01, 0x00, 0x02}},
		{name: "reserved value", ind: IPMSIndication{Support: 15}, wantErr: true},
		{name: "empty value", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ind.MarshalBinary()
			if tt.wantErr {
				if err == nil {
					t.Fatal("MarshalBinary() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("MarshalBinary() = % X, want % X", got, tt.want)
			}
		})
	}
}

func TestIPMSSelectionFromAttributes(t *testing.T) {
	tests := []struct {
		name          string
		attrs         []AKAAttribute
		wantSelection IPMSSelection
		wantOK        bool
		wantErr       bool
	}{
		{name: "missing"},
		{
			name:          "nbm selected",
			attrs:         []AKAAttribute{{Type: akaAttrIPMSRes, Value: []byte{0x00, byte(IPMSSelectionNBM)}}},
			wantSelection: IPMSSelectionNBM,
			wantOK:        true,
		},
		{
			name:    "invalid length",
			attrs:   []AKAAttribute{{Type: akaAttrIPMSRes, Value: []byte{0x00, byte(IPMSSelectionNBM), 0x00, 0x00}}},
			wantOK:  true,
			wantErr: true,
		},
		{
			name:    "reserved octet",
			attrs:   []AKAAttribute{{Type: akaAttrIPMSRes, Value: []byte{0x01, byte(IPMSSelectionNBM)}}},
			wantOK:  true,
			wantErr: true,
		},
		{
			name:    "reserved selection",
			attrs:   []AKAAttribute{{Type: akaAttrIPMSRes, Value: []byte{0x00, 0x04}}},
			wantOK:  true,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok, err := IPMSSelectionFromAttributes(tt.attrs)
			if ok != tt.wantOK {
				t.Fatalf("IPMSSelectionFromAttributes() ok = %t, want %t", ok, tt.wantOK)
			}
			if tt.wantErr {
				if err == nil {
					t.Fatal("IPMSSelectionFromAttributes() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("IPMSSelectionFromAttributes() error = %v", err)
			}
			if got != tt.wantSelection {
				t.Fatalf("IPMSSelectionFromAttributes() selection = %d, want %d", got, tt.wantSelection)
			}
		})
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	got, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) error = %v", value, err)
	}
	return got
}

func marshalAKAMessageUncheckedForTest(t *testing.T, message AKAMessage) []byte {
	t.Helper()
	payload := []byte{message.Subtype, 0x00, 0x00}
	for _, attr := range message.Attributes {
		wire, err := attr.MarshalBinary()
		if err != nil {
			t.Fatalf("AKAAttribute.MarshalBinary() error = %v", err)
		}
		payload = append(payload, wire...)
	}
	eapType := message.EAPType
	if eapType == 0 {
		eapType = eapTypeAKA
	}
	wire, err := (EAPPacket{
		Code:       message.Code,
		Identifier: message.Identifier,
		Type:       eapType,
		HasType:    true,
		Data:       payload,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("EAPPacket.MarshalBinary() error = %v", err)
	}
	return wire
}

func mustKDFInputWire(t *testing.T, networkName []byte) []byte {
	t.Helper()
	wire, err := buildAKAStringAttribute(akaAttrKDFInput, string(networkName)).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	return wire
}

func assertAKAKeys(t *testing.T, got, want AKAKeys) {
	t.Helper()
	if !bytes.Equal(got.MK, want.MK) {
		t.Fatalf("MK = % X, want % X", got.MK, want.MK)
	}
	if !bytes.Equal(got.ENCR, want.ENCR) {
		t.Fatalf("ENCR = % X, want % X", got.ENCR, want.ENCR)
	}
	if !bytes.Equal(got.AUT, want.AUT) {
		t.Fatalf("AUT = % X, want % X", got.AUT, want.AUT)
	}
	if !bytes.Equal(got.MSK, want.MSK) {
		t.Fatalf("MSK = % X, want % X", got.MSK, want.MSK)
	}
	if !bytes.Equal(got.EMSK, want.EMSK) {
		t.Fatalf("EMSK = % X, want % X", got.EMSK, want.EMSK)
	}
}

func assertAKAPrimeKeys(t *testing.T, got, want AKAPrimeKeys) {
	t.Helper()
	if !bytes.Equal(got.CKPrime, want.CKPrime) {
		t.Fatalf("CKPrime = % X, want % X", got.CKPrime, want.CKPrime)
	}
	if !bytes.Equal(got.IKPrime, want.IKPrime) {
		t.Fatalf("IKPrime = % X, want % X", got.IKPrime, want.IKPrime)
	}
	if !bytes.Equal(got.ENCR, want.ENCR) {
		t.Fatalf("ENCR = % X, want % X", got.ENCR, want.ENCR)
	}
	if !bytes.Equal(got.AUT, want.AUT) {
		t.Fatalf("AUT = % X, want % X", got.AUT, want.AUT)
	}
	if !bytes.Equal(got.RE, want.RE) {
		t.Fatalf("RE = % X, want % X", got.RE, want.RE)
	}
	if !bytes.Equal(got.MSK, want.MSK) {
		t.Fatalf("MSK = % X, want % X", got.MSK, want.MSK)
	}
	if !bytes.Equal(got.EMSK, want.EMSK) {
		t.Fatalf("EMSK = % X, want % X", got.EMSK, want.EMSK)
	}
}

func TestAKAReauthenticationUnmarshalMessageValidatesAttributeLengths(t *testing.T) {
	encrKey := bytes.Repeat([]byte{0x22}, 16)
	validCounter := []byte{0x00, 0x03}
	validNonce := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x33}, akaVectorLen)...)

	tests := []struct {
		name        string
		eapType     byte
		counter     []byte
		nonce       []byte
		macValue    []byte
		nestedAttrs []AKAAttribute
		topAttrs    []AKAAttribute
		wantErr     bool
	}{
		{
			name:    "valid",
			counter: validCounter,
			nonce:   validNonce,
		},
		{
			name:    "counter too long",
			counter: []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x00},
			nonce:   validNonce,
			wantErr: true,
		},
		{
			name:    "nonce too long",
			counter: validCounter,
			nonce:   append(validNonce, 0x00, 0x00, 0x00, 0x00),
			wantErr: true,
		},
		{
			name:     "result indication too long",
			counter:  validCounter,
			nonce:    validNonce,
			topAttrs: []AKAAttribute{{Type: akaAttrResultInd, Value: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}},
			wantErr:  true,
		},
		{
			name:     "top-level unknown non-skippable",
			counter:  validCounter,
			nonce:    validNonce,
			topAttrs: []AKAAttribute{{Type: 9, Value: []byte{0x00, 0x00}}},
			wantErr:  true,
		},
		{
			name:     "top-level known attribute from another subtype",
			counter:  validCounter,
			nonce:    validNonce,
			topAttrs: []AKAAttribute{buildAKAStringAttribute(akaAttrNextPseudonym, "pseudonym")},
			wantErr:  true,
		},
		{
			name:        "encrypted known attribute from another subtype",
			counter:     validCounter,
			nonce:       validNonce,
			nestedAttrs: []AKAAttribute{buildAKAStringAttribute(akaAttrNextPseudonym, "pseudonym")},
			wantErr:     true,
		},
		{
			name:     "invalid mac length",
			counter:  validCounter,
			nonce:    validNonce,
			macValue: append([]byte{0x00, 0x00}, make([]byte, akaMACLen-4)...),
			wantErr:  true,
		},
		{
			name:     "aka rejects sha256 checkcode length",
			counter:  validCounter,
			nonce:    validNonce,
			topAttrs: []AKAAttribute{{Type: akaAttrCheckcode, Value: append([]byte{0x00, 0x00}, make([]byte, sha256.Size)...)}},
			wantErr:  true,
		},
		{
			name:     "aka prime rejects sha1 checkcode length",
			eapType:  eapTypeAKAPrime,
			counter:  validCounter,
			nonce:    validNonce,
			topAttrs: []AKAAttribute{{Type: akaAttrCheckcode, Value: append([]byte{0x00, 0x00}, make([]byte, sha1.Size)...)}},
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nested := []AKAAttribute{
				{Type: akaAttrCounter, Value: tt.counter},
				{Type: akaAttrNonceS, Value: tt.nonce},
			}
			nested = append(nested, tt.nestedAttrs...)
			encrypted, err := encryptAKAAttributes(nested, encrKey)
			if err != nil {
				t.Fatalf("encryptAKAAttributes() error = %v", err)
			}
			attrs := append([]AKAAttribute(nil), encrypted...)
			macValue := tt.macValue
			if macValue == nil {
				macValue = append([]byte{0x00, 0x00}, make([]byte, akaMACLen)...)
			}
			attrs = append(attrs, AKAAttribute{Type: akaAttrMAC, Value: macValue})
			attrs = append(attrs, tt.topAttrs...)
			message := AKAMessage{
				Code:       eapCodeRequest,
				Identifier: 7,
				EAPType:    tt.eapType,
				Subtype:    akaSubtypeReauthentication,
				Attributes: attrs,
			}

			var got AKAReauthentication
			err = got.UnmarshalMessage(message, encrKey)
			if tt.wantErr {
				if err == nil {
					t.Fatal("UnmarshalMessage() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalMessage() error = %v", err)
			}
			if got.Counter != 3 || !bytes.Equal(got.NonceS, validNonce[akaAttributeReservedLen:]) {
				t.Fatalf("AKAReauthentication = %+v", got)
			}
		})
	}
}

func TestDecryptAttributesValidatesEncryptedAttributes(t *testing.T) {
	encrKey := bytes.Repeat([]byte{0x22}, aes.BlockSize)
	counterAttr := buildAKAUint16Attribute(akaAttrCounter, 3)
	validPadding := AKAAttribute{Type: akaAttrPadding, Value: make([]byte, akaPaddingMaxLen-akaAttributeReservedLen)}
	nonZeroPadding := AKAAttribute{Type: akaAttrPadding, Value: append([]byte{0x01}, make([]byte, akaPaddingMaxLen-akaAttributeReservedLen-1)...)}
	oversizedPadding := AKAAttribute{Type: akaAttrPadding, Value: make([]byte, aes.BlockSize-akaAttributeReservedLen)}
	alignedAttrs := []AKAAttribute{
		counterAttr,
		buildAKAUint16Attribute(akaAttrCounterTooSmall, 0),
		buildAKAUint16Attribute(akaAttrClientErrorCode, 0),
		buildAKAUint16Attribute(akaAttrResultInd, 0),
	}

	tests := []struct {
		name       string
		attrs      []AKAAttribute
		mutate     func([]AKAAttribute) []AKAAttribute
		wantErr    bool
		wantNested int
	}{
		{
			name:       "valid padding last",
			attrs:      []AKAAttribute{counterAttr, validPadding},
			wantNested: 1,
		},
		{
			name:    "iv too long",
			attrs:   []AKAAttribute{counterAttr, validPadding},
			mutate:  appendToIVForTest,
			wantErr: true,
		},
		{
			name:    "padding not last",
			attrs:   []AKAAttribute{validPadding, counterAttr},
			wantErr: true,
		},
		{
			name:    "padding length too long",
			attrs:   []AKAAttribute{oversizedPadding},
			wantErr: true,
		},
		{
			name:    "padding not zero",
			attrs:   []AKAAttribute{counterAttr, nonZeroPadding},
			wantErr: true,
		},
		{
			name:    "nested unknown non-skippable",
			attrs:   []AKAAttribute{{Type: 9, Value: []byte{0x00, 0x00}}, validPadding},
			wantErr: true,
		},
		{
			name:       "no padding needed",
			attrs:      alignedAttrs,
			wantNested: len(alignedAttrs),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted := encryptAKAAttributesForDecryptTest(t, tt.attrs, encrKey)
			if tt.mutate != nil {
				encrypted = tt.mutate(encrypted)
			}
			got, err := DecryptAttributes(encrypted, encrKey)
			if tt.wantErr {
				if err == nil {
					t.Fatal("DecryptAttributes() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("DecryptAttributes() error = %v", err)
			}
			if len(got) != tt.wantNested {
				t.Fatalf("len(DecryptAttributes()) = %d, want %d", len(got), tt.wantNested)
			}
		})
	}
}

func TestDecryptAttributesRejectsNon128BitEncryptionKeys(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{name: "empty"},
		{name: "aes 192", key: make([]byte, 24)},
		{name: "aes 256", key: make([]byte, 32)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecryptAttributes(nil, tt.key); err == nil {
				t.Fatal("DecryptAttributes() error = nil, want error")
			}
		})
	}
}

func TestDecryptChallengeAttributesValidatesNestedAttributes(t *testing.T) {
	encrKey := bytes.Repeat([]byte{0x22}, aes.BlockSize)
	tests := []struct {
		name       string
		nested     []AKAAttribute
		wantErr    bool
		wantNested int
	}{
		{
			name: "challenge identities",
			nested: []AKAAttribute{
				buildAKAStringAttribute(akaAttrNextPseudonym, "pseudonym"),
				buildAKAStringAttribute(akaAttrNextReauthID, "reauth@example.net"),
			},
			wantNested: 2,
		},
		{
			name:    "known attribute from another subtype",
			nested:  []AKAAttribute{buildAKAUint16Attribute(akaAttrCounter, 1)},
			wantErr: true,
		},
		{
			name:       "unknown skippable attribute",
			nested:     []AKAAttribute{{Type: 200, Value: []byte{0x00, 0x00}}},
			wantNested: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := encryptAKAAttributes(tt.nested, encrKey)
			if err != nil {
				t.Fatalf("encryptAKAAttributes() error = %v", err)
			}
			got, err := DecryptChallengeAttributes(encrypted, encrKey)
			if tt.wantErr {
				if err == nil {
					t.Fatal("DecryptChallengeAttributes() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("DecryptChallengeAttributes() error = %v", err)
			}
			if len(got) != tt.wantNested {
				t.Fatalf("len(DecryptChallengeAttributes()) = %d, want %d", len(got), tt.wantNested)
			}
		})
	}
}

func appendToIVForTest(attrs []AKAAttribute) []AKAAttribute {
	for i := range attrs {
		if attrs[i].Type == akaAttrIV {
			attrs[i].Value = append(attrs[i].Value, 0x00, 0x00, 0x00, 0x00)
		}
	}
	return attrs
}

func encryptAKAAttributesForDecryptTest(t *testing.T, attrs []AKAAttribute, encrKey []byte) []AKAAttribute {
	t.Helper()
	plain, err := marshalAKAAttributes(attrs)
	if err != nil {
		t.Fatalf("marshalAKAAttributes() error = %v", err)
	}
	if len(plain)%aes.BlockSize != 0 {
		t.Fatalf("plain length = %d, want block aligned", len(plain))
	}
	iv := bytes.Repeat([]byte{0x44}, aes.BlockSize)
	block, err := aes.NewCipher(encrKey)
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	ciphertext := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plain)
	return []AKAAttribute{
		{Type: akaAttrIV, Value: append([]byte{0x00, 0x00}, iv...)},
		{Type: akaAttrEncryptedData, Value: append([]byte{0x00, 0x00}, ciphertext...)},
	}
}
