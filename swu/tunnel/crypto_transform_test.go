package tunnel

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/damonto/ims-go/ipsec/esp"
	"github.com/damonto/ims-go/swu/handshake"
	"github.com/damonto/ims-go/swu/ike"
)

func TestMODPGroupsRFC3526(t *testing.T) {
	tests := []struct {
		name  string
		group uint16
		bits  int
	}{
		{name: "group 2", group: transformDH1024MODP, bits: 1024},
		{name: "group 5", group: transformDH1536MODP, bits: 1536},
		{name: "group 14", group: transformDH2048MODP, bits: 2048},
		{name: "group 15", group: transformDH3072MODP, bits: 3072},
		{name: "group 16", group: transformDH4096MODP, bits: 4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prime, size, err := modpGroup(tt.group)
			if err != nil {
				t.Fatalf("modpGroup() error = %v", err)
			}
			if got := prime.BitLen(); got != tt.bits {
				t.Fatalf("prime.BitLen() = %d, want %d", got, tt.bits)
			}
			if got := size; got != tt.bits/8 {
				t.Fatalf("group size = %d, want %d", got, tt.bits/8)
			}
		})
	}
}

func TestPRFTransformsRFCVectors(t *testing.T) {
	tests := []struct {
		name      string
		transform uint16
		key       []byte
		data      []byte
		want      string
	}{
		{
			name:      "AES XCBC RFC 4434",
			transform: transformPRFAES128XCBC,
			key:       mustDecodeHex(t, "000102030405060708090a0b0c0d0e0fedcb"),
			data:      mustDecodeHex(t, "000102030405060708090a0b0c0d0e0f10111213"),
			want:      "8cd3c93ae598a9803006ffb67c40e9e4",
		},
		{
			name:      "HMAC SHA384 RFC 4868",
			transform: transformPRFHMACSHA384,
			key:       bytes.Repeat([]byte{0x0b}, 20),
			data:      []byte("Hi There"),
			want:      "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
		},
		{
			name:      "HMAC SHA512 RFC 4868",
			transform: transformPRFHMACSHA512,
			key:       bytes.Repeat([]byte{0x0b}, 20),
			data:      []byte("Hi There"),
			want:      "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crypto := ikeCrypto{prf: tt.transform}
			got, err := crypto.prfSum(tt.key, tt.data)
			if err != nil {
				t.Fatalf("prfSum() error = %v", err)
			}
			want := mustDecodeHex(t, tt.want)
			if !bytes.Equal(got, want) {
				t.Fatalf("prfSum() = %x, want %x", got, want)
			}
		})
	}
}

func TestIntegrityTransformsRFCVectors(t *testing.T) {
	tests := []struct {
		name      string
		transform uint16
		key       []byte
		data      []byte
		want      string
	}{
		{
			name:      "AES XCBC 96 RFC 3566",
			transform: transformINTEGAESXCBC96,
			key:       mustDecodeHex(t, "000102030405060708090a0b0c0d0e0f"),
			data:      mustDecodeHex(t, "000102030405060708090a0b0c0d0e0f10111213"),
			want:      "47f51b4564966215b8985c63",
		},
		{
			name:      "HMAC SHA384 192 RFC 4868",
			transform: transformINTEGHMACSHA384,
			key:       bytes.Repeat([]byte("Jefe"), 12),
			data:      []byte("what do ya want for nothing?"),
			want:      "2c7353974f1842fd66d53c452ca42122b28c0b594cfb184d",
		},
		{
			name:      "HMAC SHA512 256 RFC 4868",
			transform: transformINTEGHMACSHA512,
			key:       bytes.Repeat([]byte{0x0b}, 64),
			data:      []byte("Hi There"),
			want:      "637edc6e01dce7e6742a99451aae82df23da3e92439e590e43e761b33e910fb8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crypto := ikeCrypto{integ: tt.transform}
			got, err := crypto.integritySum(tt.key, tt.data)
			if err != nil {
				t.Fatalf("integritySum() error = %v", err)
			}
			want := mustDecodeHex(t, tt.want)
			if !bytes.Equal(got, want) {
				t.Fatalf("integritySum() = %x, want %x", got, want)
			}
		})
	}
}

func TestConfigAcceptsPixelTransformSets(t *testing.T) {
	cfg := Config{
		RemoteAddr:                   "127.0.0.1",
		DHGroups:                     []uint16{2, 5, 14, 15, 16},
		IKEEncryption:                []uint16{12, 13},
		IKEEncryptionAESCTRKeyLens:   []uint16{128},
		IKEIntegrity:                 []uint16{2, 5, 12, 13, 14},
		IKEPRF:                       []uint16{2, 4, 5, 6, 7},
		ChildEncryption:              []uint16{12, 13},
		ChildEncryptionAESCTRKeyLens: []uint16{128},
		ChildIntegrity:               []uint16{2, 5, 12, 13, 14},
	}
	if _, err := cfg.Normalized(); err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}
}

func TestInitialSKEYSEEDNonceRFC7296(t *testing.T) {
	nonceI := []byte("initiator-nonce-data")
	nonceR := []byte("responder-nonce-data")
	tests := []struct {
		name    string
		prf     uint16
		nonceI  []byte
		nonceR  []byte
		want    []byte
		wantErr bool
	}{
		{
			name:   "HMAC uses complete nonces",
			prf:    transformPRFHMACSHA256,
			nonceI: nonceI,
			nonceR: nonceR,
			want:   append(append([]byte(nil), nonceI...), nonceR...),
		},
		{
			name:   "AES XCBC uses first 64 bits of each nonce",
			prf:    transformPRFAES128XCBC,
			nonceI: nonceI,
			nonceR: nonceR,
			want:   append(append([]byte(nil), nonceI[:8]...), nonceR[:8]...),
		},
		{
			name:    "AES XCBC rejects short nonce",
			prf:     transformPRFAES128XCBC,
			nonceI:  []byte("short"),
			nonceR:  nonceR,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crypto := ikeCrypto{prf: tt.prf, nonceI: tt.nonceI, nonceR: tt.nonceR}
			got, err := crypto.initialSKEYSEEDNonce()
			if (err != nil) != tt.wantErr {
				t.Fatalf("initialSKEYSEEDNonce() error = %v, wantErr %t", err, tt.wantErr)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("initialSKEYSEEDNonce() = %x, want %x", got, tt.want)
			}
		})
	}
}

func TestAESCTRIVExhaustionIsPermanent(t *testing.T) {
	crypto := ikeCrypto{encr: transformENCRAESCTR}
	crypto.ctrIV.Store(^uint64(0) - 1)
	if _, err := crypto.nextEncryptionIV(); err != nil {
		t.Fatalf("nextEncryptionIV() final IV error = %v", err)
	}
	for range 2 {
		if _, err := crypto.nextEncryptionIV(); err == nil {
			t.Fatal("nextEncryptionIV() error = nil after exhaustion")
		}
	}
}

func TestAESCTRProposalTransformsUseIndependentKeySizes(t *testing.T) {
	tests := []struct {
		name  string
		build func() []ike.Proposal
	}{
		{
			name: "IKE",
			build: func() []ike.Proposal {
				return ikeSAProposals(handshake.Config{
					IKEEncryption:              []uint16{transformENCRAESCBC, transformENCRAESCTR},
					IKEEncryptionKeyLens:       []uint16{128, 256},
					IKEEncryptionAESCTRKeyLens: []uint16{128},
				})
			},
		},
		{
			name: "Child",
			build: func() []ike.Proposal {
				return childSAProposals(handshake.Config{
					ChildEncryption:              []uint16{transformENCRAESCBC, transformENCRAESCTR},
					ChildEncryptionKeyLens:       []uint16{128, 256},
					ChildEncryptionAESCTRKeyLens: []uint16{128},
				}, 0x01020304)
			},
		},
	}
	want := []struct {
		transform uint16
		keyLen    uint16
	}{
		{transform: transformENCRAESCBC, keyLen: 128},
		{transform: transformENCRAESCBC, keyLen: 256},
		{transform: transformENCRAESCTR, keyLen: 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proposals := tt.build()
			if len(proposals) != 1 {
				t.Fatalf("proposal count = %d, want 1", len(proposals))
			}
			var got []struct {
				transform uint16
				keyLen    uint16
			}
			for _, transform := range proposals[0].Transforms {
				if transform.TransformType != transformTypeENCR {
					continue
				}
				keyLen, ok := transformKeyLength(transform)
				if !ok {
					t.Fatalf("encryption transform %d has no key length", transform.ID)
				}
				got = append(got, struct {
					transform uint16
					keyLen    uint16
				}{transform: transform.ID, keyLen: keyLen})
			}
			if len(got) != len(want) {
				t.Fatalf("encryption transforms = %+v, want %+v", got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("encryption transform %d = %+v, want %+v", i, got[i], want[i])
				}
			}
		})
	}
}

func TestIKEAESCTRRoundTripAndUniqueIV(t *testing.T) {
	crypto := testIKECrypto()
	crypto.encr = transformENCRAESCTR
	crypto.keys.SKEI = append(bytes.Repeat([]byte{0x33}, 16), 0x01, 0x02, 0x03, 0x04)
	crypto.keys.SKER = append(bytes.Repeat([]byte{0x44}, 16), 0x05, 0x06, 0x07, 0x08)
	header := ike.IKEHeader{
		InitiatorSPI: 0x0102030405060708,
		ResponderSPI: 0x1112131415161718,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeInformational,
		Flags:        flagInitiator,
		MessageID:    7,
	}
	payloads := []ike.Payload{&ike.NotifyPayload{NotifyType: notifyTypeTemporaryFailure, Data: []byte("ctr")}}

	wires := make([][]byte, 2)
	ivs := make([][]byte, 2)
	for i := range wires {
		wire, err := crypto.SealIKE(header, payloads, true)
		if err != nil {
			t.Fatalf("SealIKE(%d) error = %v", i, err)
		}
		wires[i] = wire
		var packet ike.IKEPacket
		if err := packet.UnmarshalBinary(wire); err != nil {
			t.Fatalf("UnmarshalBinary(%d) error = %v", i, err)
		}
		encrypted, ok := packet.Payloads[0].(*ike.EncryptedPayload)
		if !ok {
			t.Fatalf("payload = %T, want *ike.EncryptedPayload", packet.Payloads[0])
		}
		ivs[i] = append([]byte(nil), encrypted.Raw[:8]...)
		opened, err := crypto.OpenIKE(packet, true)
		if err != nil {
			t.Fatalf("OpenIKE(%d) error = %v", i, err)
		}
		notify := ike.FindNotifyPayload(opened, notifyTypeTemporaryFailure)
		if notify == nil || !bytes.Equal(notify.Data, []byte("ctr")) {
			t.Fatalf("OpenIKE(%d) notify = %+v, want ctr data", i, notify)
		}
	}
	if bytes.Equal(ivs[0], ivs[1]) {
		t.Fatalf("successive AES-CTR IVs are equal: %x", ivs[0])
	}

	tampered := append([]byte(nil), wires[0]...)
	tampered[len(tampered)-1] ^= 0x01
	var packet ike.IKEPacket
	if err := packet.UnmarshalBinary(tampered); err != nil {
		t.Fatalf("UnmarshalBinary(tampered) error = %v", err)
	}
	if _, err := crypto.OpenIKE(packet, true); err == nil {
		t.Fatal("OpenIKE(tampered) error = nil, want integrity error")
	}
}

func TestAESCTRKeyMaterialIncludesSalt(t *testing.T) {
	tests := []struct {
		name      string
		transform uint16
		wantLen   int
	}{
		{name: "AES-CBC 128", transform: transformENCRAESCBC, wantLen: 16},
		{name: "AES-CTR 128", transform: transformENCRAESCTR, wantLen: 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encryptionKeyMaterialLength(tt.transform, 128)
			if err != nil {
				t.Fatalf("encryptionKeyMaterialLength() error = %v", err)
			}
			if got != tt.wantLen {
				t.Fatalf("encryptionKeyMaterialLength() = %d, want %d", got, tt.wantLen)
			}
		})
	}
}

func TestIKEEncryptionKeyMaterialDerivation(t *testing.T) {
	tests := []struct {
		name      string
		transform uint16
		wantLen   int
	}{
		{name: "AES-CBC 128", transform: transformENCRAESCBC, wantLen: 16},
		{name: "AES-CTR 128 plus salt", transform: transformENCRAESCTR, wantLen: 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initiator, err := newIKECrypto(transformDH2048MODP)
			if err != nil {
				t.Fatalf("newIKECrypto(initiator) error = %v", err)
			}
			responder, err := newIKECrypto(transformDH2048MODP)
			if err != nil {
				t.Fatalf("newIKECrypto(responder) error = %v", err)
			}
			initiator.SetProposal(tt.transform, 128, transformINTEGHMACSHA196, transformPRFHMACSHA1)
			initiator.SetSPIs(0x0102030405060708, 0x1112131415161718)
			initiator.SetNonces(testNonce("initiator key material"), testNonce("responder key material"))

			if err := initiator.DeriveIKEKeys(responder.PublicKey()); err != nil {
				t.Fatalf("DeriveIKEKeys() error = %v", err)
			}
			if len(initiator.keys.SKEI) != tt.wantLen || len(initiator.keys.SKER) != tt.wantLen {
				t.Fatalf("IKE encryption key lengths = (%d, %d), want (%d, %d)", len(initiator.keys.SKEI), len(initiator.keys.SKER), tt.wantLen, tt.wantLen)
			}
		})
	}
}

func TestNegotiatedAESCTRTransforms(t *testing.T) {
	tests := []struct {
		name  string
		parse func() (uint16, uint16, error)
	}{
		{
			name: "IKE",
			parse: func() (uint16, uint16, error) {
				proposal := ike.Proposal{
					ProtocolID: proposalProtocolIKE,
					Transforms: []ike.Transform{
						encryptionTransform(transformENCRAESCTR, 128),
						{TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA196},
						{TransformType: transformTypePRF, ID: transformPRFHMACSHA1},
						{TransformType: transformTypeDH, ID: transformDH2048MODP},
					},
				}
				negotiated, err := negotiatedIKESAFromProposal(proposal, transformDH2048MODP)
				return negotiated.Encryption, negotiated.EncryptionKeyLen, err
			},
		},
		{
			name: "Child",
			parse: func() (uint16, uint16, error) {
				proposal := childSAResponseProposal(acceptedChildSA{Info: Info{
					Encryption:       transformENCRAESCTR,
					EncryptionKeyLen: 128,
					Integrity:        transformINTEGHMACSHA196,
				}}, 0x01020304)
				info, err := tunnelInfoFromProposal(proposal)
				return info.Encryption, info.EncryptionKeyLen, err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transform, keyLen, err := tt.parse()
			if err != nil {
				t.Fatalf("parse() error = %v", err)
			}
			if transform != transformENCRAESCTR || keyLen != 128 {
				t.Fatalf("negotiated encryption = (%d, %d), want (%d, 128)", transform, keyLen, transformENCRAESCTR)
			}
		})
	}
}

func TestNewESPCodecSplitsAESCTRKeyAndSalt(t *testing.T) {
	material := append(bytes.Repeat([]byte{0x11}, 16), 0xaa, 0xbb, 0xcc, 0xdd)
	codec := newESPCodec(0x01020304, Info{
		Encryption:       transformENCRAESCTR,
		EncryptionKeyLen: 128,
		Integrity:        transformINTEGHMACSHA196,
	}, material, bytes.Repeat([]byte{0x22}, 20))

	if codec.Encryption != esp.EncryptionAESCTR {
		t.Fatalf("Encryption = %q, want %q", codec.Encryption, esp.EncryptionAESCTR)
	}
	if !bytes.Equal(codec.EncryptionKey, material[:16]) {
		t.Fatalf("EncryptionKey = %x, want %x", codec.EncryptionKey, material[:16])
	}
	if codec.Salt != [4]byte{0xaa, 0xbb, 0xcc, 0xdd} {
		t.Fatalf("Salt = %x, want aabbccdd", codec.Salt)
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString(%q): %v", value, err)
	}
	return decoded
}
