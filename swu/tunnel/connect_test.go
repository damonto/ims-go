package tunnel

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/damonto/vowifi-go/swu/handshake"
	"github.com/damonto/vowifi-go/swu/ike"
)

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

func TestNewConnectStateUsesConfiguredDHGroup(t *testing.T) {
	tests := []struct {
		name string
		cfg  handshake.Config
		want uint16
	}{
		{name: "configured", cfg: handshake.Config{DHGroups: []uint16{transformDH2048MODP}}, want: transformDH2048MODP},
		{name: "fallback", cfg: handshake.Config{}, want: transformDH2048MODP},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, err := newConnectState(handshake.ConnectInput{
				IMEI:        "356789012345678",
				Card:        sessionTestCard{},
				OuterRemote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 500},
				Config:      tt.cfg,
			})
			if err != nil {
				t.Fatalf("newConnectState() error = %v", err)
			}
			if state.saInit.DHGroup != tt.want {
				t.Fatalf("DHGroup = %d, want %d", state.saInit.DHGroup, tt.want)
			}
		})
	}
}

func TestTunnelAddressesAcceptsIPv6Subnet(t *testing.T) {
	subnetValue := append(net.ParseIP("2001:db8::").To16(), 64)
	pcscf := net.ParseIP("2001:db8::100").To16()
	_, internalIPv6, _, pcscfIPv6 := tunnelAddresses([]ike.Attribute{
		ike.NewTLVAttribute(configAttrInternalIPv6Subnet, subnetValue),
		ike.NewTLVAttribute(configAttrPCSCFIPv6Address, pcscf),
	}, 0, 0)
	if !internalIPv6.Equal(net.ParseIP("2001:db8::")) {
		t.Fatalf("internalIPv6 = %s, want 2001:db8::", internalIPv6)
	}
	if !pcscfIPv6.Equal(net.ParseIP("2001:db8::100")) {
		t.Fatalf("pcscfIPv6 = %s, want 2001:db8::100", pcscfIPv6)
	}
}

func TestTunnelAddressesAcceptsConfiguredPCSCFAttributes(t *testing.T) {
	tests := []struct {
		name          string
		attrs         []ike.Attribute
		ipv4Attr      uint16
		ipv6Attr      uint16
		wantInternal4 net.IP
		wantInternal6 net.IP
		wantPCSCF4    net.IP
		wantPCSCF6    net.IP
	}{
		{
			name:          "separate ipv4 attribute",
			attrs:         []ike.Attribute{ike.NewTLVAttribute(configAttrInternalIPv4Address, net.IPv4(10, 1, 2, 3).To4()), ike.NewTLVAttribute(16384, net.IPv4(10, 9, 8, 7).To4())},
			ipv4Attr:      16384,
			ipv6Attr:      16386,
			wantInternal4: net.IPv4(10, 1, 2, 3).To4(),
			wantPCSCF4:    net.IPv4(10, 9, 8, 7).To4(),
		},
		{
			name:          "shared attribute ipv6 value",
			attrs:         []ike.Attribute{ike.NewTLVAttribute(configAttrInternalIPv6Address, net.ParseIP("2001:db8::1").To16()), ike.NewTLVAttribute(16384, net.ParseIP("2001:db8::100").To16())},
			ipv4Attr:      16384,
			ipv6Attr:      16384,
			wantInternal6: net.ParseIP("2001:db8::1").To16(),
			wantPCSCF6:    net.ParseIP("2001:db8::100").To16(),
		},
		{
			name:          "shared attribute ipv4 value",
			attrs:         []ike.Attribute{ike.NewTLVAttribute(configAttrInternalIPv4Address, net.IPv4(10, 1, 2, 3).To4()), ike.NewTLVAttribute(16384, net.IPv4(10, 9, 8, 7).To4())},
			ipv4Attr:      16384,
			ipv6Attr:      16384,
			wantInternal4: net.IPv4(10, 1, 2, 3).To4(),
			wantPCSCF4:    net.IPv4(10, 9, 8, 7).To4(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			internalIPv4, internalIPv6, pcscfIPv4, pcscfIPv6 := tunnelAddresses(tt.attrs, tt.ipv4Attr, tt.ipv6Attr)
			if !ipEqual(internalIPv4, tt.wantInternal4) {
				t.Fatalf("internalIPv4 = %s, want %s", internalIPv4, tt.wantInternal4)
			}
			if !ipEqual(internalIPv6, tt.wantInternal6) {
				t.Fatalf("internalIPv6 = %s, want %s", internalIPv6, tt.wantInternal6)
			}
			if !ipEqual(pcscfIPv4, tt.wantPCSCF4) {
				t.Fatalf("pcscfIPv4 = %s, want %s", pcscfIPv4, tt.wantPCSCF4)
			}
			if !ipEqual(pcscfIPv6, tt.wantPCSCF6) {
				t.Fatalf("pcscfIPv6 = %s, want %s", pcscfIPv6, tt.wantPCSCF6)
			}
		})
	}
}

func ipEqual(got, want net.IP) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	return got.Equal(want)
}

func TestDefaultIKEAuthInitPayloadsUsesConfiguredPCSCFAttributes(t *testing.T) {
	payloads, err := defaultIKEAuthInitPayloads(handshake.Config{
		PCSCFIPv4ConfigAttribute: 16384,
		PCSCFIPv6ConfigAttribute: 16386,
	}, "0454000121084653@nai.epc.mnc000.mcc454.3gppnetwork.org", 0x01020304)
	if err != nil {
		t.Fatalf("defaultIKEAuthInitPayloads() error = %v", err)
	}
	idr, ok := payloads[1].(*ike.IDPayload)
	if !ok {
		t.Fatalf("payload[1] = %T, want *ike.IDPayload", payloads[1])
	}
	if got := string(idr.Data); got != "ims" {
		t.Fatalf("IDr = %q, want ims", got)
	}
	config := ike.FindConfigPayload(payloads)
	if config == nil {
		t.Fatal("config payload is missing")
	}
	if !hasConfigAttribute(config.Attributes, 16384) || !hasConfigAttribute(config.Attributes, 16386) {
		t.Fatalf("config attrs = %v, want P-CSCF attrs 16384 and 16386", config.Attributes)
	}
	if !hasConfigAttribute(config.Attributes, configAttrPCSCFIPv4Address) || !hasConfigAttribute(config.Attributes, configAttrPCSCFIPv6Address) {
		t.Fatalf("config attrs = %v, want standard P-CSCF attrs", config.Attributes)
	}
}

func TestPCSCFRequestAttributesDeduplicatesSharedCarrierAttribute(t *testing.T) {
	got := pcscfRequestAttributes(handshake.Config{
		PCSCFIPv4ConfigAttribute: 16384,
		PCSCFIPv6ConfigAttribute: 16384,
	})
	want := []uint16{16384, configAttrPCSCFIPv4Address, configAttrPCSCFIPv6Address}
	if !slices.Equal(got, want) {
		t.Fatalf("pcscfRequestAttributes() = %v, want %v", got, want)
	}
}

func hasConfigAttribute(attrs []ike.Attribute, attrType uint16) bool {
	for _, attr := range attrs {
		if attr.Type == attrType {
			return true
		}
	}
	return false
}

func TestSAProposalsUseConfigWithoutFallback(t *testing.T) {
	tests := []struct {
		name            string
		cfg             handshake.Config
		wantIKE         int
		wantChild       int
		wantIKEKeyLen   uint16
		wantIKEInteg    uint16
		wantIKEPRF      uint16
		wantChildKeyLen uint16
		wantChildInteg  uint16
	}{
		{
			name:            "defaults are pixel supported intersection",
			cfg:             handshake.Config{},
			wantIKE:         4,
			wantChild:       2,
			wantIKEKeyLen:   128,
			wantIKEInteg:    transformINTEGHMACSHA256,
			wantIKEPRF:      transformPRFHMACSHA1,
			wantChildKeyLen: 128,
			wantChildInteg:  transformINTEGHMACSHA256,
		},
		{
			name: "custom values are not expanded",
			cfg: handshake.Config{
				IKEEncryptionKeyLens:   []uint16{256},
				IKEIntegrity:           []uint16{transformINTEGHMACSHA196},
				IKEPRF:                 []uint16{transformPRFHMACSHA1},
				ChildEncryptionKeyLens: []uint16{256},
				ChildIntegrity:         []uint16{transformINTEGHMACSHA196},
			},
			wantIKE:         1,
			wantChild:       1,
			wantIKEKeyLen:   256,
			wantIKEInteg:    transformINTEGHMACSHA196,
			wantIKEPRF:      transformPRFHMACSHA1,
			wantChildKeyLen: 256,
			wantChildInteg:  transformINTEGHMACSHA196,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ikeProposals := ikeSAProposals(tt.cfg, transformDH2048MODP)
			if len(ikeProposals) != tt.wantIKE {
				t.Fatalf("len(ikeProposals) = %d, want %d", len(ikeProposals), tt.wantIKE)
			}
			if got := proposalKeyLength(t, ikeProposals[0]); got != tt.wantIKEKeyLen {
				t.Fatalf("ike key len = %d, want %d", got, tt.wantIKEKeyLen)
			}
			if got := proposalTransformID(ikeProposals[0], transformTypeINTEG); got != tt.wantIKEInteg {
				t.Fatalf("ike integ = %d, want %d", got, tt.wantIKEInteg)
			}
			if got := proposalTransformID(ikeProposals[0], transformTypePRF); got != tt.wantIKEPRF {
				t.Fatalf("ike prf = %d, want %d", got, tt.wantIKEPRF)
			}

			childProposals := childSAProposals(tt.cfg, 0x01020304)
			if len(childProposals) != tt.wantChild {
				t.Fatalf("len(childProposals) = %d, want %d", len(childProposals), tt.wantChild)
			}
			if got := proposalKeyLength(t, childProposals[0]); got != tt.wantChildKeyLen {
				t.Fatalf("child key len = %d, want %d", got, tt.wantChildKeyLen)
			}
			if got := proposalTransformID(childProposals[0], transformTypeINTEG); got != tt.wantChildInteg {
				t.Fatalf("child integ = %d, want %d", got, tt.wantChildInteg)
			}
		})
	}
}

func TestExchangeIKESAInitCookieHandling(t *testing.T) {
	tests := []struct {
		name        string
		readResults []readResult
		check       func(t *testing.T, conn *fakePacketConn, err error)
	}{
		{
			name: "cookie response retries with cookie payload first",
			readResults: []readResult{
				{
					data: mustIKEPacket(t, ike.IKEHeader{
						InitiatorSPI: 0x0102030405060708,
						Version:      ike.Version20,
						ExchangeType: ike.ExchangeTypeIKESAInit,
						Flags:        ike.FlagResponse,
						MessageID:    0,
					}, []ike.Payload{
						&ike.NotifyPayload{
							NotifyType: notifyTypeCookie,
							Data:       []byte{0x01, 0x02, 0x03, 0x04},
						},
					}),
					addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500},
				},
				{
					data: mustIKEPacket(t, ike.IKEHeader{
						InitiatorSPI: 0x0102030405060708,
						ResponderSPI: 0x1112131415161718,
						Version:      ike.Version20,
						ExchangeType: ike.ExchangeTypeIKESAInit,
						Flags:        ike.FlagResponse,
						MessageID:    0,
					}, nil),
					addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500},
				},
			},
			check: func(t *testing.T, conn *fakePacketConn, err error) {
				t.Helper()
				if err == nil || !strings.Contains(err.Error(), "required payload is missing") {
					t.Fatalf("exchangeIKESAInit() error = %v, want missing payload error after retry", err)
				}
				if len(conn.writes) != 2 {
					t.Fatalf("writes = %d, want 2", len(conn.writes))
				}
				first := mustUnmarshalIKEPacket(t, conn.writes[0])
				if _, ok := first.Payloads[0].(*ike.NotifyPayload); ok {
					t.Fatal("first request unexpectedly included COOKIE notify")
				}
				second := mustUnmarshalIKEPacket(t, conn.writes[1])
				notify, ok := second.Payloads[0].(*ike.NotifyPayload)
				if !ok {
					t.Fatalf("second request payload[0] = %T, want *ike.NotifyPayload", second.Payloads[0])
				}
				if notify.NotifyType != notifyTypeCookie {
					t.Fatalf("second request cookie notify type = %d, want %d", notify.NotifyType, notifyTypeCookie)
				}
				if got := string(notify.Data); got != string([]byte{0x01, 0x02, 0x03, 0x04}) {
					t.Fatalf("second request cookie = %x, want 01020304", notify.Data)
				}
			},
		},
		{
			name: "invalid cookie length fails fast",
			readResults: []readResult{
				{
					data: mustIKEPacket(t, ike.IKEHeader{
						InitiatorSPI: 0x0102030405060708,
						Version:      ike.Version20,
						ExchangeType: ike.ExchangeTypeIKESAInit,
						Flags:        ike.FlagResponse,
						MessageID:    0,
					}, []ike.Payload{
						&ike.NotifyPayload{
							NotifyType: notifyTypeCookie,
							Data:       make([]byte, 65),
						},
					}),
					addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500},
				},
			},
			check: func(t *testing.T, conn *fakePacketConn, err error) {
				t.Helper()
				if err == nil || !strings.Contains(err.Error(), "invalid COOKIE length 65") {
					t.Fatalf("exchangeIKESAInit() error = %v, want invalid COOKIE length", err)
				}
				if len(conn.writes) != 1 {
					t.Fatalf("writes = %d, want 1", len(conn.writes))
				}
			},
		},
		{
			name: "generic ike_sa_init error notify is surfaced",
			readResults: []readResult{
				{
					data: mustIKEPacket(t, ike.IKEHeader{
						InitiatorSPI: 0x0102030405060708,
						Version:      ike.Version20,
						ExchangeType: ike.ExchangeTypeIKESAInit,
						Flags:        ike.FlagResponse,
						MessageID:    0,
					}, []ike.Payload{
						&ike.NotifyPayload{NotifyType: 14},
					}),
					addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500},
				},
			},
			check: func(t *testing.T, conn *fakePacketConn, err error) {
				t.Helper()
				if err == nil || !strings.Contains(err.Error(), "NO_PROPOSAL_CHOSEN (14)") {
					t.Fatalf("exchangeIKESAInit() error = %v, want NO_PROPOSAL_CHOSEN", err)
				}
				if len(conn.writes) != 1 {
					t.Fatalf("writes = %d, want 1", len(conn.writes))
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{
				local:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
				readResults: tt.readResults,
			}
			session := mustDialSession(t, conn)
			state, finish, err := session.prepareConnect("356789012345678", sessionTestCard{})
			if err != nil {
				t.Fatalf("prepareConnect() error = %v", err)
			}
			defer finish()
			state.initiatorSPI = 0x0102030405060708
			state.saInit.InitiatorSPI = state.initiatorSPI
			err = session.exchangeIKESAInit(context.Background(), state)
			tt.check(t, conn, err)
		})
	}
}

func TestMatchesIKEMessageRequiresResponseContext(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
	expected := ikeResponseMatch{
		peer:         peer,
		initiatorSPI: 0x0102030405060708,
		responderSPI: 0x1112131415161718,
		exchangeType: exchangeTypeIKEAuth,
		messageID:    2,
	}
	packet := func(header ike.IKEHeader) []byte {
		return mustIKEPacket(t, header, nil)
	}
	validHeader := ike.IKEHeader{
		InitiatorSPI: expected.initiatorSPI,
		ResponderSPI: expected.responderSPI,
		Version:      ike.Version20,
		ExchangeType: expected.exchangeType,
		Flags:        ike.FlagResponse,
		MessageID:    expected.messageID,
	}
	tests := []struct {
		name   string
		header ike.IKEHeader
		peer   *net.UDPAddr
		want   bool
	}{
		{name: "valid response", header: validHeader, peer: peer, want: true},
		{name: "same id request is rejected", header: func() ike.IKEHeader { h := validHeader; h.Flags = ike.FlagInitiator; return h }(), peer: peer},
		{name: "initiator response is rejected", header: func() ike.IKEHeader { h := validHeader; h.Flags = ike.FlagResponse | ike.FlagInitiator; return h }(), peer: peer},
		{name: "wrong exchange is rejected", header: func() ike.IKEHeader { h := validHeader; h.ExchangeType = exchangeTypeInformational; return h }(), peer: peer},
		{name: "wrong responder spi is rejected", header: func() ike.IKEHeader { h := validHeader; h.ResponderSPI++; return h }(), peer: peer},
		{name: "wrong peer is rejected", header: validHeader, peer: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 4500}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesIKEMessage(packet(tt.header), tt.peer, expected); got != tt.want {
				t.Fatalf("matchesIKEMessage() = %t, want %t", got, tt.want)
			}
		})
	}
}

func proposalTransformID(proposal ike.Proposal, transformType byte) uint16 {
	for _, transform := range proposal.Transforms {
		if transform.TransformType == transformType {
			return transform.ID
		}
	}
	return 0
}

func proposalKeyLength(t *testing.T, proposal ike.Proposal) uint16 {
	t.Helper()
	for _, transform := range proposal.Transforms {
		if transform.TransformType != transformTypeENCR {
			continue
		}
		for _, attr := range transform.Attributes {
			if attr.Type != transformAttrKeyLength {
				continue
			}
			value, ok := attr.Uint16()
			if !ok {
				t.Fatal("key length attr is not TV encoded")
			}
			return value
		}
	}
	t.Fatal("key length attr is missing")
	return 0
}

func mustIKEPacket(t *testing.T, header ike.IKEHeader, payloads []ike.Payload) []byte {
	t.Helper()
	wire, err := (ike.IKEPacket{Header: header, Payloads: payloads}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	return wire
}

func mustUnmarshalIKEPacket(t *testing.T, wire []byte) ike.IKEPacket {
	t.Helper()
	var packet ike.IKEPacket
	if err := packet.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	return packet
}
