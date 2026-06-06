package tunnel

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

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

func TestDefaultIKESAInitPayloadsAdvertisesFragmentation(t *testing.T) {
	crypto := testIKECrypto()
	crypto.initiatorSPI = 0x0102030405060708
	local := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 40000}
	remote := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 500}

	payloads := defaultIKESAInitPayloads(handshake.Config{}, crypto, local, remote)

	if !hasNotifyPayload(payloads, notifyTypeIKEV2FragmentationSupported) {
		t.Fatalf("defaultIKESAInitPayloads() missing IKEV2_FRAGMENTATION_SUPPORTED notify")
	}
}

func TestApplyIKESAInitResponseRecordsFragmentationSupport(t *testing.T) {
	tests := []struct {
		name       string
		notify     bool
		wantEnable bool
	}{
		{name: "peer supports fragmentation", notify: true, wantEnable: true},
		{name: "peer omits fragmentation notify"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, response, request, responseRaw, local, remote := testIKESAInitResponse(t, tt.notify)

			err := state.applyIKESAInitResponse(response, request, responseRaw, local, remote)

			if err != nil {
				t.Fatalf("applyIKESAInitResponse() error = %v", err)
			}
			if state.ikeFragmentationSupported != tt.wantEnable {
				t.Fatalf("ikeFragmentationSupported = %t, want %t", state.ikeFragmentationSupported, tt.wantEnable)
			}
			if state.useNATT {
				t.Fatal("useNATT = true, want false when NAT is not detected and peer is on port 500")
			}
		})
	}
}

func TestConnectIKEPeerUsesNATTOnlyWhenSelected(t *testing.T) {
	session := &Session{
		outerRemote: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 500},
		outerNAT:    &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 4500},
	}
	tests := []struct {
		name     string
		state    *connectState
		wantPort int
		wantNATT bool
	}{
		{name: "nil state uses ike port", wantPort: 500},
		{name: "no natt uses ike port", state: &connectState{}, wantPort: 500},
		{name: "natt uses natt port", state: &connectState{useNATT: true}, wantPort: 4500, wantNATT: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer, useNATT := session.connectIKEPeer(tt.state)
			if peer.Port != tt.wantPort {
				t.Fatalf("peer port = %d, want %d", peer.Port, tt.wantPort)
			}
			if useNATT != tt.wantNATT {
				t.Fatalf("useNATT = %t, want %t", useNATT, tt.wantNATT)
			}
		})
	}
}

func TestTunnelAddressesAcceptsIPv6Subnet(t *testing.T) {
	subnetValue := append(net.ParseIP("2001:db8::").To16(), 64)
	pcscf := net.ParseIP("2001:db8::100").To16()
	addresses := tunnelAddresses([]ike.Attribute{
		ike.NewTLVAttribute(configAttrInternalIPv6Subnet, subnetValue),
		ike.NewTLVAttribute(configAttrPCSCFIPv6Address, pcscf),
	}, 0, 0)
	if !addresses.internalIPv6.Equal(net.ParseIP("2001:db8::")) {
		t.Fatalf("internalIPv6 = %s, want 2001:db8::", addresses.internalIPv6)
	}
	if len(addresses.pcscfIPv6) != 1 || !addresses.pcscfIPv6[0].Equal(net.ParseIP("2001:db8::100")) {
		t.Fatalf("pcscfIPv6 = %v, want [2001:db8::100]", addresses.pcscfIPv6)
	}
}

func TestTunnelAddressesAcceptsConfiguredPCSCFAttributes(t *testing.T) {
	internalIPv6 := append(net.ParseIP("2001:db8::1").To16(), 64)

	tests := []struct {
		name          string
		attrs         []ike.Attribute
		ipv4Attr      uint16
		ipv6Attr      uint16
		wantInternal4 net.IP
		wantInternal6 net.IP
		wantPCSCF4    []net.IP
		wantPCSCF6    []net.IP
	}{
		{
			name:          "separate ipv4 attribute",
			attrs:         []ike.Attribute{ike.NewTLVAttribute(configAttrInternalIPv4Address, net.IPv4(10, 1, 2, 3).To4()), ike.NewTLVAttribute(16384, net.IPv4(10, 9, 8, 7).To4())},
			ipv4Attr:      16384,
			ipv6Attr:      16386,
			wantInternal4: net.IPv4(10, 1, 2, 3).To4(),
			wantPCSCF4:    []net.IP{net.IPv4(10, 9, 8, 7).To4()},
		},
		{
			name:          "shared attribute ipv6 value",
			attrs:         []ike.Attribute{ike.NewTLVAttribute(configAttrInternalIPv6Address, internalIPv6), ike.NewTLVAttribute(16384, net.ParseIP("2001:db8::100").To16())},
			ipv4Attr:      16384,
			ipv6Attr:      16384,
			wantInternal6: net.ParseIP("2001:db8::1").To16(),
			wantPCSCF6:    []net.IP{net.ParseIP("2001:db8::100").To16()},
		},
		{
			name:          "shared attribute ipv4 value",
			attrs:         []ike.Attribute{ike.NewTLVAttribute(configAttrInternalIPv4Address, net.IPv4(10, 1, 2, 3).To4()), ike.NewTLVAttribute(16384, net.IPv4(10, 9, 8, 7).To4())},
			ipv4Attr:      16384,
			ipv6Attr:      16384,
			wantInternal4: net.IPv4(10, 1, 2, 3).To4(),
			wantPCSCF4:    []net.IP{net.IPv4(10, 9, 8, 7).To4()},
		},
		{
			name: "multiple ipv4 attributes",
			attrs: []ike.Attribute{
				ike.NewTLVAttribute(configAttrInternalIPv4Address, net.IPv4(10, 1, 2, 3).To4()),
				ike.NewTLVAttribute(16384, net.IPv4(10, 9, 8, 7).To4()),
				ike.NewTLVAttribute(16384, net.IPv4(10, 9, 8, 8).To4()),
				ike.NewTLVAttribute(configAttrPCSCFIPv4Address, net.IPv4(10, 9, 8, 7).To4()),
			},
			ipv4Attr:      16384,
			ipv6Attr:      16386,
			wantInternal4: net.IPv4(10, 1, 2, 3).To4(),
			wantPCSCF4: []net.IP{
				net.IPv4(10, 9, 8, 7).To4(),
				net.IPv4(10, 9, 8, 8).To4(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addresses := tunnelAddresses(tt.attrs, tt.ipv4Attr, tt.ipv6Attr)
			if !ipEqual(addresses.internalIPv4, tt.wantInternal4) {
				t.Fatalf("internalIPv4 = %s, want %s", addresses.internalIPv4, tt.wantInternal4)
			}
			if !ipEqual(addresses.internalIPv6, tt.wantInternal6) {
				t.Fatalf("internalIPv6 = %s, want %s", addresses.internalIPv6, tt.wantInternal6)
			}
			if !ipListEqual(addresses.pcscfIPv4, tt.wantPCSCF4) {
				t.Fatalf("pcscfIPv4 = %v, want %v", addresses.pcscfIPv4, tt.wantPCSCF4)
			}
			if !ipListEqual(addresses.pcscfIPv6, tt.wantPCSCF6) {
				t.Fatalf("pcscfIPv6 = %v, want %v", addresses.pcscfIPv6, tt.wantPCSCF6)
			}
		})
	}
}

func TestApplyTunnelAddressesHandlesInvalidAddressLengths(t *testing.T) {
	tests := []struct {
		name         string
		attrs        []ike.Attribute
		wantErr      string
		wantInner    net.IP
		wantPCSCFNil bool
	}{
		{
			name: "internal ipv4 with trailing byte",
			attrs: []ike.Attribute{
				ike.NewTLVAttribute(configAttrInternalIPv4Address, []byte{10, 1, 2, 3, 4}),
				ike.NewTLVAttribute(configAttrPCSCFIPv4Address, net.IPv4(10, 9, 8, 7).To4()),
			},
			wantErr: "internal ip is missing",
		},
		{
			name: "internal ipv6 missing prefix length",
			attrs: []ike.Attribute{
				ike.NewTLVAttribute(configAttrInternalIPv6Address, net.ParseIP("2001:db8::1").To16()),
				ike.NewTLVAttribute(configAttrPCSCFIPv6Address, net.ParseIP("2001:db8::100").To16()),
			},
			wantErr: "internal ip is missing",
		},
		{
			name: "p-cscf ipv4 with trailing byte",
			attrs: []ike.Attribute{
				ike.NewTLVAttribute(configAttrInternalIPv4Address, net.IPv4(10, 1, 2, 3).To4()),
				ike.NewTLVAttribute(configAttrPCSCFIPv4Address, []byte{10, 9, 8, 7, 6}),
			},
			wantInner:    net.IPv4(10, 1, 2, 3).To4(),
			wantPCSCFNil: true,
		},
		{
			name: "p-cscf ipv6 with trailing byte",
			attrs: []ike.Attribute{
				ike.NewTLVAttribute(configAttrInternalIPv6Address, append(net.ParseIP("2001:db8::1").To16(), 64)),
				ike.NewTLVAttribute(configAttrPCSCFIPv6Address, append(net.ParseIP("2001:db8::100").To16(), 0)),
			},
			wantInner:    net.ParseIP("2001:db8::1").To16(),
			wantPCSCFNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tunnel := Info{}
			err := applyTunnelAddresses(&tunnel, ike.ConfigPayload{Attributes: tt.attrs}, handshake.Config{})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("applyTunnelAddresses() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("applyTunnelAddresses() error = %v", err)
			}
			if !ipEqual(tunnel.InnerIP, tt.wantInner) {
				t.Fatalf("InnerIP = %s, want %s", tunnel.InnerIP, tt.wantInner)
			}
			if tt.wantPCSCFNil && (tunnel.PCSCFIP != nil || len(tunnel.PCSCFIPs) != 0) {
				t.Fatalf("P-CSCF = %s/%v, want empty", tunnel.PCSCFIP, tunnel.PCSCFIPs)
			}
		})
	}
}

func TestApplyTunnelAddressesAllowsMissingPCSCF(t *testing.T) {
	tests := []struct {
		name      string
		attrs     []ike.Attribute
		wantInner net.IP
	}{
		{
			name: "ipv4 internal only",
			attrs: []ike.Attribute{
				ike.NewTLVAttribute(configAttrInternalIPv4Address, net.IPv4(10, 1, 2, 3).To4()),
			},
			wantInner: net.IPv4(10, 1, 2, 3).To4(),
		},
		{
			name: "ipv6 internal only",
			attrs: []ike.Attribute{
				ike.NewTLVAttribute(configAttrInternalIPv6Address, append(net.ParseIP("2001:db8::1").To16(), 64)),
			},
			wantInner: net.ParseIP("2001:db8::1").To16(),
		},
		{
			name: "ipv6 internal ignores ipv4 pcscf",
			attrs: []ike.Attribute{
				ike.NewTLVAttribute(configAttrInternalIPv6Address, append(net.ParseIP("2001:db8::1").To16(), 64)),
				ike.NewTLVAttribute(configAttrPCSCFIPv4Address, net.IPv4(10, 9, 8, 7).To4()),
			},
			wantInner: net.ParseIP("2001:db8::1").To16(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tunnel := Info{}
			err := applyTunnelAddresses(&tunnel, ike.ConfigPayload{Attributes: tt.attrs}, handshake.Config{})
			if err != nil {
				t.Fatalf("applyTunnelAddresses() error = %v", err)
			}
			if !ipEqual(tunnel.InnerIP, tt.wantInner) {
				t.Fatalf("InnerIP = %s, want %s", tunnel.InnerIP, tt.wantInner)
			}
			if tunnel.PCSCFIP != nil || len(tunnel.PCSCFIPs) != 0 {
				t.Fatalf("P-CSCF = %s/%v, want empty", tunnel.PCSCFIP, tunnel.PCSCFIPs)
			}
		})
	}
}

func TestApplyTunnelAddressesKeepsSameFamilyPCSCFList(t *testing.T) {
	tunnel := Info{}
	config := &ike.ConfigPayload{Attributes: []ike.Attribute{
		ike.NewTLVAttribute(configAttrInternalIPv4Address, net.IPv4(10, 1, 2, 3).To4()),
		ike.NewTLVAttribute(configAttrPCSCFIPv4Address, net.IPv4(10, 9, 8, 7).To4()),
		ike.NewTLVAttribute(configAttrPCSCFIPv4Address, net.IPv4(10, 9, 8, 8).To4()),
	}}

	if err := applyTunnelAddresses(&tunnel, *config, handshake.Config{}); err != nil {
		t.Fatalf("applyTunnelAddresses() error = %v", err)
	}
	if !tunnel.PCSCFIP.Equal(net.IPv4(10, 9, 8, 7)) {
		t.Fatalf("PCSCFIP = %s, want first P-CSCF", tunnel.PCSCFIP)
	}
	want := []net.IP{net.IPv4(10, 9, 8, 7).To4(), net.IPv4(10, 9, 8, 8).To4()}
	if !ipListEqual(tunnel.PCSCFIPs, want) {
		t.Fatalf("PCSCFIPs = %v, want %v", tunnel.PCSCFIPs, want)
	}
}

func ipEqual(got, want net.IP) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	return got.Equal(want)
}

func ipListEqual(got, want []net.IP) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if !ipEqual(got[i], want[i]) {
			return false
		}
	}
	return true
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

func TestDefaultIKEAuthInitPayloadsUsesAPNAsResponderID(t *testing.T) {
	tests := []struct {
		name string
		cfg  handshake.Config
		want string
	}{
		{name: "default ims apn", cfg: handshake.Config{}, want: DefaultAPN},
		{name: "configured apn", cfg: handshake.Config{APN: "internet"}, want: "internet"},
		{name: "trimmed configured apn", cfg: handshake.Config{APN: " ims.mnc001.mcc001.gprs "}, want: "ims.mnc001.mcc001.gprs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads, err := defaultIKEAuthInitPayloads(tt.cfg, "001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org", 0x01020304)
			if err != nil {
				t.Fatalf("defaultIKEAuthInitPayloads() error = %v", err)
			}
			idr, ok := payloads[1].(*ike.IDPayload)
			if !ok {
				t.Fatalf("payload[1] = %T, want *ike.IDPayload", payloads[1])
			}
			if got := string(idr.Data); got != tt.want {
				t.Fatalf("IDr = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDefaultIKEAuthInitPayloadsAdvertisesPCSCFRestoration(t *testing.T) {
	payloads, err := defaultIKEAuthInitPayloads(handshake.Config{
		PCSCFRestoration: true,
	}, "001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org", 0x01020304)
	if err != nil {
		t.Fatalf("defaultIKEAuthInitPayloads() error = %v", err)
	}
	if !hasNotifyPayload(payloads, notifyTypePCSCFReselectionSupport) {
		t.Fatalf("payloads = %v, want P-CSCF_RESELECTION_SUPPORT notify", payloads)
	}
}

func TestDefaultIKEAuthInitPayloadsAdvertisesN1ModeCapability(t *testing.T) {
	payloads, err := defaultIKEAuthInitPayloads(handshake.Config{
		PDUSessionID: 0x01,
	}, "001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org", 0x01020304)
	if err != nil {
		t.Fatalf("defaultIKEAuthInitPayloads() error = %v", err)
	}
	notify := ike.FindNotifyPayload(payloads, notifyTypeN1ModeCapability)
	if notify == nil {
		t.Fatalf("payloads = %v, want N1_MODE_CAPABILITY notify", payloads)
	}
	if string(notify.Data) != string([]byte{0x01, 0x01}) {
		t.Fatalf("N1_MODE_CAPABILITY data = % X, want 01 01", notify.Data)
	}
}

func TestDefaultIKEAuthInitPayloadsRejectsEmptyIdentity(t *testing.T) {
	tests := []struct {
		name     string
		identity string
		wantErr  string
	}{
		{name: "empty identity", wantErr: "identity is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := defaultIKEAuthInitPayloads(handshake.Config{}, tt.identity, 0x01020304)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("defaultIKEAuthInitPayloads() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestApplyN1ModeInfoStoresNegotiatedSliceData(t *testing.T) {
	tunnel := Info{}
	payloads := []ike.Payload{
		&ike.NotifyPayload{NotifyType: notifyTypeN1ModeInformation, Data: []byte{0x04, 0x11, 0x22, 0x33, 0x44}},
		&ike.NotifyPayload{NotifyType: notifyTypeN1ModeSNSSAIPlmnID, Data: []byte{0x03, 0x13, 0x10, 0x01}},
	}
	if err := applyN1ModeInfo(&tunnel, payloads, handshake.Config{PDUSessionID: 0x01}); err != nil {
		t.Fatalf("applyN1ModeInfo() error = %v", err)
	}
	if tunnel.PDUSessionID != 0x01 {
		t.Fatalf("PDUSessionID = %#x, want 0x01", tunnel.PDUSessionID)
	}
	if string(tunnel.SNSSAI) != string([]byte{0x11, 0x22, 0x33, 0x44}) {
		t.Fatalf("SNSSAI = % X, want 11 22 33 44", tunnel.SNSSAI)
	}
	if string(tunnel.SNSSAIPlmnID) != string([]byte{0x13, 0x10, 0x01}) {
		t.Fatalf("SNSSAIPlmnID = % X, want 13 10 01", tunnel.SNSSAIPlmnID)
	}
}

func TestApplyN1ModeInfoIgnoresNetworkDataWhenNotConfigured(t *testing.T) {
	tunnel := Info{}
	payloads := []ike.Payload{
		&ike.NotifyPayload{NotifyType: notifyTypeN1ModeInformation, Data: []byte{0x05, 0x11, 0x22, 0x33, 0x44}},
	}
	if err := applyN1ModeInfo(&tunnel, payloads, handshake.Config{}); err != nil {
		t.Fatalf("applyN1ModeInfo() error = %v", err)
	}
	if tunnel.PDUSessionID != 0 || len(tunnel.SNSSAI) != 0 {
		t.Fatalf("applyN1ModeInfo() = %+v, want no N1 data", tunnel)
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

func TestConnectStateSessionLivenessTimeout(t *testing.T) {
	tests := []struct {
		name          string
		finalPayloads []ike.Payload
		cfgTimeout    time.Duration
		want          time.Duration
	}{
		{
			name: "epdg config wins over local config",
			finalPayloads: []ike.Payload{&ike.ConfigPayload{Attributes: []ike.Attribute{
				ike.NewTLVAttribute(configAttrTimeoutPeriodForLivenessCheck, []byte{0x00, 0x00, 0x01, 0x2c}),
			}}},
			cfgTimeout: 90 * time.Second,
			want:       300 * time.Second,
		},
		{
			name:       "local config used when epdg omits liveness attribute",
			cfgTimeout: 90 * time.Second,
			want:       90 * time.Second,
		},
		{
			name: "local config used when epdg liveness attribute is invalid",
			finalPayloads: []ike.Payload{&ike.ConfigPayload{Attributes: []ike.Attribute{
				ike.NewTLVAttribute(configAttrTimeoutPeriodForLivenessCheck, []byte{0x00, 0x01}),
			}}},
			cfgTimeout: 90 * time.Second,
			want:       90 * time.Second,
		},
		{
			name: "default when no peer or local config is present",
			want: defaultLivenessTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &connectState{
				input:         handshake.ConnectInput{Config: handshake.Config{LivenessTimeout: tt.cfgTimeout}},
				finalPayloads: tt.finalPayloads,
			}
			if got := state.sessionLivenessTimeout(); got != tt.want {
				t.Fatalf("sessionLivenessTimeout() = %s, want %s", got, tt.want)
			}
		})
	}
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

func TestNegotiatedIKESAInitProposalValidation(t *testing.T) {
	const dhGroup = transformDH2048MODP
	validProposal := func() ike.Proposal {
		return ike.Proposal{
			ProtocolID: proposalProtocolIKE,
			Transforms: []ike.Transform{
				aesCBCTransform(128),
				{TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA256},
				{TransformType: transformTypePRF, ID: transformPRFHMACSHA1},
				{TransformType: transformTypeDH, ID: dhGroup},
			},
		}
	}
	payloads := func(proposals ...ike.Proposal) []ike.Payload {
		return []ike.Payload{
			&ike.SecurityAssociationPayload{Proposals: proposals},
			&ike.NoncePayload{Data: make([]byte, ikeNonceMinLen)},
			&ike.KeyExchangePayload{DHGroup: dhGroup, Data: []byte{0x01}},
		}
	}
	tests := []struct {
		name      string
		proposals []ike.Proposal
		wantErr   string
	}{
		{
			name:      "valid",
			proposals: []ike.Proposal{validProposal()},
		},
		{
			name:      "multiple negotiated proposals",
			proposals: []ike.Proposal{validProposal(), validProposal()},
			wantErr:   "negotiated proposal count 2",
		},
		{
			name: "esp proposal",
			proposals: []ike.Proposal{
				func() ike.Proposal {
					proposal := validProposal()
					proposal.ProtocolID = proposalProtocolESP
					return proposal
				}(),
			},
			wantErr: "invalid protocol id",
		},
		{
			name: "initial ike spi included",
			proposals: []ike.Proposal{
				func() ike.Proposal {
					proposal := validProposal()
					proposal.SPI = []byte{0, 1, 2, 3, 4, 5, 6, 7}
					return proposal
				}(),
			},
			wantErr: "invalid negotiated ike spi length 8",
		},
		{
			name: "dh transform missing",
			proposals: []ike.Proposal{
				func() ike.Proposal {
					proposal := validProposal()
					proposal.Transforms = proposal.Transforms[:3]
					return proposal
				}(),
			},
			wantErr: "dh group 0 does not match",
		},
		{
			name: "duplicate prf transform",
			proposals: []ike.Proposal{
				func() ike.Proposal {
					proposal := validProposal()
					proposal.Transforms = append(proposal.Transforms, ike.Transform{TransformType: transformTypePRF, ID: transformPRFHMACSHA256})
					return proposal
				}(),
			},
			wantErr: "duplicate prf transform",
		},
		{
			name: "unsupported transform",
			proposals: []ike.Proposal{
				func() ike.Proposal {
					proposal := validProposal()
					proposal.Transforms = append(proposal.Transforms, ike.Transform{TransformType: transformTypeESN, ID: transformESNNoESN})
					return proposal
				}(),
			},
			wantErr: "unsupported transform type",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := negotiatedIKESAFromPayloads(payloads(tt.proposals...), dhGroup, nil)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("negotiatedIKESAFromPayloads() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("negotiatedIKESAFromPayloads() error = %v", err)
			}
		})
	}
}

func TestNegotiatedIKESAInitValidatesOfferedProposal(t *testing.T) {
	const dhGroup = transformDH2048MODP
	requestProposals := ikeSAProposals(handshake.Config{
		IKEEncryptionKeyLens: []uint16{128},
		IKEIntegrity:         []uint16{transformINTEGHMACSHA256},
		IKEPRF:               []uint16{transformPRFHMACSHA1},
	}, dhGroup)

	tests := []struct {
		name    string
		mutate  func(*ike.Proposal)
		wantErr string
	}{
		{
			name: "valid selected transform set",
		},
		{
			name: "unrequested prf",
			mutate: func(proposal *ike.Proposal) {
				for i := range proposal.Transforms {
					if proposal.Transforms[i].TransformType == transformTypePRF {
						proposal.Transforms[i].ID = transformPRFHMACSHA256
					}
				}
			},
			wantErr: "was not requested",
		},
		{
			name: "unrequested key length",
			mutate: func(proposal *ike.Proposal) {
				for i := range proposal.Transforms {
					if proposal.Transforms[i].TransformType == transformTypeENCR {
						proposal.Transforms[i].Attributes = []ike.Attribute{ike.NewTVAttribute(transformAttrKeyLength, 256)}
					}
				}
			},
			wantErr: "was not requested",
		},
		{
			name: "invalid proposal number",
			mutate: func(proposal *ike.Proposal) {
				proposal.Number = 2
			},
			wantErr: "invalid negotiated proposal number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := requestProposals[0]
			response.Transforms = append([]ike.Transform(nil), response.Transforms...)
			for i := range response.Transforms {
				response.Transforms[i].Attributes = append([]ike.Attribute(nil), response.Transforms[i].Attributes...)
			}
			if tt.mutate != nil {
				tt.mutate(&response)
			}
			payloads := []ike.Payload{
				&ike.SecurityAssociationPayload{Proposals: []ike.Proposal{response}},
				&ike.NoncePayload{Data: make([]byte, ikeNonceMinLen)},
				&ike.KeyExchangePayload{DHGroup: dhGroup, Data: []byte{0x01}},
			}
			_, _, _, err := negotiatedIKESAFromPayloads(payloads, dhGroup, requestProposals)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("negotiatedIKESAFromPayloads() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("negotiatedIKESAFromPayloads() error = %v", err)
			}
		})
	}
}

func TestChildSAConfigValidatesNegotiatedProposal(t *testing.T) {
	requestProposals := childSAProposals(handshake.Config{}, 0x01020304)
	validProposal := func() ike.Proposal {
		proposal := requestProposals[0]
		proposal.SPI = append([]byte(nil), proposal.SPI...)
		proposal.Transforms = append([]ike.Transform(nil), proposal.Transforms...)
		for i := range proposal.Transforms {
			proposal.Transforms[i].Attributes = append([]ike.Attribute(nil), proposal.Transforms[i].Attributes...)
		}
		return proposal
	}
	payloads := func(proposals ...ike.Proposal) []ike.Payload {
		return []ike.Payload{
			&ike.ConfigPayload{ConfigType: configTypeReply},
			&ike.SecurityAssociationPayload{Proposals: proposals},
			&ike.TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: ike.TrafficSelectorsAny()},
			&ike.TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: ike.TrafficSelectorsAny()},
		}
	}
	tests := []struct {
		name    string
		payload []ike.Payload
		wantErr string
	}{
		{
			name:    "valid",
			payload: payloads(validProposal()),
		},
		{
			name:    "missing child sa",
			payload: []ike.Payload{&ike.ConfigPayload{ConfigType: configTypeReply}},
			wantErr: "missing child sa or configuration",
		},
		{
			name: "wrong configuration type",
			payload: []ike.Payload{
				&ike.ConfigPayload{ConfigType: configTypeRequest},
				&ike.SecurityAssociationPayload{Proposals: []ike.Proposal{validProposal()}},
				&ike.TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: ike.TrafficSelectorsAny()},
				&ike.TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: ike.TrafficSelectorsAny()},
			},
			wantErr: "unexpected configuration type 1",
		},
		{
			name: "missing tsi",
			payload: []ike.Payload{
				&ike.ConfigPayload{ConfigType: configTypeReply},
				&ike.SecurityAssociationPayload{Proposals: []ike.Proposal{validProposal()}},
				&ike.TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: ike.TrafficSelectorsAny()},
			},
			wantErr: "missing traffic selectors",
		},
		{
			name: "missing tsr",
			payload: []ike.Payload{
				&ike.ConfigPayload{ConfigType: configTypeReply},
				&ike.SecurityAssociationPayload{Proposals: []ike.Proposal{validProposal()}},
				&ike.TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: ike.TrafficSelectorsAny()},
			},
			wantErr: "missing traffic selectors",
		},
		{
			name:    "multiple negotiated proposals",
			payload: payloads(validProposal(), validProposal()),
			wantErr: "negotiated proposal count 2",
		},
		{
			name: "ike proposal",
			payload: payloads(
				func() ike.Proposal {
					proposal := validProposal()
					proposal.ProtocolID = proposalProtocolIKE
					return proposal
				}(),
			),
			wantErr: "negotiated protocol id",
		},
		{
			name: "missing esn",
			payload: payloads(
				func() ike.Proposal {
					proposal := validProposal()
					proposal.Transforms = proposal.Transforms[:2]
					return proposal
				}(),
			),
			wantErr: "negotiated esp transform is incomplete",
		},
		{
			name: "unsupported esn",
			payload: payloads(
				func() ike.Proposal {
					proposal := validProposal()
					proposal.Transforms[len(proposal.Transforms)-1].ID = 1
					return proposal
				}(),
			),
			wantErr: "was not requested",
		},
		{
			name: "duplicate integrity",
			payload: payloads(
				func() ike.Proposal {
					proposal := validProposal()
					proposal.Transforms = append(proposal.Transforms, ike.Transform{TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA196})
					return proposal
				}(),
			),
			wantErr: "was not requested",
		},
		{
			name: "prf is invalid for esp",
			payload: payloads(
				func() ike.Proposal {
					proposal := validProposal()
					proposal.Transforms = append(proposal.Transforms, ike.Transform{TransformType: transformTypePRF, ID: transformPRFHMACSHA1})
					return proposal
				}(),
			),
			wantErr: "was not requested",
		},
		{
			name: "unrequested encryption key length",
			payload: payloads(
				func() ike.Proposal {
					proposal := validProposal()
					proposal.Transforms[0].Attributes = []ike.Attribute{ike.NewTVAttribute(transformAttrKeyLength, 192)}
					return proposal
				}(),
			),
			wantErr: "was not requested",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, err := childSAConfig(tt.payload, requestProposals)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("childSAConfig() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("childSAConfig() error = %v", err)
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
						Version:      ikeVersion20,
						ExchangeType: exchangeTypeIKESAInit,
						Flags:        flagResponse,
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
						Version:      ikeVersion20,
						ExchangeType: exchangeTypeIKESAInit,
						Flags:        flagResponse,
						MessageID:    0,
					}, []ike.Payload{
						&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionSourceIP},
					}),
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
				if !hasNonESPMarker(conn.writes[0]) {
					t.Fatal("first request is missing UDP-encapsulated Non-ESP marker")
				}
				first := mustUnmarshalIKEPacket(t, conn.writes[0])
				if _, ok := first.Payloads[0].(*ike.NotifyPayload); ok {
					t.Fatal("first request unexpectedly included COOKIE notify")
				}
				if !hasNonESPMarker(conn.writes[1]) {
					t.Fatal("second request is missing UDP-encapsulated Non-ESP marker")
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
						Version:      ikeVersion20,
						ExchangeType: exchangeTypeIKESAInit,
						Flags:        flagResponse,
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
						Version:      ikeVersion20,
						ExchangeType: exchangeTypeIKESAInit,
						Flags:        flagResponse,
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
		{
			name: "invalid ke group outside configured policy fails",
			readResults: []readResult{
				{
					data: mustIKEPacket(t, ike.IKEHeader{
						InitiatorSPI: 0x0102030405060708,
						Version:      ikeVersion20,
						ExchangeType: exchangeTypeIKESAInit,
						Flags:        flagResponse,
						MessageID:    0,
					}, []ike.Payload{
						&ike.NotifyPayload{NotifyType: notifyTypeInvalidKEPayload, Data: []byte{0x00, byte(transformDH1024MODP)}},
					}),
					addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500},
				},
			},
			check: func(t *testing.T, conn *fakePacketConn, err error) {
				t.Helper()
				if err == nil || !strings.Contains(err.Error(), "dh group 2 was not requested") {
					t.Fatalf("exchangeIKESAInit() error = %v, want unrequested dh group", err)
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

func TestIKESAInitNATDetection(t *testing.T) {
	initiatorSPI := uint64(0x0102030405060708)
	responderSPI := uint64(0x1112131415161718)
	local := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 40000}
	remote := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 500}
	localHash := natDetectionHash(initiatorSPI, responderSPI, local)
	remoteHash := natDetectionHash(initiatorSPI, responderSPI, remote)

	tests := []struct {
		name          string
		payloads      []ike.Payload
		wantSupported bool
		wantDetected  bool
		wantErr       string
	}{
		{
			name: "both payloads match",
			payloads: []ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionSourceIP, Data: remoteHash[:]},
				&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionDestIP, Data: localHash[:]},
			},
			wantSupported: true,
		},
		{
			name: "multiple sources allow one matching address",
			payloads: []ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionSourceIP, Data: make([]byte, 20)},
				&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionSourceIP, Data: remoteHash[:]},
				&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionDestIP, Data: localHash[:]},
			},
			wantSupported: true,
		},
		{
			name: "destination mismatch detects local nat",
			payloads: []ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionSourceIP, Data: remoteHash[:]},
				&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionDestIP, Data: make([]byte, 20)},
			},
			wantSupported: true,
			wantDetected:  true,
		},
		{
			name: "source mismatch detects remote nat",
			payloads: []ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionSourceIP, Data: make([]byte, 20)},
				&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionDestIP, Data: localHash[:]},
			},
			wantSupported: true,
			wantDetected:  true,
		},
		{
			name: "neither payload means peer does not support natt",
		},
		{
			name: "source without destination is invalid",
			payloads: []ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionSourceIP, Data: remoteHash[:]},
			},
			wantErr: "missing source or destination NAT detection notification",
		},
		{
			name: "destination without source is invalid",
			payloads: []ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionDestIP, Data: localHash[:]},
			},
			wantErr: "missing source or destination NAT detection notification",
		},
		{
			name: "duplicate destination is invalid",
			payloads: []ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionSourceIP, Data: remoteHash[:]},
				&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionDestIP, Data: localHash[:]},
				&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionDestIP, Data: localHash[:]},
			},
			wantErr: "multiple NAT_DETECTION_DESTINATION_IP notifications",
		},
		{
			name: "source hash length is validated",
			payloads: []ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionSourceIP, Data: make([]byte, 19)},
				&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionDestIP, Data: localHash[:]},
			},
			wantErr: "invalid NAT_DETECTION_SOURCE_IP length 19",
		},
		{
			name: "destination hash length is validated",
			payloads: []ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionSourceIP, Data: remoteHash[:]},
				&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionDestIP, Data: make([]byte, 19)},
			},
			wantErr: "invalid NAT_DETECTION_DESTINATION_IP length 19",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSupported, gotDetected, err := ikeSAInitNATDetection(tt.payloads, initiatorSPI, responderSPI, local, remote)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ikeSAInitNATDetection() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ikeSAInitNATDetection() error = %v", err)
			}
			if gotSupported != tt.wantSupported {
				t.Fatalf("supported = %v, want %v", gotSupported, tt.wantSupported)
			}
			if gotDetected != tt.wantDetected {
				t.Fatalf("detected = %v, want %v", gotDetected, tt.wantDetected)
			}
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
		Version:      ikeVersion20,
		ExchangeType: expected.exchangeType,
		Flags:        flagResponse,
		MessageID:    expected.messageID,
	}
	tests := []struct {
		name   string
		header ike.IKEHeader
		peer   *net.UDPAddr
		want   bool
	}{
		{name: "valid response", header: validHeader, peer: peer, want: true},
		{name: "same id request is rejected", header: func() ike.IKEHeader { h := validHeader; h.Flags = flagInitiator; return h }(), peer: peer},
		{name: "initiator response is rejected", header: func() ike.IKEHeader { h := validHeader; h.Flags = flagResponse | flagInitiator; return h }(), peer: peer},
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

func TestNormalizeIKEPacketOnlyStripsMarkerForUDPEncapsulation(t *testing.T) {
	raw := mustIKEPacket(t, ike.IKEHeader{
		InitiatorSPI: 0x0000000005060708,
		ResponderSPI: 0x1112131415161718,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeIKESAInit,
		Flags:        flagResponse,
		MessageID:    0,
	}, nil)
	natt := prependNonESPMarker(raw)

	tests := []struct {
		name     string
		wire     []byte
		udpEncap bool
		want     []byte
	}{
		{
			name: "plain ike with high zero spi is preserved",
			wire: raw,
			want: raw,
		},
		{
			name:     "udp encapsulated ike strips marker",
			wire:     natt,
			udpEncap: true,
			want:     raw,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeIKEPacket(tt.wire, tt.udpEncap)
			if string(got) != string(tt.want) {
				t.Fatalf("normalizeIKEPacket() = %x, want %x", got, tt.want)
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

func testIKESAInitResponse(t *testing.T, fragmentationSupported bool) (*connectState, ike.IKEPacket, []byte, []byte, *net.UDPAddr, *net.UDPAddr) {
	t.Helper()
	local := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 40000}
	remote := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 500}
	state, err := newConnectState(handshake.ConnectInput{
		IMEI:        "356789012345678",
		Card:        sessionTestCard{},
		OuterRemote: remote,
		Config: handshake.Config{
			IKEEncryptionKeyLens: []uint16{128},
			IKEIntegrity:         []uint16{transformINTEGHMACSHA196},
			IKEPRF:               []uint16{transformPRFHMACSHA1},
		},
	})
	if err != nil {
		t.Fatalf("newConnectState() error = %v", err)
	}
	request, err := state.buildIKESAInitRequest(local, remote)
	if err != nil {
		t.Fatalf("buildIKESAInitRequest() error = %v", err)
	}
	responder, err := newIKECrypto(state.crypto.dhGroup)
	if err != nil {
		t.Fatalf("newIKECrypto(responder) error = %v", err)
	}
	responderSPI := uint64(0x1112131415161718)
	localHash := natDetectionHash(state.initiatorSPI, responderSPI, local)
	remoteHash := natDetectionHash(state.initiatorSPI, responderSPI, remote)
	payloads := []ike.Payload{
		&ike.SecurityAssociationPayload{Proposals: []ike.Proposal{ikeSAProposals(state.input.Config, state.crypto.dhGroup)[0]}},
		&ike.NoncePayload{Data: make([]byte, defaultIKENonceLength)},
		&ike.KeyExchangePayload{DHGroup: state.crypto.dhGroup, Data: responder.PublicKey()},
		&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionSourceIP, Data: remoteHash[:]},
		&ike.NotifyPayload{NotifyType: notifyTypeNATDetectionDestIP, Data: localHash[:]},
	}
	if fragmentationSupported {
		payloads = append(payloads, &ike.NotifyPayload{NotifyType: notifyTypeIKEV2FragmentationSupported})
	}
	responseRaw, err := (ike.IKEPacket{
		Header: ike.IKEHeader{
			InitiatorSPI: state.initiatorSPI,
			ResponderSPI: responderSPI,
			Version:      ikeVersion20,
			ExchangeType: exchangeTypeIKESAInit,
			Flags:        flagResponse,
			MessageID:    0,
		},
		Payloads: payloads,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(response) error = %v", err)
	}
	response, err := decodeIKESAInitPacket(responseRaw)
	if err != nil {
		t.Fatalf("decodeIKESAInitPacket() error = %v", err)
	}
	return state, response, request, responseRaw, local, remote
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
	wire = normalizeIKEPacket(wire, true)
	var packet ike.IKEPacket
	if err := packet.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	return packet
}
