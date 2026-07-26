package ims

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"

	imsvoice "github.com/damonto/ims-go/ims/voice"
	"github.com/damonto/ims-go/lte"
	swutunnel "github.com/damonto/ims-go/swu/tunnel"
)

func TestVoWiFiMediaReady(t *testing.T) {
	tests := []struct {
		name    string
		cancel  bool
		wantErr error
	}{
		{name: "active context"},
		{name: "canceled context", cancel: true, wantErr: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancel {
				cancel()
			}
			err := voWiFiMediaReady(ctx, imsvoice.MediaConfig{})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("voWiFiMediaReady() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

const testVoLTEPANI = "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=1112233C476B4321"

type imsPDNSessionStub struct {
	info       imsPDNInfo
	closeCalls int
}

func TestVoLTEMediaReady(t *testing.T) {
	tests := []struct {
		name    string
		cancel  bool
		wantErr error
	}{
		{name: "RTP transport is ready"},
		{name: "canceled context", cancel: true, wantErr: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancel {
				cancel()
			}
			access := &voLTEAccess{}
			err := access.waitMediaReady(ctx, imsvoice.MediaConfig{RemotePort: 50000})
			if tt.wantErr == nil && err != nil {
				t.Fatalf("waitMediaReady() error = %v", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("waitMediaReady() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func (s *imsPDNSessionStub) Info() imsPDNInfo {
	return s.info
}

func (s *imsPDNSessionStub) Close() error {
	s.closeCalls++
	return nil
}

type imsPDNReaderStub struct {
	readerStub
	session imsPDNSession
}

func (s *imsPDNReaderStub) OpenIMSPDN(context.Context, imsPDNConfig) (imsPDNSession, error) {
	return s.session, nil
}

func TestConfigNormalizedAccess(t *testing.T) {
	tests := []struct {
		name           string
		cfg            Config
		wantErr        bool
		wantVoLTE      bool
		wantEPDG       string
		wantAPN        string
		wantPDNType    string
		wantTransport  string
		wantAccessInfo string
	}{
		{
			name: "empty access fails",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
			},
			wantErr: true,
		},
		{
			name: "vowifi defaults from sim",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoWiFi(VoWiFiConfig{}),
			},
			wantEPDG:       "epdg.epc.mnc001.mcc001.pub.3gppnetwork.org",
			wantTransport:  "tcp",
			wantAccessInfo: "IEEE-802.11",
		},
		{
			name: "volte defaults qmi ims pdn",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoLTE(lte.Config{AccessNetworkInfo: testVoLTEPANI}),
			},
			wantVoLTE:      true,
			wantAPN:        lte.DefaultAPN,
			wantPDNType:    lte.DefaultPDNType,
			wantTransport:  "udp",
			wantAccessInfo: testVoLTEPANI,
		},
		{
			name: "volte requires access network info",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoLTE(lte.Config{}),
			},
			wantErr: true,
		},
		{
			name: "volte access network info feeds ims",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access: VoLTE(lte.Config{
					AccessNetworkInfo: " 3gpp-e-utran-fdd; utran-cell-id-3gpp=1112233c476b4321 ",
					APN:               " ims ",
					PDNType:           " IPV6 ",
				}),
			},
			wantVoLTE:      true,
			wantAPN:        lte.DefaultAPN,
			wantPDNType:    "ipv6",
			wantTransport:  "udp",
			wantAccessInfo: testVoLTEPANI,
		},
		{
			name: "volte accepts valid ims access network override",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoLTE(lte.Config{}),
				IMS:      IMSConfig{AccessNetworkInfo: testVoLTEPANI},
			},
			wantVoLTE:      true,
			wantAPN:        lte.DefaultAPN,
			wantPDNType:    lte.DefaultPDNType,
			wantTransport:  "udp",
			wantAccessInfo: testVoLTEPANI,
		},
		{
			name: "volte rejects WLAN access network override",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoLTE(lte.Config{}),
				IMS:      IMSConfig{AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aabbccddeeff"},
			},
			wantErr: true,
		},
		{
			name: "volte rejects E-UTRAN without cell identity",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoLTE(lte.Config{AccessNetworkInfo: "3GPP-E-UTRAN-FDD"}),
			},
			wantErr: true,
		},
		{
			name: "invalid volte pdn type fails",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoLTE(lte.Config{PDNType: "ipv5"}),
			},
			wantErr: true,
		},
		{
			name: "invalid volte local ipv4 fails",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoLTE(lte.Config{LocalIPv4: net.ParseIP("2001:db8::1")}),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := withTestIPSecAlgorithms(tt.cfg).normalized(stubCard{})
			if tt.wantErr {
				if err == nil {
					t.Fatal("normalized() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalized() error = %v", err)
			}
			if got.usesVoLTE() != tt.wantVoLTE {
				t.Fatalf("usesVoLTE() = %t, want %t", got.usesVoLTE(), tt.wantVoLTE)
			}
			if got.usesVoWiFi() != !tt.wantVoLTE {
				t.Fatalf("usesVoWiFi() = %t, want %t", got.usesVoWiFi(), !tt.wantVoLTE)
			}
			if gotEPDG := configEPDG(got); gotEPDG != tt.wantEPDG {
				t.Fatalf("EPDG = %q, want %q", gotEPDG, tt.wantEPDG)
			}
			if gotAPN := configVoLTE(got).APN; gotAPN != tt.wantAPN {
				t.Fatalf("Access.VoLTE.APN = %q, want %q", gotAPN, tt.wantAPN)
			}
			if gotPDNType := configVoLTE(got).PDNType; gotPDNType != tt.wantPDNType {
				t.Fatalf("Access.VoLTE.PDNType = %q, want %q", gotPDNType, tt.wantPDNType)
			}
			if got.IMS.Transport != tt.wantTransport {
				t.Fatalf("IMS.Transport = %q, want %q", got.IMS.Transport, tt.wantTransport)
			}
			if got.IMS.AccessNetworkInfo != tt.wantAccessInfo {
				t.Fatalf("IMS.AccessNetworkInfo = %q, want %q", got.IMS.AccessNetworkInfo, tt.wantAccessInfo)
			}
		})
	}
}

func TestLTEInfoFromIMSPDN(t *testing.T) {
	tests := []struct {
		name      string
		cfg       lte.Config
		pdn       imsPDNInfo
		wantIPv4  net.IP
		wantIPv6  net.IP
		wantPCSCF []net.IP
		wantPANI  string
		wantIF    string
	}{
		{
			name: "uses modem info",
			cfg:  lte.Config{InterfaceName: "wwan0", AccessNetworkInfo: testVoLTEPANI},
			pdn: imsPDNInfo{
				InterfaceName:   "mbim7s1",
				LocalIPv4:       net.IPv4(10, 0, 0, 2),
				PCSCFIPs:        []net.IP{net.IPv4(198, 51, 100, 10)},
				VoPSKnown:       true,
				VoPSSupported:   true,
				PacketDataReady: true,
			},
			wantIPv4:  net.IPv4(10, 0, 0, 2),
			wantPCSCF: []net.IP{net.IPv4(198, 51, 100, 10)},
			wantPANI:  testVoLTEPANI,
			wantIF:    "mbim7s1",
		},
		{
			name: "configured values override modem info",
			cfg: lte.Config{
				LocalIPv4: net.IPv4(10, 1, 0, 2),
				PCSCFIPs:  []net.IP{net.ParseIP("2001:db8::1")},
			},
			pdn: imsPDNInfo{
				LocalIPv4:       net.IPv4(10, 0, 0, 2),
				PCSCFIPs:        []net.IP{net.IPv4(198, 51, 100, 10)},
				PacketDataReady: true,
			},
			wantIPv4:  net.IPv4(10, 1, 0, 2),
			wantPCSCF: []net.IP{net.ParseIP("2001:db8::1")},
		},
		{
			name: "ipv4 PDN ignores unexpected modem IPv6 address",
			cfg:  lte.Config{PDNType: "ipv4"},
			pdn: imsPDNInfo{
				LocalIPv4: net.IPv4(10, 0, 0, 2),
				LocalIPv6: net.ParseIP("2001:db8::2"),
			},
			wantIPv4: net.IPv4(10, 0, 0, 2),
		},
		{
			name: "ipv6 PDN ignores unexpected modem IPv4 address",
			cfg:  lte.Config{PDNType: "ipv6"},
			pdn: imsPDNInfo{
				LocalIPv4: net.IPv4(10, 0, 0, 2),
				LocalIPv6: net.ParseIP("2001:db8::2"),
			},
			wantIPv6: net.ParseIP("2001:db8::2"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := lteInfoFromIMSPDN(tt.cfg, tt.pdn)
			if got.InterfaceName != tt.wantIF {
				t.Fatalf("InterfaceName = %q, want %q", got.InterfaceName, tt.wantIF)
			}
			if !got.LocalIPv4.Equal(tt.wantIPv4) {
				t.Fatalf("LocalIPv4 = %v, want %v", got.LocalIPv4, tt.wantIPv4)
			}
			if !got.LocalIPv6.Equal(tt.wantIPv6) {
				t.Fatalf("LocalIPv6 = %v, want %v", got.LocalIPv6, tt.wantIPv6)
			}
			if len(got.PCSCFIPs) != len(tt.wantPCSCF) {
				t.Fatalf("PCSCFIPs len = %d, want %d", len(got.PCSCFIPs), len(tt.wantPCSCF))
			}
			for i, want := range tt.wantPCSCF {
				if !got.PCSCFIPs[i].Equal(want) {
					t.Fatalf("PCSCFIPs[%d] = %v, want %v", i, got.PCSCFIPs[i], want)
				}
			}
			if got.IMSPDNConnected != tt.pdn.PacketDataReady {
				t.Fatalf("IMSPDNConnected = %v, want %v", got.IMSPDNConnected, tt.pdn.PacketDataReady)
			}
			if got.VoPSKnown != tt.pdn.VoPSKnown || got.VoPSSupported != tt.pdn.VoPSSupported {
				t.Fatalf("VoPS = known %v supported %v, want known %v supported %v", got.VoPSKnown, got.VoPSSupported, tt.pdn.VoPSKnown, tt.pdn.VoPSSupported)
			}
			if got.VoiceBearerReady {
				t.Fatal("VoiceBearerReady = true without a dedicated bearer indication")
			}
			if got.AccessNetworkInfo != tt.wantPANI {
				t.Fatalf("AccessNetworkInfo = %q, want %q", got.AccessNetworkInfo, tt.wantPANI)
			}
		})
	}
}

func TestOpenVoLTEAccessRequiresReadyIMSPDN(t *testing.T) {
	previousInterfaceByName := voLTEInterfaceByName
	voLTEInterfaceByName = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: 1}, nil
	}
	t.Cleanup(func() { voLTEInterfaceByName = previousInterfaceByName })

	tests := []struct {
		name    string
		ready   bool
		wantErr bool
	}{
		{name: "ready IMS PDN", ready: true},
		{name: "packet data not ready", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interfaceName := "ims-test0"
			session := &imsPDNSessionStub{info: imsPDNInfo{
				LocalIPv4:       net.IPv4(192, 0, 2, 10),
				PCSCFIPs:        []net.IP{net.IPv4(198, 51, 100, 20)},
				PacketDataReady: tt.ready,
			}}
			client := &Client{
				cfg: Config{
					Logger: slog.Default(),
					Access: VoLTE(lte.Config{
						InterfaceName:     interfaceName,
						APN:               lte.DefaultAPN,
						PDNType:           lte.DefaultPDNType,
						AccessNetworkInfo: testVoLTEPANI,
					}),
				},
				reader: &imsPDNReaderStub{session: session},
			}

			access, err := client.openVoLTEAccess(context.Background(), &connectSetup{})
			if tt.wantErr {
				if err == nil {
					_ = access.Close()
					t.Fatal("openVoLTEAccess() error = nil, want non-nil")
				}
				if session.closeCalls != 1 {
					t.Fatalf("IMS PDN Close() calls = %d, want 1", session.closeCalls)
				}
				return
			}
			if err != nil {
				t.Fatalf("openVoLTEAccess() error = %v", err)
			}
			if err := access.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			if session.closeCalls != 1 {
				t.Fatalf("IMS PDN Close() calls = %d, want 1", session.closeCalls)
			}
		})
	}
}

func TestVoLTEMediaRejectsKnownUnsupportedVoPS(t *testing.T) {
	tests := []struct {
		name string
		info lte.Info
	}{
		{name: "known unsupported", info: lte.Info{VoPSKnown: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			access := &voLTEAccess{info: tt.info}
			transport, err := access.openMedia(context.Background(), imsvoice.MediaConfig{})
			if err == nil {
				if transport != nil {
					_ = transport.Close()
				}
				t.Fatal("openMedia() error = nil, want VoPS unavailable error")
			}
		})
	}
}

func TestVoLTEMediaUsesRegisteredSIPFamily(t *testing.T) {
	tests := []struct {
		name       string
		info       lte.Info
		sipLocalIP net.IP
		remoteIP   net.IP
		wantErr    string
	}{
		{
			name: "rejects IPv4 media after IPv6 SIP registration",
			info: lte.Info{
				LocalIPv4: net.IPv4(192, 0, 2, 10),
				LocalIPv6: net.ParseIP("2001:db8::10"),
			},
			sipLocalIP: net.ParseIP("2001:db8::10"),
			remoteIP:   net.IPv4(198, 51, 100, 20),
			wantErr:    "differs from registered SIP flow",
		},
		{
			name: "rejects media before SIP flow is known",
			info: lte.Info{
				LocalIPv4: net.IPv4(192, 0, 2, 10),
			},
			remoteIP: net.IPv4(198, 51, 100, 20),
			wantErr:  "registered SIP local address is unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			access := &voLTEAccess{info: tt.info, sipLocalIP: tt.sipLocalIP}
			transport, err := access.openMedia(context.Background(), imsvoice.MediaConfig{RemoteIP: tt.remoteIP})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				if transport != nil {
					_ = transport.Close()
				}
				t.Fatalf("openMedia() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func configEPDG(cfg Config) string {
	if cfg.Access.VoWiFi == nil {
		return ""
	}
	return cfg.Access.VoWiFi.EPDG
}

func configVoLTE(cfg Config) lte.Config {
	if cfg.Access.VoLTE == nil {
		return lte.Config{}
	}
	return *cfg.Access.VoLTE
}

func configTunnel(cfg Config) swutunnel.Config {
	if cfg.Access.VoWiFi == nil {
		return swutunnel.Config{}
	}
	return cfg.Access.VoWiFi.Tunnel
}

func testVoWiFiConfig(epdg string, tunnel swutunnel.Config) Config {
	return Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Access: VoWiFi(VoWiFiConfig{
			EPDG:   epdg,
			Tunnel: tunnel,
		}),
	}
}
