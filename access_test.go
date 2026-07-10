package ims

import (
	"net"
	"testing"

	"github.com/damonto/ims-go/lte"
	swutunnel "github.com/damonto/ims-go/swu/tunnel"
	"github.com/damonto/uicc-go/usim"
)

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
				Access:   VoLTE(lte.Config{}),
			},
			wantVoLTE:     true,
			wantAPN:       lte.DefaultAPN,
			wantPDNType:   lte.DefaultPDNType,
			wantTransport: "udp",
		},
		{
			name: "volte access network info feeds ims",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access: VoLTE(lte.Config{
					AccessNetworkInfo: " 3GPP-E-UTRAN-FDD ",
					APN:               " ims ",
					PDNType:           " IPV6 ",
				}),
			},
			wantVoLTE:      true,
			wantAPN:        lte.DefaultAPN,
			wantPDNType:    "ipv6",
			wantTransport:  "udp",
			wantAccessInfo: "3GPP-E-UTRAN-FDD",
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
			got, err := tt.cfg.normalized(stubCard{})
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
		pdn       usim.IMSPDNInfo
		wantIPv4  net.IP
		wantPCSCF []net.IP
	}{
		{
			name: "uses modem info",
			cfg:  lte.Config{InterfaceName: "wwan0", AccessNetworkInfo: "3GPP-E-UTRAN-FDD"},
			pdn: usim.IMSPDNInfo{
				LocalIPv4:       net.IPv4(10, 0, 0, 2),
				PCSCFIPs:        []net.IP{net.IPv4(198, 51, 100, 10)},
				VoPSSupported:   true,
				PacketDataReady: true,
			},
			wantIPv4:  net.IPv4(10, 0, 0, 2),
			wantPCSCF: []net.IP{net.IPv4(198, 51, 100, 10)},
		},
		{
			name: "configured values override modem info",
			cfg: lte.Config{
				LocalIPv4: net.IPv4(10, 1, 0, 2),
				PCSCFIPs:  []net.IP{net.ParseIP("2001:db8::1")},
			},
			pdn: usim.IMSPDNInfo{
				LocalIPv4:       net.IPv4(10, 0, 0, 2),
				PCSCFIPs:        []net.IP{net.IPv4(198, 51, 100, 10)},
				PacketDataReady: true,
			},
			wantIPv4:  net.IPv4(10, 1, 0, 2),
			wantPCSCF: []net.IP{net.ParseIP("2001:db8::1")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := lteInfoFromIMSPDN(tt.cfg, tt.pdn)
			if !got.LocalIPv4.Equal(tt.wantIPv4) {
				t.Fatalf("LocalIPv4 = %v, want %v", got.LocalIPv4, tt.wantIPv4)
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
			if got.VoiceBearerReady != tt.pdn.PacketDataReady {
				t.Fatalf("VoiceBearerReady = %v, want %v", got.VoiceBearerReady, tt.pdn.PacketDataReady)
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
