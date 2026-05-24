package imsclient

import (
	"context"
	"testing"
	"time"

	swutunnel "github.com/damonto/ims-client/swu/tunnel"
	"github.com/damonto/ims-client/usim"
)

type wfcTestCard struct{}

func (wfcTestCard) ICCID() string { return "" }
func (wfcTestCard) IMSI() string  { return "530240123456789" }
func (wfcTestCard) MCC() string   { return "530" }
func (wfcTestCard) MNC() string   { return "24" }
func (wfcTestCard) SMSC() string  { return "" }
func (wfcTestCard) AKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return usim.AKAResult{}, nil
}

func tunnelConfigForWFCOverride() swutunnel.Config {
	return swutunnel.Config{
		InitialPort: 502,
		SIPPort:     5091,
	}
}

func TestConfigNormalizedWFCProfile(t *testing.T) {
	data := []byte(`{
  "53024": {
    "mcc": "530",
    "mnc": "24",
    "epdg": "epdg.ims.2degrees.net.nz",
    "initialPort": 501,
    "nattPort": 4501,
    "localSIPPort": 5064,
    "sipPort": 5070,
    "dhGroups": [2, 14],
    "ikeEncryptionKeyLens": [256],
    "ikeIntegrity": [12],
    "ikePRF": [5],
    "childEncryptionKeyLens": [128],
    "childIntegrity": [2],
    "natKeepaliveInterval": "60s",
    "ikeRetransmitDelays": ["1s", "2s", "4s"],
    "imsTransport": "tcp",
    "imsHomeDomain": "ims.mnc024.mcc530.3gppnetwork.org",
    "imsPhoneContextDomain": "ims.mnc024.mcc530.3gppnetwork.org",
    "imsAccessNetworkInfo": "IEEE-802.11;utran-cell-id-3gpp=00000000",
    "imsUserAgent": "PRD-IR92/15 #MANUFACTURE#/#MODEL#-#BUILD# device-type/#TYPE# mno-custom/#MCCMNC# imeisv/#IMEISV# op/#OPERATOR# sku/#HWSKU#",
    "wfcSPN": "2degrees",
    "imsRegisterExpires": "7200s",
    "imsSIPServerPort": 5080,
    "imsSIPTimerT1": "3s",
    "imsSIPTimerT2": "6s",
    "imsSIPTimerT4": "7s",
    "imsSIPTimerB": "9s",
    "imsSIPTimerD": "10s",
    "imsSIPTimerF": "11s",
    "imsSIPTimerH": "12s",
    "imsSIPTimerJ": "13s"
  }
}`)
	profile, ok, err := parseWFCProfile(data, wfcTestCard{})
	if err != nil {
		t.Fatalf("parseWFCProfile() error = %v", err)
	}
	if !ok {
		t.Fatal("parseWFCProfile() ok = false, want true")
	}

	tests := []struct {
		name  string
		cfg   Config
		check func(t *testing.T, got Config)
	}{
		{
			name: "profile fills empty client ims and ike config",
			cfg: Config{
				IMEI: testIMEI,
			},
			check: func(t *testing.T, got Config) {
				t.Helper()
				if got.EPDG != "epdg.ims.2degrees.net.nz" {
					t.Fatalf("EPDG = %q, want profile ePDG", got.EPDG)
				}
				if got.Tunnel.InitialPort != 501 || got.Tunnel.NATTPort != 4501 || got.Tunnel.LocalSIPPort != 5064 || got.Tunnel.SIPPort != 5070 {
					t.Fatalf("Tunnel ports = %d/%d/%d/%d, want profile ports", got.Tunnel.InitialPort, got.Tunnel.NATTPort, got.Tunnel.LocalSIPPort, got.Tunnel.SIPPort)
				}
				if len(got.Tunnel.DHGroups) != 2 || got.Tunnel.DHGroups[0] != 2 || got.Tunnel.DHGroups[1] != 14 {
					t.Fatalf("Tunnel.DHGroups = %v, want [2 14]", got.Tunnel.DHGroups)
				}
				if got.Tunnel.NATKeepaliveInterval != 60*time.Second {
					t.Fatalf("Tunnel.NATKeepaliveInterval = %v, want 60s", got.Tunnel.NATKeepaliveInterval)
				}
				if len(got.Tunnel.IKERetransmitDelays) != 3 || got.Tunnel.IKERetransmitDelays[2] != 4*time.Second {
					t.Fatalf("Tunnel.IKERetransmitDelays = %v, want [1s 2s 4s]", got.Tunnel.IKERetransmitDelays)
				}
				if got.IMS.Transport != "tcp" || got.IMS.HomeDomain != "ims.mnc024.mcc530.3gppnetwork.org" {
					t.Fatalf("IMS transport/domain = %q/%q, want profile values", got.IMS.Transport, got.IMS.HomeDomain)
				}
				wantUserAgent := "PRD-IR92/15 Google/Pixel 3XL-SQ3A.220705.004 device-type/Smartphone mno-custom/53024 imeisv/3567890123456700 op/2degrees sku/Pixel 3XL"
				if got.IMS.UserAgent != wantUserAgent || got.IMS.AccessNetworkInfo != "IEEE-802.11;utran-cell-id-3gpp=00000000" {
					t.Fatalf("IMS user agent/access = %q/%q, want profile values", got.IMS.UserAgent, got.IMS.AccessNetworkInfo)
				}
				if got.IMS.RegisterExpires != 7200*time.Second || got.IMS.SIPServerPort != 5080 {
					t.Fatalf("IMS expires/port = %v/%d, want profile values", got.IMS.RegisterExpires, got.IMS.SIPServerPort)
				}
				if got.IMS.SIPTimers.T1 != 3*time.Second || got.IMS.SIPTimers.TJ != 13*time.Second {
					t.Fatalf("IMS SIP timers T1/TJ = %v/%v, want profile values", got.IMS.SIPTimers.T1, got.IMS.SIPTimers.TJ)
				}
			},
		},
		{
			name: "explicit config overrides profile",
			cfg: Config{
				IMEI:   testIMEI,
				EPDG:   "epdg.example.com",
				Tunnel: tunnelConfigForWFCOverride(),
				IMS: IMSConfig{
					Transport:       "udp",
					HomeDomain:      "ims.example.com",
					UserAgent:       "explicit-agent",
					RegisterExpires: 30 * time.Second,
					SIPServerPort:   5090,
				},
			},
			check: func(t *testing.T, got Config) {
				t.Helper()
				if got.EPDG != "epdg.example.com" {
					t.Fatalf("EPDG = %q, want explicit value", got.EPDG)
				}
				if got.Tunnel.InitialPort != 502 || got.Tunnel.SIPPort != 5091 {
					t.Fatalf("Tunnel ports = %d/%d, want explicit values", got.Tunnel.InitialPort, got.Tunnel.SIPPort)
				}
				if got.IMS.Transport != "udp" || got.IMS.HomeDomain != "ims.example.com" {
					t.Fatalf("IMS transport/domain = %q/%q, want explicit values", got.IMS.Transport, got.IMS.HomeDomain)
				}
				if got.IMS.UserAgent != "explicit-agent" || got.IMS.RegisterExpires != 30*time.Second || got.IMS.SIPServerPort != 5090 {
					t.Fatalf("IMS user agent/expires/port = %q/%v/%d, want explicit values", got.IMS.UserAgent, got.IMS.RegisterExpires, got.IMS.SIPServerPort)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.withWFCProfile(profile)
			imsCfg, err := got.normalizedIMS()
			if err != nil {
				t.Fatalf("normalizedIMS() error = %v", err)
			}
			got.IMS = imsCfg
			tunnelCfg, err := got.normalizedTunnel()
			if err != nil {
				t.Fatalf("normalizedTunnel() error = %v", err)
			}
			got.Tunnel = tunnelCfg
			tt.check(t, got)
		})
	}
}

func TestConfigNormalizedUsesEmbeddedWFCProfile(t *testing.T) {
	tests := []struct {
		name     string
		cfg      Config
		wantEPDG string
	}{
		{
			name: "embedded profile fills epdg",
			cfg: Config{
				IMEI: testIMEI,
			},
			wantEPDG: "epdg.ims.2degrees.net.nz",
		},
		{
			name: "explicit epdg still wins",
			cfg: Config{
				IMEI: testIMEI,
				EPDG: "epdg.example.com",
			},
			wantEPDG: "epdg.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.normalized(wfcTestCard{})
			if err != nil {
				t.Fatalf("normalized() error = %v", err)
			}
			if got.EPDG != tt.wantEPDG {
				t.Fatalf("EPDG = %q, want %q", got.EPDG, tt.wantEPDG)
			}
		})
	}
}
