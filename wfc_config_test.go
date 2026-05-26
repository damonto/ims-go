package imsclient

import (
	"context"
	"strings"
	"testing"
	"time"

	swutunnel "github.com/damonto/ims-client/swu/tunnel"
	"github.com/damonto/ims-client/usim"
)

type wfcTestCard struct{}
type paddedTwoDigitMNCCard struct{}
type gid1WFCCard struct {
	wfcTestCard
	gid1 string
}
type paddedTwoDigitGID1Card struct {
	paddedTwoDigitMNCCard
	gid1 string
}
type plmnWFCCard struct {
	mcc       string
	mnc       string
	mncLength int
	gid1      string
}

func (wfcTestCard) ICCID() string { return "" }
func (wfcTestCard) IMSI() string  { return "530240123456789" }
func (wfcTestCard) MCC() string   { return "530" }
func (wfcTestCard) MNC() string   { return "24" }
func (wfcTestCard) SMSC() string  { return "" }
func (wfcTestCard) AKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return usim.AKAResult{}, nil
}

func (c gid1WFCCard) GID1() string { return c.gid1 }
func (c paddedTwoDigitGID1Card) GID1() string {
	return c.gid1
}
func (c plmnWFCCard) ICCID() string  { return "" }
func (c plmnWFCCard) IMSI() string   { return c.mcc + c.mnc + "0123456789" }
func (c plmnWFCCard) MCC() string    { return c.mcc }
func (c plmnWFCCard) MNC() string    { return c.mnc }
func (c plmnWFCCard) MNCLength() int { return c.mncLength }
func (c plmnWFCCard) SMSC() string   { return "" }
func (c plmnWFCCard) GID1() string   { return c.gid1 }
func (c plmnWFCCard) AKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return usim.AKAResult{}, nil
}

func (paddedTwoDigitMNCCard) ICCID() string  { return "" }
func (paddedTwoDigitMNCCard) IMSI() string   { return "454000121084653" }
func (paddedTwoDigitMNCCard) MCC() string    { return "454" }
func (paddedTwoDigitMNCCard) MNC() string    { return "000" }
func (paddedTwoDigitMNCCard) MNCLength() int { return 2 }
func (paddedTwoDigitMNCCard) SMSC() string   { return "" }
func (paddedTwoDigitMNCCard) AKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return usim.AKAResult{}, nil
}

func tunnelConfigForWFCOverride() swutunnel.Config {
	return swutunnel.Config{
		InitialPort: 502,
		SIPPort:     5091,
	}
}

func TestConfigNormalizedWFCProfile(t *testing.T) {
	data := []byte(`[
  {
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
    "pcscfIPv4ConfigAttribute": 16384,
    "pcscfIPv6ConfigAttribute": 16386,
    "natKeepaliveInterval": "60s",
    "ikeRetransmitDelays": ["1s", "2s", "4s"],
    "imsTransport": "tcp",
    "imsHomeDomain": "ims.mnc024.mcc530.3gppnetwork.org",
    "imsPrivateIdentity": "#IMSI#@private.example",
    "imsPublicIdentity": "sip:#IMSI#@#HOME_DOMAIN#",
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
]`)
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
				if got.Tunnel.PCSCFIPv4ConfigAttribute != 16384 || got.Tunnel.PCSCFIPv6ConfigAttribute != 16386 {
					t.Fatalf("Tunnel P-CSCF attrs = %d/%d, want 16384/16386", got.Tunnel.PCSCFIPv4ConfigAttribute, got.Tunnel.PCSCFIPv6ConfigAttribute)
				}
				if len(got.Tunnel.IKERetransmitDelays) != 3 || got.Tunnel.IKERetransmitDelays[2] != 4*time.Second {
					t.Fatalf("Tunnel.IKERetransmitDelays = %v, want [1s 2s 4s]", got.Tunnel.IKERetransmitDelays)
				}
				if got.IMS.Transport != "tcp" || got.IMS.HomeDomain != "ims.mnc024.mcc530.3gppnetwork.org" {
					t.Fatalf("IMS transport/domain = %q/%q, want profile values", got.IMS.Transport, got.IMS.HomeDomain)
				}
				if got.IMS.PrivateIdentity != "530240123456789@private.example" || got.IMS.PublicIdentity != "sip:530240123456789@ims.mnc024.mcc530.3gppnetwork.org" {
					t.Fatalf("IMS identities = %q/%q, want profile values", got.IMS.PrivateIdentity, got.IMS.PublicIdentity)
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
					PrivateIdentity: "private@example.com",
					PublicIdentity:  "sip:public@example.com",
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
				if got.Tunnel.PCSCFIPv4ConfigAttribute != 16384 || got.Tunnel.PCSCFIPv6ConfigAttribute != 16386 {
					t.Fatalf("Tunnel P-CSCF attrs = %d/%d, want profile values", got.Tunnel.PCSCFIPv4ConfigAttribute, got.Tunnel.PCSCFIPv6ConfigAttribute)
				}
				if got.IMS.Transport != "udp" || got.IMS.HomeDomain != "ims.example.com" {
					t.Fatalf("IMS transport/domain = %q/%q, want explicit values", got.IMS.Transport, got.IMS.HomeDomain)
				}
				if got.IMS.PrivateIdentity != "private@example.com" || got.IMS.PublicIdentity != "sip:public@example.com" {
					t.Fatalf("IMS identities = %q/%q, want explicit values", got.IMS.PrivateIdentity, got.IMS.PublicIdentity)
				}
				if got.IMS.UserAgent != "explicit-agent" || got.IMS.RegisterExpires != 30*time.Second || got.IMS.SIPServerPort != 5090 {
					t.Fatalf("IMS user agent/expires/port = %q/%v/%d, want explicit values", got.IMS.UserAgent, got.IMS.RegisterExpires, got.IMS.SIPServerPort)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.withWFCProfile(profile, wfcTestCard{})
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

func TestParseWFCProfileGID1(t *testing.T) {
	data := []byte(`[
  {
    "mcc": "530",
    "mnc": "24",
    "epdg": "epdg.base.example"
  },
  {
    "mcc": "530",
    "mnc": "24",
    "gid1": "ABCD",
    "epdg": "epdg.gid.example"
  }
]`)

	tests := []struct {
		name     string
		card     Card
		wantEPDG string
	}{
		{
			name:     "gid profile wins when gid matches",
			card:     gid1WFCCard{gid1: "abcdffff"},
			wantEPDG: "epdg.gid.example",
		},
		{
			name:     "base profile wins when gid is absent",
			card:     wfcTestCard{},
			wantEPDG: "epdg.base.example",
		},
		{
			name:     "base profile wins when gid does not match",
			card:     gid1WFCCard{gid1: "1234"},
			wantEPDG: "epdg.base.example",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, ok, err := parseWFCProfile(data, tt.card)
			if err != nil {
				t.Fatalf("parseWFCProfile() error = %v", err)
			}
			if !ok {
				t.Fatal("parseWFCProfile() ok = false, want true")
			}
			if profile.EPDG != tt.wantEPDG {
				t.Fatalf("EPDG = %q, want %q", profile.EPDG, tt.wantEPDG)
			}
		})
	}
}

func TestConfigNormalizedUsesEmbeddedWFCProfile(t *testing.T) {
	tests := []struct {
		name     string
		cfg      Config
		card     Card
		wantEPDG string
	}{
		{
			name: "embedded profile fills epdg",
			cfg: Config{
				IMEI: testIMEI,
			},
			card:     wfcTestCard{},
			wantEPDG: "epdg.ims.2degrees.net.nz",
		},
		{
			name: "explicit epdg still wins",
			cfg: Config{
				IMEI: testIMEI,
				EPDG: "epdg.example.com",
			},
			card:     wfcTestCard{},
			wantEPDG: "epdg.example.com",
		},
		{
			name: "embedded two digit mnc profile matches padded card mnc",
			cfg: Config{
				IMEI: testIMEI,
			},
			card:     paddedTwoDigitMNCCard{},
			wantEPDG: "epdg.epc.mnc000.mcc454.pub.3gppnetwork.org",
		},
		{
			name: "embedded gid profile wins over base profile",
			cfg: Config{
				IMEI: testIMEI,
			},
			card:     paddedTwoDigitGID1Card{gid1: "547275554B3030656EFFFF"},
			wantEPDG: "epdg.eps.truphone.net",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.normalized(tt.card)
			if err != nil {
				t.Fatalf("normalized() error = %v", err)
			}
			if got.EPDG != tt.wantEPDG {
				t.Fatalf("EPDG = %q, want %q", got.EPDG, tt.wantEPDG)
			}
		})
	}
}

func TestEmbeddedWFCConfigHonorEPDG(t *testing.T) {
	tests := []struct {
		name     string
		card     plmnWFCCard
		wantEPDG string
	}{
		{
			name:     "csl hk base uses honor",
			card:     plmnWFCCard{mcc: "454", mnc: "000", mncLength: 2},
			wantEPDG: "epdg.epc.mnc000.mcc454.pub.3gppnetwork.org",
		},
		{
			name:     "truphone hk gid keeps pixel override",
			card:     plmnWFCCard{mcc: "454", mnc: "000", mncLength: 2, gid1: "547275554B3030656EFFFF"},
			wantEPDG: "epdg.eps.truphone.net",
		},
		{
			name:     "austria 23210 base uses honor",
			card:     plmnWFCCard{mcc: "232", mnc: "10", mncLength: 2},
			wantEPDG: "epdg.epc.mnc010.mcc232.pub.3gppnetwork.org",
		},
		{
			name:     "att mexico base uses honor",
			card:     plmnWFCCard{mcc: "334", mnc: "050", mncLength: 3},
			wantEPDG: "epdg.ims.attmex.mx",
		},
		{
			name:     "singapore 52502 base uses honor",
			card:     plmnWFCCard{mcc: "525", mnc: "02", mncLength: 2},
			wantEPDG: "epdg.epc.mnc002.mcc525.pub.3gppnetwork.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Config{IMEI: testIMEI}.normalized(tt.card)
			if err != nil {
				t.Fatalf("normalized() error = %v", err)
			}
			if got.EPDG != tt.wantEPDG {
				t.Fatalf("EPDG = %q, want %q", got.EPDG, tt.wantEPDG)
			}
		})
	}
}

func TestEmbeddedWFCConfigATTUsesConfiguredIMSIdentities(t *testing.T) {
	got, err := Config{IMEI: testIMEI}.normalized(plmnWFCCard{mcc: "310", mnc: "280", mncLength: 3})
	if err != nil {
		t.Fatalf("normalized() error = %v", err)
	}
	if got.IMS.HomeDomain != "one.att.net" {
		t.Fatalf("HomeDomain = %q, want one.att.net", got.IMS.HomeDomain)
	}
	if got.IMS.PrivateIdentity != "3102800123456789@private.att.net" {
		t.Fatalf("PrivateIdentity = %q, want AT&T private identity", got.IMS.PrivateIdentity)
	}
	if got.IMS.PublicIdentity != "sip:3102800123456789@one.att.net" {
		t.Fatalf("PublicIdentity = %q, want AT&T public identity", got.IMS.PublicIdentity)
	}
}

func TestEmbeddedWFCConfigMatchesNSDSProfiles(t *testing.T) {
	for _, profile := range nsdsWFCProfiles {
		t.Run(profile.Carrier+" "+profile.MCC+profile.MNC, func(t *testing.T) {
			card := plmnWFCCard{
				mcc:       profile.MCC,
				mnc:       profile.MNC,
				mncLength: len(profile.MNC),
			}
			got, err := Config{IMEI: testIMEI}.normalized(card)
			if err != nil {
				t.Fatalf("normalized() error = %v", err)
			}

			if strings.Contains(profile.ServerURL, "mobile.att.net") {
				wantIMSI := card.IMSI()
				if got.IMS.HomeDomain != "one.att.net" {
					t.Fatalf("HomeDomain = %q, want one.att.net", got.IMS.HomeDomain)
				}
				if got.IMS.PrivateIdentity != wantIMSI+"@private.att.net" {
					t.Fatalf("PrivateIdentity = %q, want AT&T private identity", got.IMS.PrivateIdentity)
				}
				if got.IMS.PublicIdentity != "sip:"+wantIMSI+"@one.att.net" {
					t.Fatalf("PublicIdentity = %q, want AT&T public identity", got.IMS.PublicIdentity)
				}
				return
			}

			if got.IMS.HomeDomain == "one.att.net" || strings.Contains(got.IMS.PrivateIdentity, "att.net") || strings.Contains(got.IMS.PublicIdentity, "att.net") {
				t.Fatalf("IMS profile = %q/%q/%q, want non-AT&T values", got.IMS.HomeDomain, got.IMS.PrivateIdentity, got.IMS.PublicIdentity)
			}
		})
	}
}
