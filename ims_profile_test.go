package ims

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	imsvoice "github.com/damonto/ims-go/ims/voice"
	"github.com/damonto/ims-go/lte"
	swutunnel "github.com/damonto/ims-go/swu/tunnel"
	usim "github.com/damonto/wwan-go/sim"
)

type wfcTestCard struct{}
type paddedTwoDigitMNCCard struct{}
type minimalProfileCard struct{}
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
	iccid     string
	spn       string
	gid1      string
	gid2      string
	imsi      string
}

var _ Card = minimalProfileCard{}

func (minimalProfileCard) ICCID() string  { return "" }
func (minimalProfileCard) IMSI() string   { return "001010123456789" }
func (minimalProfileCard) MCC() string    { return "001" }
func (minimalProfileCard) MNC() string    { return "01" }
func (minimalProfileCard) MNCLength() int { return 2 }
func (minimalProfileCard) GID1() string   { return "" }
func (minimalProfileCard) GID2() string   { return "" }
func (minimalProfileCard) SPN() string    { return "" }
func (minimalProfileCard) SMSC() string   { return "" }
func (minimalProfileCard) AKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return usim.AKAResult{}, nil
}
func (minimalProfileCard) EAPAKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return usim.AKAResult{}, nil
}

func (wfcTestCard) ICCID() string  { return "" }
func (wfcTestCard) IMSI() string   { return "530240123456789" }
func (wfcTestCard) MCC() string    { return "530" }
func (wfcTestCard) MNC() string    { return "24" }
func (wfcTestCard) MNCLength() int { return 2 }
func (wfcTestCard) GID1() string   { return "" }
func (wfcTestCard) GID2() string   { return "" }
func (wfcTestCard) SPN() string    { return "" }
func (wfcTestCard) SMSC() string   { return "" }
func (wfcTestCard) AKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return usim.AKAResult{}, nil
}
func (wfcTestCard) EAPAKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return usim.AKAResult{}, nil
}

func (c gid1WFCCard) GID1() string { return c.gid1 }
func (c paddedTwoDigitGID1Card) GID1() string {
	return c.gid1
}
func (c plmnWFCCard) ICCID() string { return c.iccid }
func (c plmnWFCCard) IMSI() string {
	if c.imsi != "" {
		return c.imsi
	}
	return c.mcc + c.mnc + "0123456789"
}
func (c plmnWFCCard) MCC() string    { return c.mcc }
func (c plmnWFCCard) MNC() string    { return c.mnc }
func (c plmnWFCCard) MNCLength() int { return c.mncLength }
func (c plmnWFCCard) SMSC() string   { return "" }
func (c plmnWFCCard) GID1() string   { return c.gid1 }
func (c plmnWFCCard) GID2() string   { return c.gid2 }
func (c plmnWFCCard) SPN() string    { return c.spn }
func (c plmnWFCCard) AKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return usim.AKAResult{}, nil
}
func (c plmnWFCCard) EAPAKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return usim.AKAResult{}, nil
}

func (paddedTwoDigitMNCCard) ICCID() string  { return "" }
func (paddedTwoDigitMNCCard) IMSI() string   { return "454000121084653" }
func (paddedTwoDigitMNCCard) MCC() string    { return "454" }
func (paddedTwoDigitMNCCard) MNC() string    { return "000" }
func (paddedTwoDigitMNCCard) MNCLength() int { return 2 }
func (paddedTwoDigitMNCCard) GID1() string   { return "" }
func (paddedTwoDigitMNCCard) GID2() string   { return "" }
func (paddedTwoDigitMNCCard) SPN() string    { return "" }
func (paddedTwoDigitMNCCard) SMSC() string   { return "" }
func (paddedTwoDigitMNCCard) AKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return usim.AKAResult{}, nil
}
func (paddedTwoDigitMNCCard) EAPAKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
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
    "ikeSALifetime": "7200s",
    "ikeSARekeySoftTime": "3600s",
    "ikeSARekeyHardTime": "3900s",
    "childSALifetime": "3600s",
    "childSARekeySoftTime": "1800s",
    "childSARekeyHardTime": "1980s",
    "addKEToChildSARekey": true,
    "imsTransport": "tcp",
    "imsHomeDomain": "ims.mnc024.mcc530.3gppnetwork.org",
    "imsPublicIdentity": "sip:#IMSI#@#HOME_DOMAIN#",
    "imsPhoneContextDomain": "ims.mnc024.mcc530.3gppnetwork.org",
    "imsAccessNetworkInfo": "IEEE-802.11;utran-cell-id-3gpp=00000000",
    "imsUserAgent": "PRD-IR92/15 #MANUFACTURE#/#MODEL#-#BUILD# device-type/#TYPE# mno-custom/#MCCMNC# imeisv/#IMEISV# op/#OPERATOR# sku/#HWSKU#",
    "wfcSPN": "2degrees",
    "imsRegisterExpires": "7200s",
    "imsRegistrationRetryBase": "120s",
    "imsRegistrationRetryMax": "300s",
    "imsGeolocationPIDFInSIPInviteSupport": [4, 2],
    "imsGeolocationPIDFInSIPRegisterSupport": [4, 2],
    "imsUseTelURIForPIDFXML": true,
    "imsSIPServerPort": 5080,
    "imsSIPTimerT1": "3s",
    "imsSIPTimerT2": "6s",
    "imsSIPTimerT4": "7s",
    "imsSIPTimerB": "9s",
    "imsSIPTimerD": "10s",
    "imsSIPTimerF": "11s",
    "imsSIPTimerH": "12s",
    "imsSIPTimerJ": "13s",
    "imsVoice": {
      "rtpProfile": "RTP/AVP",
      "ptime": "20ms",
      "maxptime": "240ms",
      "pidfShortCodes": ["211", "311"],
      "qosPreconditionsSupported": true,
      "reliableProvisionalSupported": true,
      "sessionTimer": true,
      "sessionExpires": "3600s",
      "minimumSessionExpires": "600s",
      "sessionRefresher": "uas",
      "moCallRequestTimeout": "30s",
      "ringbackTimer": "180s",
      "ringingTimer": "45s",
      "audioASBandwidthKbps": 49,
      "rtpInactivityTimeout": "20s",
      "rtcpInactivityTimeout": "21s",
      "audioInactivityCallEndReasons": [0, 1, 2],
      "localRTPPortMin": 41000,
      "localRTPPortMax": 41020,
      "codecs": [
        {"name": "EVS", "payloadTypes": [127], "clockRate": 16000},
        {"name": "AMR-WB", "payloadTypes": [104], "clockRate": 16000},
        {"name": "AMR", "payloadTypes": [102], "clockRate": 8000, "modeSet": "0,2,4,7"},
        {"name": "telephone-event", "payloadTypes": [101], "clockRate": 8000}
      ],
      "evsPayloadDescriptions": {
        "127": {"bitrate": "5.9-13.2", "bandwidth": "nb-swb", "channelAwareReceive": 2}
      }
    }
  }
]`)
	profile, ok, err := parseIMSProfile(data, wfcTestCard{})
	if err != nil {
		t.Fatalf("parseIMSProfile() error = %v", err)
	}
	if !ok {
		t.Fatal("parseIMSProfile() ok = false, want true")
	}

	tests := []struct {
		name  string
		cfg   Config
		check func(t *testing.T, got Config)
	}{
		{
			name: "profile fills empty client ims and ike config",
			cfg: Config{
				Terminal: TerminalInfo{
					ID:              testIMEI,
					Vendor:          "Google",
					Model:           "Pixel 10 Pro",
					SoftwareVersion: "16",
					Build:           "BD1A.250702.001",
					Type:            "Smartphone",
					HardwareSKU:     "Pixel 10 Pro",
				},
				Access: VoWiFi(VoWiFiConfig{}),
			},
			check: func(t *testing.T, got Config) {
				t.Helper()
				tunnel := configTunnel(got)
				if gotEPDG := configEPDG(got); gotEPDG != "epdg.ims.2degrees.net.nz" {
					t.Fatalf("EPDG = %q, want profile ePDG", gotEPDG)
				}
				if tunnel.InitialPort != 501 || tunnel.NATTPort != 4501 || tunnel.SIPPort != 5070 {
					t.Fatalf("Tunnel ports = %d/%d/%d, want profile ports", tunnel.InitialPort, tunnel.NATTPort, tunnel.SIPPort)
				}
				if len(tunnel.DHGroups) != 2 || tunnel.DHGroups[0] != 2 || tunnel.DHGroups[1] != 14 {
					t.Fatalf("Tunnel.DHGroups = %v, want [2 14]", tunnel.DHGroups)
				}
				if tunnel.NATKeepaliveInterval != 60*time.Second {
					t.Fatalf("Tunnel.NATKeepaliveInterval = %v, want 60s", tunnel.NATKeepaliveInterval)
				}
				if tunnel.PCSCFIPv4ConfigAttribute != 16384 || tunnel.PCSCFIPv6ConfigAttribute != 16386 {
					t.Fatalf("Tunnel P-CSCF attrs = %d/%d, want 16384/16386", tunnel.PCSCFIPv4ConfigAttribute, tunnel.PCSCFIPv6ConfigAttribute)
				}
				if len(tunnel.IKERetransmitDelays) != 3 || tunnel.IKERetransmitDelays[2] != 4*time.Second {
					t.Fatalf("Tunnel.IKERetransmitDelays = %v, want [1s 2s 4s]", tunnel.IKERetransmitDelays)
				}
				if tunnel.IKESALifetime != 3900*time.Second || tunnel.IKESARekeyMargin != 300*time.Second {
					t.Fatalf("Tunnel IKE SA lifetime = %v/%v, want Pixel hard/soft timers 3900s/300s", tunnel.IKESALifetime, tunnel.IKESARekeyMargin)
				}
				if tunnel.ChildSALifetime != 1980*time.Second || tunnel.ChildSARekeyMargin != 180*time.Second {
					t.Fatalf("Tunnel Child SA lifetime = %v/%v, want Pixel hard/soft timers 1980s/180s", tunnel.ChildSALifetime, tunnel.ChildSARekeyMargin)
				}
				if !tunnel.AddKEToChildSARekey {
					t.Fatal("Tunnel AddKEToChildSARekey = false, want profile value")
				}
				if got.IMS.Transport != "tcp" || got.IMS.HomeDomain != "ims.mnc024.mcc530.3gppnetwork.org" {
					t.Fatalf("IMS transport/domain = %q/%q, want profile values", got.IMS.Transport, got.IMS.HomeDomain)
				}
				if got.IMS.PrivateIdentity != "" {
					t.Fatalf("PrivateIdentity = %q, want empty without explicit config", got.IMS.PrivateIdentity)
				}
				if got.IMS.PublicIdentity != "sip:530240123456789@ims.mnc024.mcc530.3gppnetwork.org" {
					t.Fatalf("PublicIdentity = %q, want profile value", got.IMS.PublicIdentity)
				}
				wantUserAgent := "PRD-IR92/15 Google/Pixel 10 Pro-BD1A.250702.001 device-type/Smartphone mno-custom/53024 imeisv/3567890123456700 op/2degrees sku/Pixel 10 Pro"
				if got.IMS.UserAgent != wantUserAgent || got.IMS.AccessNetworkInfo != "IEEE-802.11;utran-cell-id-3gpp=00000000" {
					t.Fatalf("IMS user agent/access = %q/%q, want profile values", got.IMS.UserAgent, got.IMS.AccessNetworkInfo)
				}
				if got.IMS.RegisterExpires != 7200*time.Second || got.IMS.SIPServerPort != 5080 {
					t.Fatalf("IMS expires/port = %v/%d, want profile values", got.IMS.RegisterExpires, got.IMS.SIPServerPort)
				}
				if got.IMS.RegistrationRetryBase != 120*time.Second || got.IMS.RegistrationRetryMax != 300*time.Second {
					t.Fatalf("IMS registration retry timers = %v/%v, want 120s/300s", got.IMS.RegistrationRetryBase, got.IMS.RegistrationRetryMax)
				}
				if got.IMS.SIPTimers.T1 != 3*time.Second || got.IMS.SIPTimers.TJ != 13*time.Second {
					t.Fatalf("IMS SIP timers T1/TJ = %v/%v, want profile values", got.IMS.SIPTimers.T1, got.IMS.SIPTimers.TJ)
				}
				if !slices.Equal(got.IMS.GeolocationPIDFRegister, []int{4, 2}) || !slices.Equal(got.IMS.Voice.GeolocationPIDFInvite, []int{4, 2}) {
					t.Fatalf("IMS PIDF config = register %v invite %v, want [4 2]", got.IMS.GeolocationPIDFRegister, got.IMS.Voice.GeolocationPIDFInvite)
				}
				if !got.IMS.UseTelURIForPIDFXML || !got.IMS.Voice.UseTelURIForPIDFXML {
					t.Fatalf("IMS use tel URI for PIDF = %t/%t, want true", got.IMS.UseTelURIForPIDFXML, got.IMS.Voice.UseTelURIForPIDFXML)
				}
				if !slices.Equal(got.IMS.Voice.PIDFShortCodes, []string{"211", "311"}) {
					t.Fatalf("IMS voice PIDF short codes = %v, want [211 311]", got.IMS.Voice.PIDFShortCodes)
				}
				if got.IMS.Voice.PTime != 20*time.Millisecond || got.IMS.Voice.MaxPTime != 240*time.Millisecond {
					t.Fatalf("IMS voice ptime/maxptime = %v/%v, want profile values", got.IMS.Voice.PTime, got.IMS.Voice.MaxPTime)
				}
				if !got.IMS.Voice.Preconditions {
					t.Fatalf("IMS voice preconditions = false, want profile value")
				}
				if !got.IMS.Voice.ReliableProvisional {
					t.Fatal("IMS voice reliable provisional = false, want profile value")
				}
				if !got.IMS.Voice.SessionTimer {
					t.Fatal("IMS voice session timer = false, want profile value")
				}
				if got.IMS.Voice.SessionExpires != 3600*time.Second || got.IMS.Voice.MinSessionExpires != 600*time.Second {
					t.Fatalf("IMS voice session timers = %v/%v, want profile values", got.IMS.Voice.SessionExpires, got.IMS.Voice.MinSessionExpires)
				}
				if got.IMS.Voice.SessionRefresher != "uas" {
					t.Fatalf("IMS voice session refresher = %q, want uas", got.IMS.Voice.SessionRefresher)
				}
				if got.IMS.Voice.MOCallRequestTimeout != 30*time.Second || got.IMS.Voice.RingbackTimeout != 180*time.Second || got.IMS.Voice.RingingTimeout != 45*time.Second {
					t.Fatalf("IMS voice timers = %v/%v/%v, want profile values", got.IMS.Voice.MOCallRequestTimeout, got.IMS.Voice.RingbackTimeout, got.IMS.Voice.RingingTimeout)
				}
				if got.IMS.Voice.AudioASBandwidthKbps != 49 {
					t.Fatalf("IMS voice AudioASBandwidthKbps = %d, want 49", got.IMS.Voice.AudioASBandwidthKbps)
				}
				if *got.IMS.Voice.RTPInactivityTimeout != 20*time.Second || *got.IMS.Voice.RTCPInactivityTimeout != 21*time.Second {
					t.Fatalf("IMS voice inactivity timers = %v/%v, want profile values", *got.IMS.Voice.RTPInactivityTimeout, *got.IMS.Voice.RTCPInactivityTimeout)
				}
				wantReasons := []imsvoice.AudioInactivityCallEndReason{
					imsvoice.AudioInactivityRTCPOnHold,
					imsvoice.AudioInactivityRTCPOnConnected,
					imsvoice.AudioInactivityRTPOnConnected,
				}
				if !slices.Equal(got.IMS.Voice.AudioInactivityCallEndReasons, wantReasons) {
					t.Fatalf("IMS voice audio inactivity call end reasons = %v, want %v", got.IMS.Voice.AudioInactivityCallEndReasons, wantReasons)
				}
				if got.IMS.Voice.LocalRTPPortMin != 41000 || got.IMS.Voice.LocalRTPPortMax != 41020 {
					t.Fatalf("IMS voice ports = %d/%d, want profile values", got.IMS.Voice.LocalRTPPortMin, got.IMS.Voice.LocalRTPPortMax)
				}
				if len(got.IMS.Voice.Codecs) != 4 || got.IMS.Voice.Codecs[0].Name != imsvoice.CodecEVS || got.IMS.Voice.Codecs[0].PayloadTypes[0] != 127 {
					t.Fatalf("IMS voice codecs = %+v, want profile codecs", got.IMS.Voice.Codecs)
				}
				evs := got.IMS.Voice.Codecs[0]
				if evs.Bitrate != "5.9-13.2" || evs.Bandwidth != "nb-swb" || evs.ChAwRecv == nil || *evs.ChAwRecv != 2 {
					t.Fatalf("IMS voice EVS codec = %+v, want Pixel EVS payload description", evs)
				}
			},
		},
		{
			name: "explicit config overrides profile",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access: VoWiFi(VoWiFiConfig{
					EPDG:   "epdg.example.com",
					Tunnel: tunnelConfigForWFCOverride(),
				}),
				IMS: IMSConfig{
					Transport:             "udp",
					HomeDomain:            "ims.example.com",
					PrivateIdentity:       "private@example.com",
					PublicIdentity:        "sip:public@example.com",
					UserAgent:             "explicit-agent",
					RegisterExpires:       30 * time.Second,
					RegistrationRetryBase: 11 * time.Second,
					RegistrationRetryMax:  22 * time.Second,
					SIPServerPort:         5090,
					Voice: imsvoice.Config{
						LocalRTPPortMin: 42000,
						LocalRTPPortMax: 42010,
						AudioInactivityCallEndReasons: []imsvoice.AudioInactivityCallEndReason{
							imsvoice.AudioInactivityRTPOnConnected,
						},
						Codecs: []imsvoice.AudioCodecConfig{
							{Name: imsvoice.CodecEVS, PayloadTypes: []int{110}, ClockRate: 16000},
						},
					},
				},
			},
			check: func(t *testing.T, got Config) {
				t.Helper()
				tunnel := configTunnel(got)
				if gotEPDG := configEPDG(got); gotEPDG != "epdg.example.com" {
					t.Fatalf("EPDG = %q, want explicit value", gotEPDG)
				}
				if tunnel.InitialPort != 502 || tunnel.SIPPort != 5091 {
					t.Fatalf("Tunnel ports = %d/%d, want explicit values", tunnel.InitialPort, tunnel.SIPPort)
				}
				if tunnel.PCSCFIPv4ConfigAttribute != 16384 || tunnel.PCSCFIPv6ConfigAttribute != 16386 {
					t.Fatalf("Tunnel P-CSCF attrs = %d/%d, want profile values", tunnel.PCSCFIPv4ConfigAttribute, tunnel.PCSCFIPv6ConfigAttribute)
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
				if got.IMS.RegistrationRetryBase != 11*time.Second || got.IMS.RegistrationRetryMax != 22*time.Second {
					t.Fatalf("IMS registration retry timers = %v/%v, want explicit values", got.IMS.RegistrationRetryBase, got.IMS.RegistrationRetryMax)
				}
				if got.IMS.Voice.LocalRTPPortMin != 42000 || got.IMS.Voice.LocalRTPPortMax != 42010 {
					t.Fatalf("IMS voice ports = %d/%d, want explicit values", got.IMS.Voice.LocalRTPPortMin, got.IMS.Voice.LocalRTPPortMax)
				}
				wantReasons := []imsvoice.AudioInactivityCallEndReason{imsvoice.AudioInactivityRTPOnConnected}
				if !slices.Equal(got.IMS.Voice.AudioInactivityCallEndReasons, wantReasons) {
					t.Fatalf("IMS voice audio inactivity call end reasons = %v, want explicit value %v", got.IMS.Voice.AudioInactivityCallEndReasons, wantReasons)
				}
				if len(got.IMS.Voice.Codecs) != 1 || got.IMS.Voice.Codecs[0].Name != imsvoice.CodecEVS {
					t.Fatalf("IMS voice codecs = %+v, want explicit codecs", got.IMS.Voice.Codecs)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.withIMSProfile(profile, wfcTestCard{})
			got = withTestIPSecAlgorithms(got)
			imsCfg, err := got.normalizedIMS()
			if err != nil {
				t.Fatalf("normalizedIMS() error = %v", err)
			}
			got.IMS = imsCfg
			tunnelCfg, err := got.normalizedTunnel()
			if err != nil {
				t.Fatalf("normalizedTunnel() error = %v", err)
			}
			got.Access.VoWiFi.Tunnel = tunnelCfg
			tt.check(t, got)
		})
	}
}

func TestConfigNormalizedWFCProfileMapsIMSRegistrationRetryTimers(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantBase time.Duration
		wantMax  time.Duration
	}{
		{
			name: "profile durations",
			body: `
    "imsRegistrationRetryBase": "120s",
    "imsRegistrationRetryMax": "300s"`,
			wantBase: 120 * time.Second,
			wantMax:  300 * time.Second,
		},
		{
			name: "alternate profile durations",
			body: `
    "imsRegistrationRetryBase": "45s",
    "imsRegistrationRetryMax": "90s"`,
			wantBase: 45 * time.Second,
			wantMax:  90 * time.Second,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(`[
  {
    "mcc": "530",
    "mnc": "24",
    "epdg": "epdg.ims.2degrees.net.nz",` + tt.body + `
  }
]`)
			profile, ok, err := parseIMSProfile(data, wfcTestCard{})
			if err != nil {
				t.Fatalf("parseIMSProfile() error = %v", err)
			}
			if !ok {
				t.Fatal("parseIMSProfile() ok = false, want true")
			}

			got := Config{Terminal: TerminalInfo{ID: testIMEI}}.withIMSProfile(profile, wfcTestCard{})
			got = withTestIPSecAlgorithms(got)
			imsCfg, err := got.normalizedIMS()
			if err != nil {
				t.Fatalf("normalizedIMS() error = %v", err)
			}
			if imsCfg.RegistrationRetryBase != tt.wantBase || imsCfg.RegistrationRetryMax != tt.wantMax {
				t.Fatalf("registration retry timers = %v/%v, want %v/%v", imsCfg.RegistrationRetryBase, imsCfg.RegistrationRetryMax, tt.wantBase, tt.wantMax)
			}
		})
	}
}

func TestIMSProfileMapsIPSecAlgorithms(t *testing.T) {
	o2LegacyMD5 := []string{"hmac-md5-96"}
	tests := []struct {
		name           string
		card           plmnWFCCard
		wantIntegrity  []string
		wantEncryption []string
	}{
		{
			name:           "Telefonica GB uses Samsung explicit capability",
			card:           plmnWFCCard{mcc: "234", mnc: "10", mncLength: 2},
			wantIntegrity:  o2LegacyMD5,
			wantEncryption: []string{"null"},
		},
		{
			name:           "Telefonica GB prepaid uses Samsung explicit capability",
			card:           plmnWFCCard{mcc: "234", mnc: "10", mncLength: 2, gid1: "61"},
			wantIntegrity:  o2LegacyMD5,
			wantEncryption: []string{"null"},
		},
		{
			name:           "giffgaff Pixel GID prefix uses Telefonica capability",
			card:           plmnWFCCard{mcc: "234", mnc: "10", mncLength: 2, gid1: "508FFFFFFFFF4D564E4520202020202020202020"},
			wantIntegrity:  o2LegacyMD5,
			wantEncryption: []string{"null"},
		},
		{
			name:           "Pixel ESN GB requires AES CBC",
			card:           plmnWFCCard{mcc: "234", mnc: "71", mncLength: 2},
			wantIntegrity:  []string{"hmac-sha-1-96"},
			wantEncryption: []string{"aes-cbc"},
		},
		{
			name:           "Samsung TDC Denmark uses MD5 with AES CBC",
			card:           plmnWFCCard{mcc: "238", mnc: "01", mncLength: 2},
			wantIntegrity:  []string{"hmac-md5-96"},
			wantEncryption: []string{"aes-cbc"},
		},
		{
			name:           "Pixel Vodafone Germany allows null and AES CBC",
			card:           plmnWFCCard{mcc: "262", mnc: "02", mncLength: 2},
			wantIntegrity:  []string{"hmac-sha-1-96"},
			wantEncryption: []string{"null", "aes-cbc"},
		},
		{
			name:           "Vodafone UK inherits Samsung default capability",
			card:           plmnWFCCard{mcc: "234", mnc: "15", mncLength: 2},
			wantIntegrity:  []string{"hmac-md5-96", "hmac-sha-1-96"},
			wantEncryption: []string{"null", "aes-cbc"},
		},
		{
			name:           "Samsung Lebara UK adds standardized SHA2 capability",
			card:           plmnWFCCard{mcc: "234", mnc: "87", mncLength: 2, spn: "Lebara"},
			wantIntegrity:  []string{"hmac-sha-1-96", "hmac-sha2-256-128"},
			wantEncryption: []string{"null", "aes-cbc"},
		},
		{
			name:           "Samsung Digi Portugal adds standardized SHA2 capability",
			card:           plmnWFCCard{mcc: "268", mnc: "02", mncLength: 2},
			wantIntegrity:  []string{"hmac-sha-1-96", "hmac-sha2-256-128"},
			wantEncryption: []string{"null", "aes-cbc"},
		},
		{
			name:           "Samsung T2 Slovenia adds standardized SHA2 capability",
			card:           plmnWFCCard{mcc: "293", mnc: "64", mncLength: 2},
			wantIntegrity:  []string{"hmac-sha-1-96", "hmac-sha2-256-128"},
			wantEncryption: []string{"null", "aes-cbc"},
		},
		{
			name:           "Samsung SFR Reunion adds standardized SHA2 capability",
			card:           plmnWFCCard{mcc: "647", mnc: "10", mncLength: 2},
			wantIntegrity:  []string{"hmac-md5-96", "hmac-sha-1-96", "hmac-sha2-256-128"},
			wantEncryption: []string{"null", "aes-cbc"},
		},
		{
			name:           "baseline profile uses conservative algorithms",
			card:           plmnWFCCard{mcc: "001", mnc: "01", mncLength: 2},
			wantIntegrity:  []string{"hmac-sha-1-96"},
			wantEncryption: []string{"null", "aes-cbc"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, ok, err := parseIMSProfile(embeddedIMSConfig, tt.card)
			if err != nil {
				t.Fatalf("parseIMSProfile() error = %v", err)
			}
			if !ok {
				t.Fatal("parseIMSProfile() ok = false, want true")
			}
			got := Config{Terminal: TerminalInfo{ID: testIMEI}}.withIMSProfile(profile, tt.card)
			if !slices.Equal(got.IMS.IPSecIntegrityAlgorithms, tt.wantIntegrity) {
				t.Fatalf("IPsec integrity algorithms = %v, want %v", got.IMS.IPSecIntegrityAlgorithms, tt.wantIntegrity)
			}
			if !slices.Equal(got.IMS.IPSecEncryptionAlgorithms, tt.wantEncryption) {
				t.Fatalf("IPsec encryption algorithms = %v, want %v", got.IMS.IPSecEncryptionAlgorithms, tt.wantEncryption)
			}
		})
	}
}

func TestIMSProfileMapsChinaCarrierIPSecCapabilities(t *testing.T) {
	tests := []struct {
		name           string
		card           plmnWFCCard
		wantIntegrity  []string
		wantEncryption []string
		wantModes      []string
	}{
		{
			name:           "China Unicom legacy SBC",
			card:           plmnWFCCard{mcc: "460", mnc: "01", mncLength: 2},
			wantIntegrity:  []string{"hmac-sha-1-96"},
			wantEncryption: []string{"null", "aes-cbc"},
			wantModes:      []string{"trans"},
		},
		{
			name:           "China Telecom keeps expanded capabilities",
			card:           plmnWFCCard{mcc: "460", mnc: "11", mncLength: 2},
			wantIntegrity:  []string{"hmac-md5-96", "hmac-sha-1-96"},
			wantEncryption: []string{"null", "aes-cbc"},
			wantModes:      []string{"trans", "UDP-enc-tun"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, ok, err := parseIMSProfile(embeddedIMSConfig, tt.card)
			if err != nil {
				t.Fatalf("parseIMSProfile() error = %v", err)
			}
			if !ok {
				t.Fatal("parseIMSProfile() ok = false, want true")
			}
			got := Config{Terminal: TerminalInfo{ID: testIMEI}}.withIMSProfile(profile, tt.card)
			if !slices.Equal(got.IMS.IPSecIntegrityAlgorithms, tt.wantIntegrity) {
				t.Fatalf("IPsec integrity algorithms = %v, want %v", got.IMS.IPSecIntegrityAlgorithms, tt.wantIntegrity)
			}
			if !slices.Equal(got.IMS.IPSecEncryptionAlgorithms, tt.wantEncryption) {
				t.Fatalf("IPsec encryption algorithms = %v, want %v", got.IMS.IPSecEncryptionAlgorithms, tt.wantEncryption)
			}
			if !slices.Equal(got.IMS.IPSecModes, tt.wantModes) {
				t.Fatalf("IPsec modes = %v, want %v", got.IMS.IPSecModes, tt.wantModes)
			}
		})
	}
}

func TestIMSProfileMapsO2SecurityModes(t *testing.T) {
	tests := []struct {
		name string
		card plmnWFCCard
	}{
		{name: "O2 postpaid", card: plmnWFCCard{mcc: "234", mnc: "10", mncLength: 2}},
		{name: "O2 prepaid", card: plmnWFCCard{mcc: "234", mnc: "10", mncLength: 2, gid1: "61"}},
		{name: "giffgaff", card: plmnWFCCard{mcc: "234", mnc: "10", mncLength: 2, spn: "GIFFGAFF"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, ok, err := parseIMSProfile(embeddedIMSConfig, tt.card)
			if err != nil {
				t.Fatalf("parseIMSProfile() error = %v", err)
			}
			if !ok {
				t.Fatal("parseIMSProfile() ok = false, want true")
			}
			got := Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoLTE(lte.Config{}),
				IMS:      IMSConfig{IPSecModes: []string{"UDP-enc-tun"}},
			}.withIMSProfile(profile, tt.card)
			if got.IMS.Transport != "tcp" {
				t.Fatalf("IMS transport = %q, want tcp", got.IMS.Transport)
			}
			if !slices.Equal(got.IMS.IPSecModes, []string{"trans"}) {
				t.Fatalf("IPsec modes = %v, want [trans]", got.IMS.IPSecModes)
			}
		})
	}
}

func TestIMSProfileDoesNotTieMD5ToTransportMode(t *testing.T) {
	card := plmnWFCCard{mcc: "238", mnc: "01", mncLength: 2}
	profile, ok, err := parseIMSProfile(embeddedIMSConfig, card)
	if err != nil {
		t.Fatalf("parseIMSProfile() error = %v", err)
	}
	if !ok {
		t.Fatal("parseIMSProfile() ok = false, want true")
	}
	cfg := Config{
		Terminal: TerminalInfo{ID: testIMEI},
		IMS:      IMSConfig{IPSecModes: []string{"trans"}},
	}.withIMSProfile(profile, card)
	normalized, err := cfg.IMS.Normalized()
	if err != nil {
		t.Fatalf("IMS.Normalized() error = %v", err)
	}
	if !slices.Equal(normalized.IPSecIntegrityAlgorithms, []string{"hmac-md5-96"}) {
		t.Fatalf("IPsec integrity algorithms = %v, want [hmac-md5-96]", normalized.IPSecIntegrityAlgorithms)
	}
	if !slices.Equal(normalized.IPSecModes, []string{"trans", "UDP-enc-tun"}) {
		t.Fatalf("IPsec modes = %v, want [trans UDP-enc-tun]", normalized.IPSecModes)
	}
}

func TestEmbeddedIMSProfilesHaveIPSecAlgorithms(t *testing.T) {
	var profiles []imsProfile
	if err := json.Unmarshal(embeddedIMSConfig, &profiles); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	for i, profile := range profiles {
		t.Run(profile.MCC+"-"+profile.MNC+"-"+profile.GID1+"-"+profile.IMSIPrefix, func(t *testing.T) {
			if len(profile.IMSIPSecIntegrityAlgorithms) == 0 {
				t.Fatalf("profile[%d] IPsec integrity algorithms are empty", i)
			}
			if len(profile.IMSIPSecEncryptionAlgorithms) == 0 {
				t.Fatalf("profile[%d] IPsec encryption algorithms are empty", i)
			}
			if len(profile.IMSIPSecModes) == 0 {
				t.Fatalf("profile[%d] IPsec modes are empty", i)
			}
			normalized, err := (IMSConfig{
				IPSecIntegrityAlgorithms:  profile.IMSIPSecIntegrityAlgorithms,
				IPSecEncryptionAlgorithms: profile.IMSIPSecEncryptionAlgorithms,
				IPSecModes:                profile.IMSIPSecModes,
			}).Normalized()
			if err != nil {
				t.Fatalf("profile[%d] IPsec algorithms: %v", i, err)
			}
			if !slices.Equal(normalized.IPSecIntegrityAlgorithms, profile.IMSIPSecIntegrityAlgorithms) {
				t.Fatalf("profile[%d] IPsec integrity algorithms normalize to %v", i, normalized.IPSecIntegrityAlgorithms)
			}
			if !slices.Equal(normalized.IPSecEncryptionAlgorithms, profile.IMSIPSecEncryptionAlgorithms) {
				t.Fatalf("profile[%d] IPsec encryption algorithms normalize to %v", i, normalized.IPSecEncryptionAlgorithms)
			}
			if !slices.Equal(normalized.IPSecModes, profile.IMSIPSecModes) {
				t.Fatalf("profile[%d] IPsec modes normalize to %v", i, normalized.IPSecModes)
			}
		})
	}
}

func TestEmbeddedIMSProfilesHaveSupportedTunnelConfig(t *testing.T) {
	var profiles []imsProfile
	if err := json.Unmarshal(embeddedIMSConfig, &profiles); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	for i, profile := range profiles {
		t.Run(profile.MCC+"-"+profile.MNC+"-"+profile.GID1+"-"+profile.IMSIPrefix, func(t *testing.T) {
			cfg := Config{Access: VoWiFi(VoWiFiConfig{})}.withIMSProfile(profile, wfcTestCard{})
			if _, err := cfg.normalizedTunnel(); err != nil {
				t.Fatalf("profile[%d] tunnel config: %v", i, err)
			}
		})
	}
}

func TestConfigNormalizedWFCProfileMapsSMSDeliveryReports(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantFlag bool
	}{
		{
			name:     "carrier enables status reports",
			body:     `"enableSMSDeliveryReports": true`,
			wantFlag: true,
		},
		{
			name: "carrier disables status reports",
			body: `"enableSMSDeliveryReports": false`,
		},
		{
			name:     "missing carrier setting uses explicit zero value",
			wantFlag: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := tt.body
			if body != "" {
				body = "," + body
			}
			data := []byte(`[
  {
    "mcc": "530",
    "mnc": "24",
    "epdg": "epdg.ims.2degrees.net.nz"` + body + `
  }
]`)
			profile, ok, err := parseIMSProfile(data, wfcTestCard{})
			if err != nil {
				t.Fatalf("parseIMSProfile() error = %v", err)
			}
			if !ok {
				t.Fatal("parseIMSProfile() ok = false, want true")
			}

			got := Config{Terminal: TerminalInfo{ID: testIMEI}}.withIMSProfile(profile, wfcTestCard{})
			got = withTestIPSecAlgorithms(got)
			_, err = got.normalizedIMS()
			if err != nil {
				t.Fatalf("normalizedIMS() error = %v", err)
			}
			if got.smsRequestStatusReport != tt.wantFlag {
				t.Fatalf("smsRequestStatusReport = %t, want %t", got.smsRequestStatusReport, tt.wantFlag)
			}
		})
	}
}

func TestConfigNormalizedWFCProfileUsesTunnelTimers(t *testing.T) {
	data := []byte(`[
  {
    "mcc": "530",
    "mnc": "24",
    "epdg": "epdg.ims.2degrees.net.nz",
    "livenessTimeout": "90s",
    "natKeepaliveInterval": "30s",
    "ikeSARekeySoftTime": "86340s",
    "ikeSARekeyHardTime": "86400s",
    "childSARekeySoftTime": "3000s",
    "childSARekeyHardTime": "3600s",
    "addKEToChildSARekey": true
  }
]`)
	profile, ok, err := parseIMSProfile(data, wfcTestCard{})
	if err != nil {
		t.Fatalf("parseIMSProfile() error = %v", err)
	}
	if !ok {
		t.Fatal("parseIMSProfile() ok = false, want true")
	}

	got := Config{Terminal: TerminalInfo{ID: testIMEI}, Access: VoWiFi(VoWiFiConfig{})}.withIMSProfile(profile, wfcTestCard{})
	tunnelCfg, err := got.normalizedTunnel()
	if err != nil {
		t.Fatalf("normalizedTunnel() error = %v", err)
	}
	if tunnelCfg.LivenessTimeout != 90*time.Second {
		t.Fatalf("LivenessTimeout = %v, want 90s", tunnelCfg.LivenessTimeout)
	}
	if tunnelCfg.NATKeepaliveInterval != 30*time.Second {
		t.Fatalf("NATKeepaliveInterval = %v, want 30s", tunnelCfg.NATKeepaliveInterval)
	}
	if tunnelCfg.IKESALifetime != 86400*time.Second || tunnelCfg.IKESARekeyMargin != 60*time.Second {
		t.Fatalf("IKE SA lifetime = %v/%v, want clamped WFC 86400s/60s", tunnelCfg.IKESALifetime, tunnelCfg.IKESARekeyMargin)
	}
	if tunnelCfg.ChildSALifetime != 3600*time.Second || tunnelCfg.ChildSARekeyMargin != 600*time.Second {
		t.Fatalf("Child SA lifetime = %v/%v, want 3600s/600s", tunnelCfg.ChildSALifetime, tunnelCfg.ChildSARekeyMargin)
	}
	if !tunnelCfg.AddKEToChildSARekey {
		t.Fatal("AddKEToChildSARekey = false, want true")
	}
}

func TestSALifetimeFromIMSProfile(t *testing.T) {
	duration := func(value string) imsProfileDuration {
		t.Helper()
		got, err := time.ParseDuration(value)
		if err != nil {
			t.Fatalf("time.ParseDuration(%q) error = %v", value, err)
		}
		return imsProfileDuration{Duration: got}
	}

	tests := []struct {
		name       string
		lifetime   imsProfileDuration
		soft       imsProfileDuration
		hard       imsProfileDuration
		legacySoft imsProfileDuration
		wantLife   time.Duration
		wantMargin time.Duration
	}{
		{
			name:       "modern timer pair overrides configured lifetime",
			lifetime:   duration("86400s"),
			soft:       duration("3000s"),
			hard:       duration("86500s"),
			wantLife:   86500 * time.Second,
			wantMargin: 83500 * time.Second,
		},
		{
			name:       "modern timer pair overrides legacy rekey time",
			lifetime:   duration("43200s"),
			soft:       duration("86400s"),
			hard:       duration("86500s"),
			legacySoft: duration("14400s"),
			wantLife:   86500 * time.Second,
			wantMargin: 100 * time.Second,
		},
		{
			name:       "legacy timer complements configured lifetime",
			lifetime:   duration("64800s"),
			legacySoft: duration("60000s"),
			wantLife:   64800 * time.Second,
			wantMargin: 4800 * time.Second,
		},
		{
			name:       "hard rekey timer is fallback lifetime",
			soft:       duration("86340s"),
			hard:       duration("86400s"),
			wantLife:   86400 * time.Second,
			wantMargin: 60 * time.Second,
		},
		{
			name:       "modern timer pair wins over legacy soft",
			soft:       duration("86400s"),
			hard:       duration("86500s"),
			legacySoft: duration("64800s"),
			wantLife:   86500 * time.Second,
			wantMargin: 100 * time.Second,
		},
		{
			name:       "modern short timer pair wins over legacy soft",
			soft:       duration("3000s"),
			hard:       duration("3600s"),
			legacySoft: duration("64800s"),
			wantLife:   3600 * time.Second,
			wantMargin: 600 * time.Second,
		},
		{
			name:       "legacy soft only derives hard lifetime",
			legacySoft: duration("3600s"),
			wantLife:   3900 * time.Second,
			wantMargin: 300 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLife, gotMargin := saLifetimeFromIMSProfile(tt.lifetime, tt.soft, tt.hard, tt.legacySoft)
			if gotLife != tt.wantLife || gotMargin != tt.wantMargin {
				t.Fatalf("saLifetimeFromIMSProfile() = %v/%v, want %v/%v", gotLife, gotMargin, tt.wantLife, tt.wantMargin)
			}
		})
	}
}

func TestConfigNormalizedWFCProfileUsesDefaultTunnelTimersWhenAbsent(t *testing.T) {
	data := []byte(`[
  {
    "mcc": "530",
    "mnc": "24",
    "epdg": "epdg.ims.2degrees.net.nz"
  }
]`)
	profile, ok, err := parseIMSProfile(data, wfcTestCard{})
	if err != nil {
		t.Fatalf("parseIMSProfile() error = %v", err)
	}
	if !ok {
		t.Fatal("parseIMSProfile() ok = false, want true")
	}

	got := Config{Terminal: TerminalInfo{ID: testIMEI}, Access: VoWiFi(VoWiFiConfig{})}.withIMSProfile(profile, wfcTestCard{})
	tunnelCfg, err := got.normalizedTunnel()
	if err != nil {
		t.Fatalf("normalizedTunnel() error = %v", err)
	}
	if tunnelCfg.LivenessTimeout != 120*time.Second {
		t.Fatalf("LivenessTimeout = %v, want WFC default 120s", tunnelCfg.LivenessTimeout)
	}
	if tunnelCfg.NATKeepaliveInterval != 20*time.Second {
		t.Fatalf("NATKeepaliveInterval = %v, want WFC default 20s", tunnelCfg.NATKeepaliveInterval)
	}
	if tunnelCfg.IKESALifetime != 14400*time.Second || tunnelCfg.IKESARekeyMargin != 7200*time.Second {
		t.Fatalf("IKE SA lifetime = %v/%v, want WFC defaults 14400s/7200s", tunnelCfg.IKESALifetime, tunnelCfg.IKESARekeyMargin)
	}
	if tunnelCfg.ChildSALifetime != 7200*time.Second || tunnelCfg.ChildSARekeyMargin != 3600*time.Second {
		t.Fatalf("Child SA lifetime = %v/%v, want WFC defaults 7200s/3600s", tunnelCfg.ChildSALifetime, tunnelCfg.ChildSARekeyMargin)
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
			profile, ok, err := parseIMSProfile(data, tt.card)
			if err != nil {
				t.Fatalf("parseIMSProfile() error = %v", err)
			}
			if !ok {
				t.Fatal("parseIMSProfile() ok = false, want true")
			}
			if profile.EPDG != tt.wantEPDG {
				t.Fatalf("EPDG = %q, want %q", profile.EPDG, tt.wantEPDG)
			}
		})
	}
}

func TestParseIMSProfileSelectorSpecificity(t *testing.T) {
	data := []byte(`[
  {"mcc":"310","mnc":"260","epdg":"base"},
  {"mcc":"310","mnc":"260","imsiPrefix":"31026012","epdg":"imsi-short"},
  {"mcc":"310","mnc":"260","imsiPrefix":"3102601234","epdg":"imsi-long"},
  {"mcc":"310","mnc":"260","imsiPrefix":"310260x7","epdg":"imsi-wildcard"},
  {"mcc":"310","mnc":"260","imsiPrefix":"31026097","epdg":"imsi-exact"},
	{"mcc":"310","mnc":"260","iccidPrefix":"8901260","epdg":"iccid"},
	{"mcc":"310","mnc":"260","spn":"MVNO","epdg":"spn"},
  {"mcc":"310","mnc":"260","gid1":"ABCD","epdg":"gid"},
	{"mcc":"310","mnc":"260","gid2":"1234","epdg":"gid2"},
	{"mcc":"310","mnc":"260","gid1":"ABCD12","epdg":"long-gid"},
  {"mcc":"310","mnc":"260","imsiPrefix":"31026012","gid1":"ABCD","epdg":"imsi-gid"}
]`)
	tests := []struct {
		name     string
		card     plmnWFCCard
		wantEPDG string
	}{
		{name: "base", card: plmnWFCCard{mcc: "310", mnc: "260", mncLength: 3, imsi: "310260999999999"}, wantEPDG: "base"},
		{name: "longest IMSI prefix", card: plmnWFCCard{mcc: "310", mnc: "260", mncLength: 3, imsi: "310260123456789"}, wantEPDG: "imsi-long"},
		{name: "IMSI wildcard", card: plmnWFCCard{mcc: "310", mnc: "260", mncLength: 3, imsi: "310260877654321"}, wantEPDG: "imsi-wildcard"},
		{name: "exact IMSI beats wildcard", card: plmnWFCCard{mcc: "310", mnc: "260", mncLength: 3, imsi: "310260977654321"}, wantEPDG: "imsi-exact"},
		{name: "ICCID", card: plmnWFCCard{mcc: "310", mnc: "260", mncLength: 3, imsi: "310260999999999", iccid: "8901 2609 9999"}, wantEPDG: "iccid"},
		{name: "SPN ignores case and spaces", card: plmnWFCCard{mcc: "310", mnc: "260", mncLength: 3, imsi: "310260999999999", spn: " mvno "}, wantEPDG: "spn"},
		{name: "GID2", card: plmnWFCCard{mcc: "310", mnc: "260", mncLength: 3, imsi: "310260999999999", gid2: "1234FFFF"}, wantEPDG: "gid2"},
		{name: "longest GID", card: plmnWFCCard{mcc: "310", mnc: "260", mncLength: 3, imsi: "310260999999999", gid1: "ABCD12FFFF"}, wantEPDG: "long-gid"},
		{name: "IMSI and GID", card: plmnWFCCard{mcc: "310", mnc: "260", mncLength: 3, imsi: "310260123456789", gid1: "abcdffff"}, wantEPDG: "imsi-gid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, ok, err := parseIMSProfile(data, tt.card)
			if err != nil {
				t.Fatalf("parseIMSProfile() error = %v", err)
			}
			if !ok {
				t.Fatal("parseIMSProfile() ok = false, want true")
			}
			if profile.EPDG != tt.wantEPDG {
				t.Fatalf("EPDG = %q, want %q", profile.EPDG, tt.wantEPDG)
			}
		})
	}
}

func TestParseIMSProfileOptionalCardMetadata(t *testing.T) {
	data := []byte(`[
  {"mcc":"001","mnc":"01","epdg":"base"},
  {"mcc":"001","mnc":"01","spn":"MVNO","epdg":"spn"}
]`)
	tests := []struct {
		name     string
		card     Card
		wantEPDG string
	}{
		{name: "base card remains compatible", card: minimalProfileCard{}, wantEPDG: "base"},
		{name: "optional metadata remains supported", card: plmnWFCCard{mcc: "001", mnc: "01", mncLength: 2, spn: "MVNO"}, wantEPDG: "spn"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, ok, err := parseIMSProfile(data, tt.card)
			if err != nil {
				t.Fatalf("parseIMSProfile() error = %v", err)
			}
			if !ok {
				t.Fatal("parseIMSProfile() ok = false, want true")
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
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoWiFi(VoWiFiConfig{}),
			},
			card:     wfcTestCard{},
			wantEPDG: "epdg.ims.2degrees.net.nz",
		},
		{
			name: "explicit epdg still wins",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoWiFi(VoWiFiConfig{EPDG: "epdg.example.com"}),
			},
			card:     wfcTestCard{},
			wantEPDG: "epdg.example.com",
		},
		{
			name: "embedded two digit mnc profile matches padded card mnc",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoWiFi(VoWiFiConfig{}),
			},
			card:     paddedTwoDigitMNCCard{},
			wantEPDG: "epdg.epc.mnc000.mcc454.pub.3gppnetwork.org",
		},
		{
			name: "embedded gid profile wins over base profile",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoWiFi(VoWiFiConfig{}),
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
			if gotEPDG := configEPDG(got); gotEPDG != tt.wantEPDG {
				t.Fatalf("EPDG = %q, want %q", gotEPDG, tt.wantEPDG)
			}
		})
	}
}

func TestConfigNormalizedUsesEmbeddedLivenessTimeout(t *testing.T) {
	cfg := Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Access:   VoWiFi(VoWiFiConfig{}),
	}
	got, err := cfg.normalized(plmnWFCCard{mcc: "505", mnc: "03", mncLength: 2})
	if err != nil {
		t.Fatalf("normalized() error = %v", err)
	}
	if gotLivenessTimeout := configTunnel(got).LivenessTimeout; gotLivenessTimeout != 90*time.Second {
		t.Fatalf("Tunnel.LivenessTimeout = %v, want Vodafone AU liveness timeout 90s", gotLivenessTimeout)
	}
}

func TestEmbeddedWFCProfilesDeclareLivenessTimeout(t *testing.T) {
	var profiles []imsProfile
	if err := json.Unmarshal(embeddedIMSConfig, &profiles); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	tests := make([]struct {
		name    string
		profile imsProfile
	}, 0, len(profiles))
	for _, profile := range profiles {
		tests = append(tests, struct {
			name    string
			profile imsProfile
		}{
			name:    profile.MCC + "-" + profile.MNC + "-" + profile.GID1,
			profile: profile,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.profile.LivenessTimeout.Duration == 0 {
				t.Fatal("livenessTimeout is missing")
			}
		})
	}
}

func TestEmbeddedWFCConfigGiffgaffSelectors(t *testing.T) {
	const wantEPDG = "epdg.epc.mnc010.mcc234.pub.3gppnetwork.org"
	tests := []struct {
		name     string
		card     plmnWFCCard
		wantGID1 string
		wantSPN  string
	}{
		{
			name:     "GID1 prefix selects giffgaff",
			card:     plmnWFCCard{mcc: "234", mnc: "10", mncLength: 2, gid1: "508FFFFF"},
			wantGID1: "50",
		},
		{
			name:    "SPN selects giffgaff",
			card:    plmnWFCCard{mcc: "234", mnc: "10", mncLength: 2, spn: " giffgaff "},
			wantSPN: "GIFFGAFF",
		},
		{
			name: "neighboring GID1 does not select giffgaff",
			card: plmnWFCCard{mcc: "234", mnc: "10", mncLength: 2, gid1: "517FFFFF"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, ok, err := parseIMSProfile(embeddedIMSConfig, tt.card)
			if err != nil {
				t.Fatalf("parseIMSProfile() error = %v", err)
			}
			if !ok {
				t.Fatal("parseIMSProfile() ok = false, want true")
			}
			if profile.GID1 != tt.wantGID1 {
				t.Fatalf("GID1 selector = %q, want %q", profile.GID1, tt.wantGID1)
			}
			if profile.SPN != tt.wantSPN {
				t.Fatalf("SPN selector = %q, want %q", profile.SPN, tt.wantSPN)
			}
			if profile.EPDG != wantEPDG {
				t.Fatalf("EPDG = %q, want %q", profile.EPDG, wantEPDG)
			}
		})
	}
}

func TestEmbeddedWFCConfigPixelEPDG(t *testing.T) {
	tests := []struct {
		name     string
		card     plmnWFCCard
		wantEPDG string
	}{
		{
			name:     "csl hk base uses standard plmn epdg",
			card:     plmnWFCCard{mcc: "454", mnc: "000", mncLength: 2},
			wantEPDG: "epdg.epc.mnc000.mcc454.pub.3gppnetwork.org",
		},
		{
			name:     "truphone hk gid keeps pixel override",
			card:     plmnWFCCard{mcc: "454", mnc: "000", mncLength: 2, gid1: "547275554B3030656EFFFF"},
			wantEPDG: "epdg.eps.truphone.net",
		},
		{
			name:     "austria 23210 base uses standard plmn epdg",
			card:     plmnWFCCard{mcc: "232", mnc: "10", mncLength: 2},
			wantEPDG: "epdg.epc.mnc010.mcc232.pub.3gppnetwork.org",
		},
		{
			name:     "att mexico base uses pixel static epdg",
			card:     plmnWFCCard{mcc: "334", mnc: "050", mncLength: 3},
			wantEPDG: "epdg.epc.mnc050.mcc334.pub.3gppnetwork.org",
		},
		{
			name:     "singapore 52502 base uses pixel static epdg",
			card:     plmnWFCCard{mcc: "525", mnc: "02", mncLength: 2},
			wantEPDG: "epdg.epc.mnc001.mcc525.pub.3gppnetwork.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoWiFi(VoWiFiConfig{}),
			}.normalized(tt.card)
			if err != nil {
				t.Fatalf("normalized() error = %v", err)
			}
			if gotEPDG := configEPDG(got); gotEPDG != tt.wantEPDG {
				t.Fatalf("EPDG = %q, want %q", gotEPDG, tt.wantEPDG)
			}
		})
	}
}

func TestEmbeddedWFCConfigATTUsesConfiguredPublicIdentity(t *testing.T) {
	got, err := Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Access:   VoWiFi(VoWiFiConfig{}),
	}.normalized(plmnWFCCard{mcc: "310", mnc: "280", mncLength: 3})
	if err != nil {
		t.Fatalf("normalized() error = %v", err)
	}
	if got.IMS.HomeDomain != "one.att.net" {
		t.Fatalf("HomeDomain = %q, want one.att.net", got.IMS.HomeDomain)
	}
	if got.IMS.PrivateIdentity != "" {
		t.Fatalf("PrivateIdentity = %q, want empty without explicit config", got.IMS.PrivateIdentity)
	}
	if got.IMS.PublicIdentity != "sip:3102800123456789@one.att.net" {
		t.Fatalf("PublicIdentity = %q, want AT&T public identity", got.IMS.PublicIdentity)
	}
	if !slices.Equal(got.IMS.GeolocationPIDFRegister, []int{4, 2}) || !slices.Equal(got.IMS.Voice.GeolocationPIDFInvite, []int{4, 2}) {
		t.Fatalf("PIDF config = register %v invite %v, want [4 2]", got.IMS.GeolocationPIDFRegister, got.IMS.Voice.GeolocationPIDFInvite)
	}
	if !got.IMS.UseTelURIForPIDFXML || !got.IMS.Voice.UseTelURIForPIDFXML {
		t.Fatalf("UseTelURIForPIDFXML = %t/%t, want true", got.IMS.UseTelURIForPIDFXML, got.IMS.Voice.UseTelURIForPIDFXML)
	}
	if !slices.Equal(got.IMS.Voice.PIDFShortCodes, []string{"211", "311", "411", "511", "611", "711", "811"}) {
		t.Fatalf("PIDFShortCodes = %v, want AT&T short codes", got.IMS.Voice.PIDFShortCodes)
	}
	if got.IMS.Voice.ReliableProvisional {
		t.Fatal("ReliableProvisional = true, want Samsung default without forced 100rel")
	}
}

func TestEmbeddedIMSVoiceCarrierCapabilities(t *testing.T) {
	tests := []struct {
		name             string
		card             plmnWFCCard
		wantPrecondition bool
		wantReliable     bool
	}{
		{name: "Samsung WIND Greece", card: plmnWFCCard{mcc: "202", mnc: "09", mncLength: 2}, wantPrecondition: true},
		{name: "Samsung Monaco Telecom GID", card: plmnWFCCard{mcc: "208", mnc: "01", mncLength: 2, gid1: "4d433031"}, wantPrecondition: true},
		{name: "China Telecom", card: plmnWFCCard{mcc: "460", mnc: "11", mncLength: 2}, wantPrecondition: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, ok, err := parseIMSProfile(embeddedIMSConfig, tt.card)
			if err != nil {
				t.Fatalf("parseIMSProfile() error = %v", err)
			}
			if !ok {
				t.Fatal("parseIMSProfile() ok = false, want true")
			}
			if profile.IMSVoice.QoSPreconditionsSupported != tt.wantPrecondition || profile.IMSVoice.ReliableProvisionalSupported != tt.wantReliable {
				t.Fatalf("carrier capabilities = %t/%t, want %t/%t", profile.IMSVoice.QoSPreconditionsSupported, profile.IMSVoice.ReliableProvisionalSupported, tt.wantPrecondition, tt.wantReliable)
			}
		})
	}
}

func TestEmbeddedIMSVoicePixelSessionRefresher(t *testing.T) {
	tests := []struct {
		name string
		card plmnWFCCard
		want string
	}{
		{
			name: "Bouygues uses UAS",
			card: plmnWFCCard{mcc: "208", mnc: "20", mncLength: 2},
			want: "uas",
		},
		{
			name: "Vodafone UK omits refresher parameter",
			card: plmnWFCCard{mcc: "234", mnc: "15", mncLength: 2},
			want: "none",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, ok, err := parseIMSProfile(embeddedIMSConfig, tt.card)
			if err != nil {
				t.Fatalf("parseIMSProfile() error = %v", err)
			}
			if !ok {
				t.Fatal("parseIMSProfile() ok = false, want true")
			}
			if profile.IMSVoice.SessionRefresher != tt.want {
				t.Fatalf("SessionRefresher = %q, want %q", profile.IMSVoice.SessionRefresher, tt.want)
			}
		})
	}
}

func TestEmbeddedIMSProfileCatalogSizeAndKeys(t *testing.T) {
	var profiles []imsProfile
	if err := json.Unmarshal(embeddedIMSConfig, &profiles); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if len(profiles) != 1705 {
		t.Fatalf("profile count = %d, want 1705", len(profiles))
	}
	keys := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		key := strings.Join([]string{
			profile.MCC + profile.MNC,
			strings.TrimSpace(profile.IMSIPrefix),
			normalizeDigits(profile.ICCIDPrefix),
			strings.ToUpper(strings.TrimSpace(profile.SPN)),
			normalizeGID(profile.GID1),
			normalizeGID(profile.GID2),
		}, "|")
		if _, exists := keys[key]; exists {
			t.Fatalf("duplicate profile key %q", key)
		}
		keys[key] = struct{}{}
	}
}

func TestEmbeddedPixelIMSIPrefixProfiles(t *testing.T) {
	tests := []struct {
		name     string
		imsi     string
		wantEPDG string
	}{
		{name: "Truphone", imsi: "204047941234567", wantEPDG: "epdg.eps.truphone.net"},
		{name: "Enreach", imsi: "204047960123456", wantEPDG: "epdg.epc.mnc004.mcc204.pub.3gppnetwork.org"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, ok, err := parseIMSProfile(embeddedIMSConfig, plmnWFCCard{mcc: "204", mnc: "04", mncLength: 2, imsi: tt.imsi})
			if err != nil {
				t.Fatalf("parseIMSProfile() error = %v", err)
			}
			if !ok {
				t.Fatal("parseIMSProfile() ok = false, want true")
			}
			if profile.IMSIPrefix == "" || profile.EPDG != tt.wantEPDG {
				t.Fatalf("profile = IMSI %q EPDG %q, want IMSI selector and EPDG %q", profile.IMSIPrefix, profile.EPDG, tt.wantEPDG)
			}
		})
	}
}

func TestEmbeddedIMSUserAgentSourcePriority(t *testing.T) {
	terminal := TerminalInfo{
		Vendor: "Google",
		Model:  "Pixel 10 Pro",
		Build:  "BD1A.250702.001",
	}
	tests := []struct {
		name         string
		card         plmnWFCCard
		wantTemplate string
		wantRendered string
	}{
		{
			name:         "Pixel value wins",
			card:         plmnWFCCard{mcc: "202", mnc: "01", mncLength: 2},
			wantTemplate: "#MANUFACTURE# - #MODEL# - #BUILD#",
			wantRendered: "Google - Pixel 10 Pro - BD1A.250702.001",
		},
		{
			name:         "Samsung fallback uses Pixel placeholders",
			card:         plmnWFCCard{mcc: "202", mnc: "05", mncLength: 2},
			wantTemplate: "#MODEL#-#BUILD# Samsung IMS 6.0",
			wantRendered: "Pixel 10 Pro-BD1A.250702.001 Samsung IMS 6.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, ok, err := parseIMSProfile(embeddedIMSConfig, tt.card)
			if err != nil {
				t.Fatalf("parseIMSProfile() error = %v", err)
			}
			if !ok {
				t.Fatal("parseIMSProfile() ok = false, want true")
			}
			if profile.IMSUserAgent != tt.wantTemplate {
				t.Fatalf("IMSUserAgent = %q, want %q", profile.IMSUserAgent, tt.wantTemplate)
			}

			got := renderIMSUserAgent(profile.IMSUserAgent, Config{Terminal: terminal}, profile)
			if got != tt.wantRendered {
				t.Fatalf("renderIMSUserAgent() = %q, want %q", got, tt.wantRendered)
			}
		})
	}
}

func TestEmbeddedIMSUserAgentsUsePixelPlaceholderFormat(t *testing.T) {
	var profiles []imsProfile
	if err := json.Unmarshal(embeddedIMSConfig, &profiles); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	samsungPlaceholders := []string{
		"#SUPPORT#",
		"#OMCCODE#",
		"#UICC_VERSION#",
		"#IMS_PROFILE_VOICE#",
		"#RCS_PROFILE#",
		"#MNO_CUSTOM#",
	}

	tests := make([]struct {
		name      string
		userAgent string
	}, 0, len(profiles))
	for _, profile := range profiles {
		tests = append(tests, struct {
			name      string
			userAgent string
		}{
			name:      profile.MCC + "-" + profile.MNC,
			userAgent: profile.IMSUserAgent,
		})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if strings.ContainsAny(tt.userAgent, "[]") {
				t.Fatalf("IMS User-Agent uses Samsung placeholder format: %q", tt.userAgent)
			}
			for _, placeholder := range samsungPlaceholders {
				if strings.Contains(tt.userAgent, placeholder) {
					t.Fatalf("IMS User-Agent uses Samsung-only placeholder %q: %q", placeholder, tt.userAgent)
				}
			}
		})
	}
}

func TestEmbeddedRequestURIFormatSourcePriority(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want imsvoice.RequestURIFormat
	}{
		{name: "Truphone Netherlands GID", key: "20404|547275554B3030656E", want: imsvoice.RequestURIFormatTEL},
		{name: "Truphone Netherlands alternate PLMN", key: "20433|547275554B3030656E", want: imsvoice.RequestURIFormatTEL},
		{name: "Lowi Spain", key: "21406|", want: imsvoice.RequestURIFormatTEL},
		{name: "Truphone Spain GID", key: "21427|547275554B3030656E", want: imsvoice.RequestURIFormatTEL},
		{name: "BT UK", key: "23408|", want: imsvoice.RequestURIFormatTEL},
		{name: "Truphone UK GID", key: "23425|547275554B3030656E", want: imsvoice.RequestURIFormatTEL},
		{name: "Truphone Poland GID", key: "26033|547275554B3030656E", want: imsvoice.RequestURIFormatTEL},
		{name: "Truphone Germany GID", key: "26242|547275554B3030656E", want: imsvoice.RequestURIFormatTEL},
		{name: "Vivacom Bulgaria", key: "28403|", want: imsvoice.RequestURIFormatTEL},
		{name: "Tricom Dominican Republic", key: "37001|", want: imsvoice.RequestURIFormatTEL},
		{name: "Rakuten Japan", key: "44011|", want: imsvoice.RequestURIFormatTEL},
		{name: "T Star Taiwan", key: "46689|", want: imsvoice.RequestURIFormatTEL},
		{name: "Smartfren Indonesia", key: "51009|", want: imsvoice.RequestURIFormatTEL},
		{name: "Smartfren alternate Indonesia", key: "51028|", want: imsvoice.RequestURIFormatTEL},
		{name: "Entel Peru", key: "71617|", want: imsvoice.RequestURIFormatTEL},
		{name: "WOM Chile", key: "73009|", want: imsvoice.RequestURIFormatTEL},
		{name: "Pixel and Samsung conflict uses Pixel", key: "310300|", want: imsvoice.RequestURIFormatSIP},
	}
	var profiles []imsProfile
	if err := json.Unmarshal(embeddedIMSConfig, &profiles); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	formats := make(map[string]imsvoice.RequestURIFormat, len(profiles))
	for _, profile := range profiles {
		if profile.IMSIPrefix == "" {
			formats[profile.MCC+profile.MNC+"|"+normalizeGID(profile.GID1)] = profile.IMSRequestURIFormat
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formats[tt.key]; got != tt.want {
				t.Fatalf("Request URI format for %s = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestEmbeddedChinaCarrierVoiceTimers(t *testing.T) {
	tests := []struct {
		name         string
		mnc          string
		wantRingback time.Duration
		wantRinging  time.Duration
	}{
		{name: "China Mobile", mnc: "00", wantRingback: 80 * time.Second, wantRinging: 80 * time.Second},
		{name: "China Unicom", mnc: "01", wantRingback: 80 * time.Second, wantRinging: 80 * time.Second},
		{name: "China Telecom", mnc: "11", wantRingback: 125 * time.Second, wantRinging: 120 * time.Second},
		{name: "China Broadnet", mnc: "15", wantRingback: 125 * time.Second, wantRinging: 125 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, ok, err := parseIMSProfile(embeddedIMSConfig, plmnWFCCard{mcc: "460", mnc: tt.mnc, mncLength: 2})
			if err != nil {
				t.Fatalf("parseIMSProfile() error = %v", err)
			}
			if !ok {
				t.Fatal("parseIMSProfile() ok = false, want true")
			}
			if profile.IMSVoice.RingbackTimer.Duration != tt.wantRingback || profile.IMSVoice.RingingTimer.Duration != tt.wantRinging {
				t.Fatalf("voice timers = %v/%v, want %v/%v", profile.IMSVoice.RingbackTimer.Duration, profile.IMSVoice.RingingTimer.Duration, tt.wantRingback, tt.wantRinging)
			}
		})
	}
}

func TestIMSProfileAccessNetworkInfoFollowsAccessType(t *testing.T) {
	profile := imsProfile{IMSAccessNetworkInfo: "IEEE-802.11"}
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{name: "vowifi uses profile value", cfg: Config{Access: VoWiFi(VoWiFiConfig{})}, want: "IEEE-802.11"},
		{name: "volte keeps radio value", cfg: Config{Access: VoLTE(lte.Config{AccessNetworkInfo: testVoLTEPANI})}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.withIMSProfile(profile, wfcTestCard{})
			if got.IMS.AccessNetworkInfo != tt.want {
				t.Fatalf("AccessNetworkInfo = %q, want %q", got.IMS.AccessNetworkInfo, tt.want)
			}
		})
	}
}

func TestIMSVoiceProfileOwnsCarrierCapabilities(t *testing.T) {
	tests := []struct {
		name    string
		profile imsVoiceProfile
	}{
		{name: "profile enables capabilities", profile: imsVoiceProfile{QoSPreconditionsSupported: true, ReliableProvisionalSupported: true, SessionTimer: true}},
		{name: "profile disables capabilities"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{IMS: IMSConfig{Voice: imsvoice.Config{Preconditions: true, ReliableProvisional: true, SessionTimer: true}}}
			got := cfg.withIMSVoiceProfile(tt.profile).IMS.Voice
			if got.Preconditions != tt.profile.QoSPreconditionsSupported || got.ReliableProvisional != tt.profile.ReliableProvisionalSupported || got.SessionTimer != tt.profile.SessionTimer {
				t.Fatalf("carrier capabilities = %t/%t/%t, want %t/%t/%t", got.Preconditions, got.ReliableProvisional, got.SessionTimer, tt.profile.QoSPreconditionsSupported, tt.profile.ReliableProvisionalSupported, tt.profile.SessionTimer)
			}
		})
	}
}

func TestIMSProfileRejectsUnknownFields(t *testing.T) {
	unknown := append([]byte(nil), embeddedIMSConfig...)
	var profiles []map[string]json.RawMessage
	if err := json.Unmarshal(unknown, &profiles); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	profiles[0]["unknownField"] = json.RawMessage(`true`)
	unknown, err := json.Marshal(profiles)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if _, _, err := parseIMSProfile(unknown, wfcTestCard{}); err == nil {
		t.Fatal("parseIMSProfile() error = nil, want unknown-field error")
	}
}

func TestWFCProfileUsesJSONVoiceCodecs(t *testing.T) {
	data := []byte(`[
  {
    "mcc": "310",
    "mnc": "410",
    "epdg": "epdg.epc.att.net",
    "imsHomeDomain": "one.att.net",
    "imsVoice": {
      "codecs": [
        {"name": "AMR", "payloadTypes": [102], "clockRate": 8000}
      ]
    }
  }
]`)
	profile, ok, err := parseIMSProfile(data, plmnWFCCard{mcc: "310", mnc: "410", mncLength: 3})
	if err != nil {
		t.Fatalf("parseIMSProfile() error = %v", err)
	}
	if !ok {
		t.Fatal("parseIMSProfile() ok = false, want true")
	}

	cfg := Config{
		Terminal: TerminalInfo{ID: testIMEI},
		IMS: IMSConfig{
			Voice: imsvoice.Config{
				Codecs: []imsvoice.AudioCodecConfig{
					{Name: imsvoice.CodecAMR, PayloadTypes: []int{102}, ClockRate: 8000},
					{Name: imsvoice.CodecPCMU, PayloadTypes: []int{0}, ClockRate: 8000},
				},
			},
		},
	}
	got := cfg.withIMSProfile(profile, plmnWFCCard{mcc: "310", mnc: "410", mncLength: 3})
	if len(got.IMS.Voice.Codecs) != 2 {
		t.Fatalf("Voice codecs = %+v, want explicit codecs preserved", got.IMS.Voice.Codecs)
	}
	if got.IMS.Voice.Codecs[0].Name != imsvoice.CodecAMR || got.IMS.Voice.Codecs[0].PayloadTypes[0] != 102 {
		t.Fatalf("Voice speech codec = %+v, want explicit AMR payload 102", got.IMS.Voice.Codecs[0])
	}
	if got.IMS.Voice.Codecs[1].Name != imsvoice.CodecPCMU || got.IMS.Voice.Codecs[1].PayloadTypes[0] != 0 {
		t.Fatalf("Voice PCMU codec = %+v, want explicit static payload 0", got.IMS.Voice.Codecs[1])
	}

	got = Config{Terminal: TerminalInfo{ID: testIMEI}}.withIMSProfile(profile, plmnWFCCard{mcc: "310", mnc: "410", mncLength: 3})
	if len(got.IMS.Voice.Codecs) != 1 || got.IMS.Voice.Codecs[0].Name != imsvoice.CodecAMR || got.IMS.Voice.Codecs[0].PayloadTypes[0] != 102 {
		t.Fatalf("Voice codecs = %+v, want profile JSON codecs without carrier fallback", got.IMS.Voice.Codecs)
	}
}

func TestWFCVoiceEVSPayloadDescription(t *testing.T) {
	tests := []struct {
		name     string
		desc     imsEVSPayloadDescription
		codec    imsVoiceCodecProfile
		wantBR   string
		wantBW   string
		wantChAw *int
	}{
		{
			name:     "direct payload description",
			desc:     imsEVSPayloadDescription{Bitrate: "5.9-13.2", Bandwidth: "nb-swb", ChannelAwareReceive: 2},
			wantBR:   "5.9-13.2",
			wantBW:   "nb-swb",
			wantChAw: new(2),
		},
		{
			name:   "codec fields override payload description",
			codec:  imsVoiceCodecProfile{Bitrate: "13.2", Bandwidth: "swb"},
			desc:   imsEVSPayloadDescription{Bitrate: "5.9-13.2", Bandwidth: "nb-swb"},
			wantBR: "13.2",
			wantBW: "swb",
		},
		{
			name:   "invalid channel aware sentinel",
			desc:   imsEVSPayloadDescription{Bitrate: "5.9-24.4", Bandwidth: "nb-swb", ChannelAwareReceive: 255},
			wantBR: "5.9-24.4",
			wantBW: "nb-swb",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := tt.codec
			codec.Name = imsvoice.CodecEVS
			codec.PayloadTypes = []int{127}
			codec.ClockRate = 16000
			codecs := imsProfileVoiceCodecs(imsVoiceProfile{
				Codecs: []imsVoiceCodecProfile{codec},
				EVSPayloadDescriptions: map[string]imsEVSPayloadDescription{
					"127": tt.desc,
				},
			})
			if len(codecs) != 1 {
				t.Fatalf("imsProfileVoiceCodecs() length = %d, want 1", len(codecs))
			}
			got := codecs[0]
			if got.Bitrate != tt.wantBR || got.Bandwidth != tt.wantBW {
				t.Fatalf("EVS br/bw = %q/%q, want %q/%q", got.Bitrate, got.Bandwidth, tt.wantBR, tt.wantBW)
			}
			if (got.ChAwRecv == nil) != (tt.wantChAw == nil) {
				t.Fatalf("EVS ChAwRecv = %v, want %v", got.ChAwRecv, tt.wantChAw)
			}
			if got.ChAwRecv != nil && *got.ChAwRecv != *tt.wantChAw {
				t.Fatalf("EVS ChAwRecv = %d, want %d", *got.ChAwRecv, *tt.wantChAw)
			}
		})
	}
}

func TestEmbeddedWFCConfigUsesPixelIMSVoice(t *testing.T) {
	got, err := Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Access:   VoWiFi(VoWiFiConfig{}),
	}.normalized(plmnWFCCard{mcc: "310", mnc: "280", mncLength: 3})
	if err != nil {
		t.Fatalf("normalized() error = %v", err)
	}

	if got.IMS.Voice.AudioASBandwidthKbps != 49 {
		t.Fatalf("AudioASBandwidthKbps = %d, want Pixel value 49", got.IMS.Voice.AudioASBandwidthKbps)
	}
	if got.IMS.Voice.RingbackTimeout != 180*time.Second || got.IMS.Voice.RingingTimeout != 45*time.Second {
		t.Fatalf("ring timers = %v/%v, want Pixel values", got.IMS.Voice.RingbackTimeout, got.IMS.Voice.RingingTimeout)
	}
	want := []struct {
		name      imsvoice.AudioCodec
		payload   int
		clockRate int
	}{
		{imsvoice.CodecAMRWB, 104, 16000},
		{imsvoice.CodecAMR, 110, 8000},
		{imsvoice.CodecEVS, 127, 16000},
		{imsvoice.CodecTelephoneEvent, 97, 8000},
		{imsvoice.CodecTelephoneEvent, 96, 16000},
	}
	if len(got.IMS.Voice.Codecs) != len(want) {
		t.Fatalf("Voice codecs = %+v, want Pixel codec list", got.IMS.Voice.Codecs)
	}
	for i, wantCodec := range want {
		gotCodec := got.IMS.Voice.Codecs[i]
		if gotCodec.Name != wantCodec.name || len(gotCodec.PayloadTypes) != 1 || gotCodec.PayloadTypes[0] != wantCodec.payload || gotCodec.ClockRate != wantCodec.clockRate {
			t.Fatalf("Voice codec[%d] = %+v, want %s/%d/%d", i, gotCodec, wantCodec.name, wantCodec.payload, wantCodec.clockRate)
		}
	}
	evs := got.IMS.Voice.Codecs[2]
	if evs.Bitrate != "5.9-13.2" || evs.Bandwidth != "nb-swb" || evs.ChAwRecv == nil || *evs.ChAwRecv != 2 {
		t.Fatalf("EVS codec = %+v, want Pixel payload description", evs)
	}
}

func TestEmbeddedWFCConfigUsesWFCWidebandDTMFPayloads(t *testing.T) {
	tests := []struct {
		name string
		card plmnWFCCard
		nb   int
		wb   int
	}{
		{
			name: "Pixel default",
			card: plmnWFCCard{mcc: "000", mnc: "000", mncLength: 3},
			nb:   97,
			wb:   96,
		},
		{
			name: "Vodafone Netherlands generic",
			card: plmnWFCCard{mcc: "204", mnc: "04", mncLength: 2},
			nb:   97,
			wb:   96,
		},
		{
			name: "Verizon Netherlands GID1",
			card: plmnWFCCard{mcc: "204", mnc: "04", mncLength: 2, gid1: "BAE0000000000000"},
			nb:   100,
			wb:   105,
		},
		{
			name: "T-Mobile Austria",
			card: plmnWFCCard{mcc: "232", mnc: "03", mncLength: 2},
			nb:   99,
			wb:   98,
		},
		{
			name: "Verizon",
			card: plmnWFCCard{mcc: "311", mnc: "480", mncLength: 3},
			nb:   100,
			wb:   105,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoWiFi(VoWiFiConfig{}),
			}.normalized(tt.card)
			if err != nil {
				t.Fatalf("normalized() error = %v", err)
			}
			wantByClock := map[int]int{
				8000:  tt.nb,
				16000: tt.wb,
			}
			seen := make(map[int]bool, len(wantByClock))
			for _, codec := range got.IMS.Voice.Codecs {
				if codec.Name != imsvoice.CodecTelephoneEvent {
					continue
				}
				want, ok := wantByClock[codec.ClockRate]
				if !ok {
					continue
				}
				seen[codec.ClockRate] = true
				if len(codec.PayloadTypes) != 1 || codec.PayloadTypes[0] != want {
					t.Fatalf("DTMF %d payloadTypes = %v, want [%d]", codec.ClockRate, codec.PayloadTypes, want)
				}
			}
			for clock := range wantByClock {
				if !seen[clock] {
					t.Fatalf("DTMF %d codec is missing", clock)
				}
			}
		})
	}
}

func TestEmbeddedWFCConfigUsesAudioInactivityCallEndReasons(t *testing.T) {
	tests := []struct {
		name string
		card plmnWFCCard
		want []imsvoice.AudioInactivityCallEndReason
	}{
		{
			name: "default test profile",
			card: plmnWFCCard{mcc: "000", mnc: "000", mncLength: 3},
			want: []imsvoice.AudioInactivityCallEndReason{
				imsvoice.AudioInactivityRTCPOnHold,
				imsvoice.AudioInactivityRTPOnConnected,
				imsvoice.AudioInactivityE911RTP,
			},
		},
		{
			name: "gid profile",
			card: plmnWFCCard{mcc: "001", mnc: "01", mncLength: 2, gid1: "ABCD2025"},
			want: []imsvoice.AudioInactivityCallEndReason{
				imsvoice.AudioInactivityRTCPOnHold,
				imsvoice.AudioInactivityRTCPOnConnected,
				imsvoice.AudioInactivityRTPOnConnected,
			},
		},
		{
			name: "new zealand profile uses pixel default carrier value",
			card: plmnWFCCard{mcc: "530", mnc: "01", mncLength: 2},
			want: []imsvoice.AudioInactivityCallEndReason{
				imsvoice.AudioInactivityRTCPOnHold,
				imsvoice.AudioInactivityRTPOnConnected,
				imsvoice.AudioInactivityE911RTP,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoWiFi(VoWiFiConfig{}),
			}.normalized(tt.card)
			if err != nil {
				t.Fatalf("normalized() error = %v", err)
			}
			if !slices.Equal(got.IMS.Voice.AudioInactivityCallEndReasons, tt.want) {
				t.Fatalf("AudioInactivityCallEndReasons = %v, want %v", got.IMS.Voice.AudioInactivityCallEndReasons, tt.want)
			}
		})
	}
}

func TestEmbeddedWFCConfigPreservesDisabledRTCPInactivityTimer(t *testing.T) {
	tests := []struct {
		name string
		card plmnWFCCard
	}{
		{
			name: "free france",
			card: plmnWFCCard{mcc: "208", mnc: "09", mncLength: 2},
		},
		{
			name: "vodafone ireland",
			card: plmnWFCCard{mcc: "272", mnc: "01", mncLength: 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoWiFi(VoWiFiConfig{}),
			}.normalized(tt.card)
			if err != nil {
				t.Fatalf("normalized() error = %v", err)
			}
			if *got.IMS.Voice.RTCPInactivityTimeout != 0 {
				t.Fatalf("RTCPInactivityTimeout = %v, want disabled", *got.IMS.Voice.RTCPInactivityTimeout)
			}
		})
	}
}

func TestEmbeddedWFCConfigMatchesNSDSProfiles(t *testing.T) {
	nsdsProfiles := []struct {
		Carrier   string
		MCC       string
		MNC       string
		ServerURL string
	}{
		{Carrier: "AT&T", MCC: "310", MNC: "030", ServerURL: "https://sentitlement2.mobile.att.net/WFC"},
		{Carrier: "Cricket/AT&T", MCC: "310", MNC: "150", ServerURL: "https://sentitlement2.mobile.att.net/WFC"},
		{Carrier: "AT&T", MCC: "310", MNC: "170", ServerURL: "https://sentitlement2.mobile.att.net/WFC"},
		{Carrier: "AT&T", MCC: "310", MNC: "280", ServerURL: "https://sentitlement2.mobile.att.net/WFC"},
		{Carrier: "AT&T", MCC: "310", MNC: "380", ServerURL: "https://sentitlement2.mobile.att.net/WFC"},
		{Carrier: "AT&T", MCC: "310", MNC: "410", ServerURL: "https://sentitlement2.mobile.att.net/WFC"},
		{Carrier: "AT&T", MCC: "310", MNC: "560", ServerURL: "https://sentitlement2.mobile.att.net/WFC"},
		{Carrier: "AT&T", MCC: "310", MNC: "950", ServerURL: "https://sentitlement2.mobile.att.net/WFC"},
		{Carrier: "AT&T", MCC: "311", MNC: "180", ServerURL: "https://sentitlement2.mobile.att.net/WFC"},
		{Carrier: "FirstNet/AT&T", MCC: "313", MNC: "100", ServerURL: "https://sentitlement2.mobile.att.net/WFC"},
		{Carrier: "GCI", MCC: "311", MNC: "370", ServerURL: "https://ses.epdg.gci.net/generic_devices"},
	}
	for _, profile := range nsdsProfiles {
		t.Run(profile.Carrier+" "+profile.MCC+profile.MNC, func(t *testing.T) {
			card := plmnWFCCard{
				mcc:       profile.MCC,
				mnc:       profile.MNC,
				mncLength: len(profile.MNC),
			}
			got, err := Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoWiFi(VoWiFiConfig{}),
			}.normalized(card)
			if err != nil {
				t.Fatalf("normalized() error = %v", err)
			}
			if got.IMS.PrivateIdentity != "" {
				t.Fatalf("PrivateIdentity = %q, want empty without explicit config", got.IMS.PrivateIdentity)
			}

			if strings.Contains(profile.ServerURL, "mobile.att.net") {
				wantIMSI := card.IMSI()
				if got.IMS.HomeDomain != "one.att.net" {
					t.Fatalf("HomeDomain = %q, want one.att.net", got.IMS.HomeDomain)
				}
				if got.IMS.PublicIdentity != "sip:"+wantIMSI+"@one.att.net" {
					t.Fatalf("PublicIdentity = %q, want AT&T public identity", got.IMS.PublicIdentity)
				}
				return
			}

			if got.IMS.HomeDomain == "one.att.net" || strings.Contains(got.IMS.PublicIdentity, "att.net") {
				t.Fatalf("IMS profile = %q/%q, want non-AT&T values", got.IMS.HomeDomain, got.IMS.PublicIdentity)
			}
		})
	}
}
