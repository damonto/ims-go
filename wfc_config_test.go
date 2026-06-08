package vowifi

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/damonto/uicc-go/usim"
	imsvoice "github.com/damonto/vowifi-go/ims/voice"
	swutunnel "github.com/damonto/vowifi-go/swu/tunnel"
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
    "ikeSALifetime": "7200s",
    "ikeSARekeySoftTime": "3600s",
    "ikeSARekeyHardTime": "3900s",
    "childSALifetime": "3600s",
    "childSARekeySoftTime": "1800s",
    "childSARekeyHardTime": "1980s",
    "addKEToChildSARekey": true,
    "imsTransport": "tcp",
    "imsHomeDomain": "ims.mnc024.mcc530.3gppnetwork.org",
    "imsPrivateIdentity": "#IMSI#@private.example",
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
      "rtcpSendInterval": "5s",
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
				Terminal: TerminalInfo{
					ID:              testIMEI,
					Vendor:          "Google",
					Model:           "Pixel 10 Pro",
					SoftwareVersion: "16",
					Build:           "BD1A.250702.001",
					Type:            "Smartphone",
					HardwareSKU:     "Pixel 10 Pro",
				},
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
				if got.Tunnel.IKESALifetime != 7200*time.Second || got.Tunnel.IKESARekeyMargin != 300*time.Second {
					t.Fatalf("Tunnel IKE SA lifetime = %v/%v, want 7200s/300s", got.Tunnel.IKESALifetime, got.Tunnel.IKESARekeyMargin)
				}
				if got.Tunnel.ChildSALifetime != 3600*time.Second || got.Tunnel.ChildSARekeyMargin != 300*time.Second {
					t.Fatalf("Tunnel Child SA lifetime = %v/%v, want 3600s/300s", got.Tunnel.ChildSALifetime, got.Tunnel.ChildSARekeyMargin)
				}
				if !got.Tunnel.AddKEToChildSARekey {
					t.Fatal("Tunnel AddKEToChildSARekey = false, want profile value")
				}
				if got.IMS.Transport != "tcp" || got.IMS.HomeDomain != "ims.mnc024.mcc530.3gppnetwork.org" {
					t.Fatalf("IMS transport/domain = %q/%q, want profile values", got.IMS.Transport, got.IMS.HomeDomain)
				}
				if got.IMS.PrivateIdentity != "530240123456789@private.example" || got.IMS.PublicIdentity != "sip:530240123456789@ims.mnc024.mcc530.3gppnetwork.org" {
					t.Fatalf("IMS identities = %q/%q, want profile values", got.IMS.PrivateIdentity, got.IMS.PublicIdentity)
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
				if got.IMS.Voice.Preconditions {
					t.Fatalf("IMS voice preconditions = true, want disabled")
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
				if *got.IMS.Voice.RTPInactivityTimeout != 20*time.Second || *got.IMS.Voice.RTCPInactivityTimeout != 21*time.Second || *got.IMS.Voice.RTCPSendInterval != 5*time.Second {
					t.Fatalf("IMS voice media timers = %v/%v/%v, want profile values", *got.IMS.Voice.RTPInactivityTimeout, *got.IMS.Voice.RTCPInactivityTimeout, *got.IMS.Voice.RTCPSendInterval)
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
				EPDG:     "epdg.example.com",
				Tunnel:   tunnelConfigForWFCOverride(),
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
			profile, ok, err := parseWFCProfile(data, wfcTestCard{})
			if err != nil {
				t.Fatalf("parseWFCProfile() error = %v", err)
			}
			if !ok {
				t.Fatal("parseWFCProfile() ok = false, want true")
			}

			got := Config{Terminal: TerminalInfo{ID: testIMEI}}.withWFCProfile(profile, wfcTestCard{})
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
			name:     "missing carrier setting defaults status reports on",
			wantFlag: true,
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
			profile, ok, err := parseWFCProfile(data, wfcTestCard{})
			if err != nil {
				t.Fatalf("parseWFCProfile() error = %v", err)
			}
			if !ok {
				t.Fatal("parseWFCProfile() ok = false, want true")
			}

			got := Config{Terminal: TerminalInfo{ID: testIMEI}}.withWFCProfile(profile, wfcTestCard{})
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
	profile, ok, err := parseWFCProfile(data, wfcTestCard{})
	if err != nil {
		t.Fatalf("parseWFCProfile() error = %v", err)
	}
	if !ok {
		t.Fatal("parseWFCProfile() ok = false, want true")
	}

	got := Config{Terminal: TerminalInfo{ID: testIMEI}}.withWFCProfile(profile, wfcTestCard{})
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

func TestSALifetimeFromWFCProfile(t *testing.T) {
	duration := func(value string) *wfcDuration {
		t.Helper()
		got, err := time.ParseDuration(value)
		if err != nil {
			t.Fatalf("time.ParseDuration(%q) error = %v", value, err)
		}
		return &wfcDuration{Duration: got}
	}

	tests := []struct {
		name       string
		lifetime   *wfcDuration
		soft       *wfcDuration
		hard       *wfcDuration
		legacySoft *wfcDuration
		wantLife   time.Duration
		wantMargin time.Duration
	}{
		{
			name:       "configured lifetime ignores modern default soft rekey",
			lifetime:   duration("86400s"),
			soft:       duration("3000s"),
			hard:       duration("86500s"),
			wantLife:   86400 * time.Second,
			wantMargin: 300 * time.Second,
		},
		{
			name:       "legacy rekey time wins when valid",
			lifetime:   duration("43200s"),
			soft:       duration("86400s"),
			hard:       duration("86500s"),
			legacySoft: duration("14400s"),
			wantLife:   43200 * time.Second,
			wantMargin: 28800 * time.Second,
		},
		{
			name:       "invalid soft rekey uses default margin",
			lifetime:   duration("64800s"),
			soft:       duration("86400s"),
			legacySoft: duration("64800s"),
			wantLife:   64800 * time.Second,
			wantMargin: 300 * time.Second,
		},
		{
			name:       "hard rekey timer is fallback lifetime",
			soft:       duration("86340s"),
			hard:       duration("86400s"),
			wantLife:   86400 * time.Second,
			wantMargin: 60 * time.Second,
		},
		{
			name:       "legacy soft derives hard before modern timer pair",
			soft:       duration("86400s"),
			hard:       duration("86500s"),
			legacySoft: duration("64800s"),
			wantLife:   65100 * time.Second,
			wantMargin: 300 * time.Second,
		},
		{
			name:       "legacy soft can exceed modern hard timer",
			soft:       duration("3000s"),
			hard:       duration("3600s"),
			legacySoft: duration("64800s"),
			wantLife:   65100 * time.Second,
			wantMargin: 300 * time.Second,
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
			gotLife, gotMargin := saLifetimeFromWFCProfile(tt.lifetime, tt.soft, tt.hard, tt.legacySoft)
			if gotLife != tt.wantLife || gotMargin != tt.wantMargin {
				t.Fatalf("saLifetimeFromWFCProfile() = %v/%v, want %v/%v", gotLife, gotMargin, tt.wantLife, tt.wantMargin)
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
	profile, ok, err := parseWFCProfile(data, wfcTestCard{})
	if err != nil {
		t.Fatalf("parseWFCProfile() error = %v", err)
	}
	if !ok {
		t.Fatal("parseWFCProfile() ok = false, want true")
	}

	got := Config{Terminal: TerminalInfo{ID: testIMEI}}.withWFCProfile(profile, wfcTestCard{})
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
				Terminal: TerminalInfo{ID: testIMEI},
			},
			card:     wfcTestCard{},
			wantEPDG: "epdg.ims.2degrees.net.nz",
		},
		{
			name: "explicit epdg still wins",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				EPDG:     "epdg.example.com",
			},
			card:     wfcTestCard{},
			wantEPDG: "epdg.example.com",
		},
		{
			name: "embedded two digit mnc profile matches padded card mnc",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
			},
			card:     paddedTwoDigitMNCCard{},
			wantEPDG: "epdg.eps.truphone.net",
		},
		{
			name: "embedded gid profile wins over base profile",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
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

func TestConfigNormalizedUsesEmbeddedLivenessTimeout(t *testing.T) {
	cfg := Config{Terminal: TerminalInfo{ID: testIMEI}}
	got, err := cfg.normalized(plmnWFCCard{mcc: "505", mnc: "03", mncLength: 2})
	if err != nil {
		t.Fatalf("normalized() error = %v", err)
	}
	if got.Tunnel.LivenessTimeout != 90*time.Second {
		t.Fatalf("Tunnel.LivenessTimeout = %v, want Vodafone AU liveness timeout 90s", got.Tunnel.LivenessTimeout)
	}
}

func TestEmbeddedWFCProfilesDeclareLivenessTimeout(t *testing.T) {
	var profiles []wfcProfile
	if err := json.Unmarshal(embeddedWFCConfig, &profiles); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	tests := make([]struct {
		name    string
		profile wfcProfile
	}, 0, len(profiles))
	for _, profile := range profiles {
		tests = append(tests, struct {
			name    string
			profile wfcProfile
		}{
			name:    profile.MCC + "-" + profile.MNC + "-" + profile.GID1,
			profile: profile,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.profile.LivenessTimeout == nil {
				t.Fatal("livenessTimeout is missing")
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
			name:     "csl hk base uses pixel static epdg",
			card:     plmnWFCCard{mcc: "454", mnc: "000", mncLength: 2},
			wantEPDG: "epdg.eps.truphone.net",
		},
		{
			name:     "truphone hk gid keeps pixel override",
			card:     plmnWFCCard{mcc: "454", mnc: "000", mncLength: 2, gid1: "547275554B3030656EFFFF"},
			wantEPDG: "epdg.eps.truphone.net",
		},
		{
			name:     "austria 23210 base uses pixel static epdg",
			card:     plmnWFCCard{mcc: "232", mnc: "10", mncLength: 2},
			wantEPDG: "epdg.epc.mnc260.mcc310.pub.3gppnetwork.org",
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
			got, err := Config{Terminal: TerminalInfo{ID: testIMEI}}.normalized(tt.card)
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
	got, err := Config{Terminal: TerminalInfo{ID: testIMEI}}.normalized(plmnWFCCard{mcc: "310", mnc: "280", mncLength: 3})
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
	if !slices.Equal(got.IMS.GeolocationPIDFRegister, []int{4, 2}) || !slices.Equal(got.IMS.Voice.GeolocationPIDFInvite, []int{4, 2}) {
		t.Fatalf("PIDF config = register %v invite %v, want [4 2]", got.IMS.GeolocationPIDFRegister, got.IMS.Voice.GeolocationPIDFInvite)
	}
	if !got.IMS.UseTelURIForPIDFXML || !got.IMS.Voice.UseTelURIForPIDFXML {
		t.Fatalf("UseTelURIForPIDFXML = %t/%t, want true", got.IMS.UseTelURIForPIDFXML, got.IMS.Voice.UseTelURIForPIDFXML)
	}
	if !slices.Equal(got.IMS.Voice.PIDFShortCodes, []string{"211", "311", "411", "511", "611", "711", "811"}) {
		t.Fatalf("PIDFShortCodes = %v, want AT&T short codes", got.IMS.Voice.PIDFShortCodes)
	}
	if !got.IMS.Voice.ReliableProvisional {
		t.Fatal("ReliableProvisional = false, want AT&T profile to support 100rel")
	}
}

func TestEmbeddedWFCVoiceProfilesMatchPixelPRACKDefault(t *testing.T) {
	for _, tt := range embeddedWFCVoiceProfileTests(t) {
		t.Run(tt.name, func(t *testing.T) {
			if tt.profile.IMSVoice.ReliableProvisionalSupported == nil || !*tt.profile.IMSVoice.ReliableProvisionalSupported {
				t.Fatal("reliableProvisionalSupported = false, want true for MMTEL voice profile")
			}
		})
	}
}

func TestEmbeddedWFCVoiceProfilesDoNotEnableQoSPreconditions(t *testing.T) {
	for _, tt := range embeddedWFCVoiceProfileTests(t) {
		t.Run(tt.name, func(t *testing.T) {
			if tt.profile.IMSVoice.QoSPreconditionsSupported != nil && *tt.profile.IMSVoice.QoSPreconditionsSupported {
				t.Fatal("qosPreconditionsSupported = true, want false unless a carrier explicitly requires preconditions")
			}
		})
	}
}

func embeddedWFCVoiceProfileTests(t *testing.T) []struct {
	name    string
	profile wfcProfile
} {
	t.Helper()

	var profiles []wfcProfile
	if err := json.Unmarshal(embeddedWFCConfig, &profiles); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	tests := []struct {
		name    string
		profile wfcProfile
	}{}
	for _, profile := range profiles {
		if profile.IMSVoice == nil {
			continue
		}
		tests = append(tests, struct {
			name    string
			profile wfcProfile
		}{
			name:    profile.MCC + "-" + profile.MNC + "-" + profile.GID1 + "-" + profile.IMSHomeDomain,
			profile: profile,
		})
	}

	return tests
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
	profile, ok, err := parseWFCProfile(data, plmnWFCCard{mcc: "310", mnc: "410", mncLength: 3})
	if err != nil {
		t.Fatalf("parseWFCProfile() error = %v", err)
	}
	if !ok {
		t.Fatal("parseWFCProfile() ok = false, want true")
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
	got := cfg.withWFCProfile(profile, plmnWFCCard{mcc: "310", mnc: "410", mncLength: 3})
	if len(got.IMS.Voice.Codecs) != 2 {
		t.Fatalf("Voice codecs = %+v, want explicit codecs preserved", got.IMS.Voice.Codecs)
	}
	if got.IMS.Voice.Codecs[0].Name != imsvoice.CodecAMR || got.IMS.Voice.Codecs[0].PayloadTypes[0] != 102 {
		t.Fatalf("Voice speech codec = %+v, want explicit AMR payload 102", got.IMS.Voice.Codecs[0])
	}
	if got.IMS.Voice.Codecs[1].Name != imsvoice.CodecPCMU || got.IMS.Voice.Codecs[1].PayloadTypes[0] != 0 {
		t.Fatalf("Voice PCMU codec = %+v, want explicit static payload 0", got.IMS.Voice.Codecs[1])
	}

	got = Config{Terminal: TerminalInfo{ID: testIMEI}}.withWFCProfile(profile, plmnWFCCard{mcc: "310", mnc: "410", mncLength: 3})
	if len(got.IMS.Voice.Codecs) != 1 || got.IMS.Voice.Codecs[0].Name != imsvoice.CodecAMR || got.IMS.Voice.Codecs[0].PayloadTypes[0] != 102 {
		t.Fatalf("Voice codecs = %+v, want profile JSON codecs without carrier fallback", got.IMS.Voice.Codecs)
	}
}

func TestWFCVoiceEVSPayloadDescription(t *testing.T) {
	tests := []struct {
		name     string
		desc     wfcEVSPayloadDescription
		codec    wfcVoiceCodecProfile
		wantBR   string
		wantBW   string
		wantChAw *int
	}{
		{
			name:     "direct payload description",
			desc:     wfcEVSPayloadDescription{Bitrate: "5.9-13.2", Bandwidth: "nb-swb", ChannelAwareReceive: new(2)},
			wantBR:   "5.9-13.2",
			wantBW:   "nb-swb",
			wantChAw: new(2),
		},
		{
			name:   "codec fields override payload description",
			codec:  wfcVoiceCodecProfile{Bitrate: "13.2", Bandwidth: "swb"},
			desc:   wfcEVSPayloadDescription{Bitrate: "5.9-13.2", Bandwidth: "nb-swb"},
			wantBR: "13.2",
			wantBW: "swb",
		},
		{
			name:   "invalid channel aware sentinel",
			desc:   wfcEVSPayloadDescription{Bitrate: "5.9-24.4", Bandwidth: "nb-swb", ChannelAwareReceive: new(255)},
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
			codecs := wfcVoiceCodecs(&wfcVoiceProfile{
				Codecs: []wfcVoiceCodecProfile{codec},
				EVSPayloadDescriptions: map[string]wfcEVSPayloadDescription{
					"127": tt.desc,
				},
			})
			if len(codecs) != 1 {
				t.Fatalf("wfcVoiceCodecs() length = %d, want 1", len(codecs))
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
	got, err := Config{Terminal: TerminalInfo{ID: testIMEI}}.normalized(plmnWFCCard{mcc: "310", mnc: "280", mncLength: 3})
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
			got, err := Config{Terminal: TerminalInfo{ID: testIMEI}}.normalized(tt.card)
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
			got, err := Config{Terminal: TerminalInfo{ID: testIMEI}}.normalized(tt.card)
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
			got, err := Config{Terminal: TerminalInfo{ID: testIMEI}}.normalized(tt.card)
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
			got, err := Config{Terminal: TerminalInfo{ID: testIMEI}}.normalized(card)
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
