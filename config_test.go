package ims

import (
	"log/slog"
	"testing"
	"time"

	imssession "github.com/damonto/ims-go/ims/session"
	imsussd "github.com/damonto/ims-go/ims/ussd"
)

func TestConfigNormalized(t *testing.T) {
	logger := slog.Default()
	tests := []struct {
		name             string
		cfg              Config
		wantErr          bool
		wantTerminalID   string
		wantEPDG         string
		wantTransport    string
		wantIMSIMEI      string
		wantPhoneCtx     string
		wantAccessInfo   string
		wantReconnect    time.Duration
		wantReconnectMax time.Duration
		wantRegisterExp  time.Duration
		wantIMSRetryBase time.Duration
		wantIMSRetryMax  time.Duration
		wantSIPPort      int
		wantSIPT1        time.Duration
		wantSIPTF        time.Duration
		wantSMSTR2       time.Duration
	}{
		{
			name: "defaults build epdg from card",
			cfg: Config{
				Logger:   logger,
				Terminal: TerminalInfo{ID: " 12345 "},
				Access:   VoWiFi(VoWiFiConfig{}),
				IMS:      IMSConfig{},
			},
			wantTerminalID:   "12345",
			wantEPDG:         "epdg.epc.mnc001.mcc001.pub.3gppnetwork.org",
			wantTransport:    "tcp",
			wantIMSIMEI:      "12345",
			wantAccessInfo:   "IEEE-802.11",
			wantReconnect:    defaultReconnectDelay,
			wantReconnectMax: defaultReconnectMaxDelay,
			wantRegisterExp:  600000 * time.Second,
			wantIMSRetryBase: defaultIMSRegistrationRetryBase,
			wantIMSRetryMax:  defaultIMSRegistrationRetryMax,
			wantSIPPort:      5060,
			wantSIPT1:        imssession.DefaultTransactionTimers().T1,
			wantSIPTF:        imssession.DefaultTransactionTimers().TF,
			wantSMSTR2:       15 * time.Second,
		},
		{
			name: "explicit epdg wins over automatic default",
			cfg: Config{
				Terminal: TerminalInfo{ID: "root-imei"},
				Access:   VoWiFi(VoWiFiConfig{EPDG: " epdg.example.com "}),
			},
			wantTerminalID:   "root-imei",
			wantEPDG:         "epdg.example.com",
			wantTransport:    "tcp",
			wantIMSIMEI:      "root-imei",
			wantAccessInfo:   "IEEE-802.11",
			wantReconnect:    defaultReconnectDelay,
			wantReconnectMax: defaultReconnectMaxDelay,
			wantRegisterExp:  600000 * time.Second,
			wantIMSRetryBase: defaultIMSRegistrationRetryBase,
			wantIMSRetryMax:  defaultIMSRegistrationRetryMax,
			wantSIPPort:      5060,
			wantSIPT1:        imssession.DefaultTransactionTimers().T1,
			wantSIPTF:        imssession.DefaultTransactionTimers().TF,
			wantSMSTR2:       15 * time.Second,
		},
		{
			name: "cfg nil clone still normalizes as zero config",
			cfg: func() Config {
				cfg := cloneConfig(nil)
				cfg.Terminal.ID = testIMEI
				cfg.Access = VoWiFi(VoWiFiConfig{})
				return cfg
			}(),
			wantTerminalID:   testIMEI,
			wantEPDG:         "epdg.epc.mnc001.mcc001.pub.3gppnetwork.org",
			wantTransport:    "tcp",
			wantIMSIMEI:      testIMEI,
			wantAccessInfo:   "IEEE-802.11",
			wantReconnect:    defaultReconnectDelay,
			wantReconnectMax: defaultReconnectMaxDelay,
			wantRegisterExp:  600000 * time.Second,
			wantIMSRetryBase: defaultIMSRegistrationRetryBase,
			wantIMSRetryMax:  defaultIMSRegistrationRetryMax,
			wantSIPPort:      5060,
			wantSIPT1:        imssession.DefaultTransactionTimers().T1,
			wantSIPTF:        imssession.DefaultTransactionTimers().TF,
			wantSMSTR2:       15 * time.Second,
		},
		{
			name: "explicit ims transport is preserved",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoWiFi(VoWiFiConfig{}),
				IMS: IMSConfig{
					Transport: "udp",
				},
			},
			wantTerminalID:   testIMEI,
			wantEPDG:         "epdg.epc.mnc001.mcc001.pub.3gppnetwork.org",
			wantTransport:    "udp",
			wantIMSIMEI:      testIMEI,
			wantAccessInfo:   "IEEE-802.11",
			wantReconnect:    defaultReconnectDelay,
			wantReconnectMax: defaultReconnectMaxDelay,
			wantRegisterExp:  600000 * time.Second,
			wantIMSRetryBase: defaultIMSRegistrationRetryBase,
			wantIMSRetryMax:  defaultIMSRegistrationRetryMax,
			wantSIPPort:      5060,
			wantSIPT1:        imssession.DefaultTransactionTimers().T1,
			wantSIPTF:        imssession.DefaultTransactionTimers().TF,
			wantSMSTR2:       15 * time.Second,
		},
		{
			name: "explicit ims profile values are preserved",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoWiFi(VoWiFiConfig{}),
				IMS: IMSConfig{
					AccessNetworkInfo:        "IEEE-802.11ac;i-wlan-node-id=aabbcc",
					PhoneContextDomain:       "ims.example",
					SIPServerPort:            5070,
					RegistrationRetryBase:    10 * time.Second,
					RegistrationRetryMax:     20 * time.Second,
					SIPTimers:                imssession.TransactionTimers{T1: time.Second, TF: 45 * time.Second},
					SMSDeliveryReportTimeout: 17 * time.Second,
				},
			},
			wantTerminalID:   testIMEI,
			wantEPDG:         "epdg.epc.mnc001.mcc001.pub.3gppnetwork.org",
			wantTransport:    "tcp",
			wantIMSIMEI:      testIMEI,
			wantPhoneCtx:     "ims.example",
			wantAccessInfo:   "IEEE-802.11ac;i-wlan-node-id=aabbcc",
			wantReconnect:    defaultReconnectDelay,
			wantReconnectMax: defaultReconnectMaxDelay,
			wantRegisterExp:  600000 * time.Second,
			wantIMSRetryBase: 10 * time.Second,
			wantIMSRetryMax:  20 * time.Second,
			wantSIPPort:      5070,
			wantSIPT1:        time.Second,
			wantSIPTF:        45 * time.Second,
			wantSMSTR2:       17 * time.Second,
		},
		{
			name: "missing terminal id fails",
			cfg: Config{
				Logger: logger,
			},
			wantErr: true,
		},
		{
			name: "negative reconnect delay fails",
			cfg: Config{
				Terminal:       TerminalInfo{ID: testIMEI},
				ReconnectDelay: -time.Second,
			},
			wantErr: true,
		},
		{
			name: "negative reconnect max delay fails",
			cfg: Config{
				Terminal:          TerminalInfo{ID: testIMEI},
				ReconnectMaxDelay: -time.Second,
			},
			wantErr: true,
		},
		{
			name: "reconnect max delay before initial delay fails",
			cfg: Config{
				Terminal:          TerminalInfo{ID: testIMEI},
				ReconnectDelay:    10 * time.Second,
				ReconnectMaxDelay: 5 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "negative sip timer fails",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				IMS: IMSConfig{
					SIPTimers: imssession.TransactionTimers{T1: -time.Second},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid tcp data ack timeout fails",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				IMS: IMSConfig{
					TCPDataACKTimeouts: []time.Duration{0},
				},
			},
			wantErr: true,
		},
		{
			name: "sub second tcp data ack timeout fails",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				IMS: IMSConfig{
					TCPDataACKTimeouts: []time.Duration{500 * time.Millisecond, time.Second},
				},
			},
			wantErr: true,
		},
		{
			name: "aggressive tcp data ack backoff fails",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				IMS: IMSConfig{
					TCPDataACKTimeouts: []time.Duration{time.Second, time.Second, 4 * time.Second},
				},
			},
			wantErr: true,
		},
		{
			name: "short tcp data ack budget fails",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				IMS: IMSConfig{
					TCPDataACKTimeouts: []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second},
				},
			},
			wantErr: true,
		},
		{
			name: "negative ims registration retry base fails",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				IMS: IMSConfig{
					RegistrationRetryBase: -time.Second,
				},
			},
			wantErr: true,
		},
		{
			name: "negative ims registration retry max fails",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				IMS: IMSConfig{
					RegistrationRetryMax: -time.Second,
				},
			},
			wantErr: true,
		},
		{
			name: "ims registration retry max before base fails",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				IMS: IMSConfig{
					RegistrationRetryBase: 10 * time.Second,
					RegistrationRetryMax:  5 * time.Second,
				},
			},
			wantErr: true,
		},
		{
			name: "negative sms delivery report timeout fails",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				IMS: IMSConfig{
					SMSDeliveryReportTimeout: -time.Second,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid sip server port fails",
			cfg: Config{
				Terminal: TerminalInfo{ID: testIMEI},
				IMS: IMSConfig{
					SIPServerPort: 70000,
				},
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
			if got.Logger == nil {
				t.Fatal("Logger = nil, want non-nil")
			}
			if got.Terminal.ID != tt.wantTerminalID {
				t.Fatalf("Terminal.ID = %q, want %q", got.Terminal.ID, tt.wantTerminalID)
			}
			if gotEPDG := configEPDG(got); gotEPDG != tt.wantEPDG {
				t.Fatalf("EPDG = %q, want %q", gotEPDG, tt.wantEPDG)
			}
			if got.IMS.Transport != tt.wantTransport {
				t.Fatalf("IMS.Transport = %q, want %q", got.IMS.Transport, tt.wantTransport)
			}
			if got.IMS.IMEI != tt.wantIMSIMEI {
				t.Fatalf("IMS.IMEI = %q, want %q", got.IMS.IMEI, tt.wantIMSIMEI)
			}
			if got.IMS.PhoneContextDomain != tt.wantPhoneCtx {
				t.Fatalf("IMS.PhoneContextDomain = %q, want %q", got.IMS.PhoneContextDomain, tt.wantPhoneCtx)
			}
			if got.IMS.AccessNetworkInfo != tt.wantAccessInfo {
				t.Fatalf("IMS.AccessNetworkInfo = %q, want %q", got.IMS.AccessNetworkInfo, tt.wantAccessInfo)
			}
			if got.ReconnectDelay != tt.wantReconnect {
				t.Fatalf("ReconnectDelay = %v, want %v", got.ReconnectDelay, tt.wantReconnect)
			}
			if got.ReconnectMaxDelay != tt.wantReconnectMax {
				t.Fatalf("ReconnectMaxDelay = %v, want %v", got.ReconnectMaxDelay, tt.wantReconnectMax)
			}
			if got.IMS.RegisterExpires != tt.wantRegisterExp {
				t.Fatalf("IMS.RegisterExpires = %v, want %v", got.IMS.RegisterExpires, tt.wantRegisterExp)
			}
			if got.IMS.RegistrationRetryBase != tt.wantIMSRetryBase {
				t.Fatalf("IMS.RegistrationRetryBase = %v, want %v", got.IMS.RegistrationRetryBase, tt.wantIMSRetryBase)
			}
			if got.IMS.RegistrationRetryMax != tt.wantIMSRetryMax {
				t.Fatalf("IMS.RegistrationRetryMax = %v, want %v", got.IMS.RegistrationRetryMax, tt.wantIMSRetryMax)
			}
			if gotSIPPort := configTunnel(got).SIPPort; gotSIPPort != tt.wantSIPPort {
				t.Fatalf("Tunnel.SIPPort = %d, want %d", gotSIPPort, tt.wantSIPPort)
			}
			if got.IMS.SIPServerPort != 0 && got.IMS.SIPServerPort != tt.wantSIPPort {
				t.Fatalf("IMS.SIPServerPort = %d, want %d", got.IMS.SIPServerPort, tt.wantSIPPort)
			}
			if got.IMS.SIPTimers.T1 != tt.wantSIPT1 {
				t.Fatalf("IMS.SIPTimers.T1 = %v, want %v", got.IMS.SIPTimers.T1, tt.wantSIPT1)
			}
			if got.IMS.SIPTimers.TF != tt.wantSIPTF {
				t.Fatalf("IMS.SIPTimers.TF = %v, want %v", got.IMS.SIPTimers.TF, tt.wantSIPTF)
			}
			if got.IMS.SMSDeliveryReportTimeout != tt.wantSMSTR2 {
				t.Fatalf("IMS.SMSDeliveryReportTimeout = %v, want %v", got.IMS.SMSDeliveryReportTimeout, tt.wantSMSTR2)
			}
		})
	}
}

func TestIMSConfigNormalizedUSSDDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		want    string
		wantErr bool
	}{
		{name: "default", want: string(imsussd.DomainIMS)},
		{name: "ims", domain: " IMS ", want: string(imsussd.DomainIMS)},
		{name: "cs", domain: " CS ", want: string(imsussd.DomainCS)},
		{name: "disabled", domain: " disabled ", want: string(imsussd.DomainDisabled)},
		{name: "invalid", domain: "ussd-over-sip", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (IMSConfig{USSDDomain: tt.domain}).Normalized()
			if tt.wantErr {
				if err == nil {
					t.Fatal("Normalized() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			if got.USSDDomain != tt.want {
				t.Fatalf("USSDDomain = %q, want %q", got.USSDDomain, tt.want)
			}
		})
	}
}

func TestUserAgent(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "client ims config leaves user agent empty",
			got: func() string {
				cfg, err := Config{Terminal: TerminalInfo{ID: "356789012345678"}}.normalizedIMS()
				if err != nil {
					t.Fatalf("normalizedIMS() error = %v", err)
				}
				return cfg.UserAgent
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("user agent = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestConfigNormalizedIMSUsesTerminalInfo(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "does not build ims user agent from terminal info",
			cfg: Config{
				Terminal: TerminalInfo{
					ID:              "356789012345678",
					Vendor:          "Samsung",
					Model:           "SM-S921B",
					SoftwareVersion: "14",
					Build:           "UP1A.231005.007",
				},
			},
		},
		{
			name: "explicit ims user agent wins",
			cfg: Config{
				Terminal: TerminalInfo{
					ID:     "356789012345678",
					Vendor: "Samsung",
					Model:  "SM-S921B",
				},
				IMS: IMSConfig{
					UserAgent: "explicit-agent",
				},
			},
			want: "explicit-agent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.normalizedIMS()
			if err != nil {
				t.Fatalf("normalizedIMS() error = %v", err)
			}
			if got.UserAgent != tt.want {
				t.Fatalf("UserAgent = %q, want %q", got.UserAgent, tt.want)
			}
		})
	}
}

func TestRenderIMSUserAgent(t *testing.T) {
	tests := []struct {
		name     string
		template string
		cfg      Config
		profile  imsProfile
		want     string
	}{
		{
			name:     "replaces known wfc placeholders",
			template: "#MANUFACTURE#/#MODEL# Android #AV# #BUILD# #TYPE# #MCCMNC# #IMEISV# #OPERATOR# #HWSKU#",
			cfg: Config{
				Terminal: TerminalInfo{
					ID:              "356789012345678",
					Vendor:          "Google",
					Model:           "Pixel 10 Pro",
					SoftwareVersion: "16",
					Build:           "BD1A.250702.001",
					Type:            "Smartphone",
					HardwareSKU:     "Pixel 10 Pro",
				},
			},
			profile: imsProfile{
				MCC:    "530",
				MNC:    "24",
				WFCSPN: "2degrees",
			},
			want: "Google/Pixel 10 Pro Android 16 BD1A.250702.001 Smartphone 53024 3567890123456700 2degrees Pixel 10 Pro",
		},
		{
			name:     "uses configured terminal info",
			template: "#MANUFACTURER#/#MODEL# Android #AV# #BUILD# #TYPE# #HWSKU#",
			cfg: Config{
				Terminal: TerminalInfo{
					Vendor:          "Samsung",
					Model:           "SM-S921B",
					SoftwareVersion: "14",
					Build:           "UP1A.231005.007",
					Type:            "Phone",
					HardwareSKU:     "dm1q",
				},
			},
			want: "Samsung/SM-S921B Android 14 UP1A.231005.007 Phone dm1q",
		},
		{
			name:     "plain user agent is unchanged",
			template: "profile-agent",
			cfg:      Config{Terminal: TerminalInfo{ID: "356789012345678"}},
			profile:  imsProfile{},
			want:     "profile-agent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := renderIMSUserAgent(tt.template, tt.cfg, tt.profile); got != tt.want {
				t.Fatalf("renderIMSUserAgent() = %q, want %q", got, tt.want)
			}
		})
	}
}
