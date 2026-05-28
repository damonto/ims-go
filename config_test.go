package vowifi

import (
	"log/slog"
	"testing"
	"time"

	imssession "github.com/damonto/vowifi-go/ims/session"
)

func TestConfigNormalized(t *testing.T) {
	logger := slog.Default()
	tests := []struct {
		name            string
		cfg             Config
		wantErr         bool
		wantIMEI        string
		wantEPDG        string
		wantTransport   string
		wantIMSIMEI     string
		wantPhoneCtx    string
		wantAccessInfo  string
		wantReconnect   time.Duration
		wantRegisterExp time.Duration
		wantSIPPort     int
		wantSIPT1       time.Duration
		wantSIPTF       time.Duration
		wantSMSTR1      time.Duration
	}{
		{
			name: "defaults build epdg from card",
			cfg: Config{
				Logger: logger,
				IMEI:   " 12345 ",
				IMS:    IMSConfig{},
			},
			wantIMEI:        "12345",
			wantEPDG:        "epdg.epc.mnc001.mcc001.pub.3gppnetwork.org",
			wantTransport:   "tcp",
			wantIMSIMEI:     "12345",
			wantAccessInfo:  "IEEE-802.11",
			wantReconnect:   defaultReconnectDelay,
			wantRegisterExp: 600000 * time.Second,
			wantSIPPort:     5060,
			wantSIPT1:       2 * time.Second,
			wantSIPTF:       128 * time.Second,
			wantSMSTR1:      130 * time.Second,
		},
		{
			name: "explicit epdg wins over automatic default",
			cfg: Config{
				IMEI: "root-imei",
				EPDG: " epdg.example.com ",
			},
			wantIMEI:        "root-imei",
			wantEPDG:        "epdg.example.com",
			wantTransport:   "tcp",
			wantIMSIMEI:     "root-imei",
			wantAccessInfo:  "IEEE-802.11",
			wantReconnect:   defaultReconnectDelay,
			wantRegisterExp: 600000 * time.Second,
			wantSIPPort:     5060,
			wantSIPT1:       2 * time.Second,
			wantSIPTF:       128 * time.Second,
			wantSMSTR1:      130 * time.Second,
		},
		{
			name: "cfg nil clone still normalizes as zero config",
			cfg: func() Config {
				cfg := cloneConfig(nil)
				cfg.IMEI = testIMEI
				return cfg
			}(),
			wantIMEI:        testIMEI,
			wantEPDG:        "epdg.epc.mnc001.mcc001.pub.3gppnetwork.org",
			wantTransport:   "tcp",
			wantIMSIMEI:     testIMEI,
			wantAccessInfo:  "IEEE-802.11",
			wantReconnect:   defaultReconnectDelay,
			wantRegisterExp: 600000 * time.Second,
			wantSIPPort:     5060,
			wantSIPT1:       2 * time.Second,
			wantSIPTF:       128 * time.Second,
			wantSMSTR1:      130 * time.Second,
		},
		{
			name: "explicit ims transport is preserved",
			cfg: Config{
				IMEI: testIMEI,
				IMS: IMSConfig{
					Transport: "udp",
				},
			},
			wantIMEI:        testIMEI,
			wantEPDG:        "epdg.epc.mnc001.mcc001.pub.3gppnetwork.org",
			wantTransport:   "udp",
			wantIMSIMEI:     testIMEI,
			wantAccessInfo:  "IEEE-802.11",
			wantReconnect:   defaultReconnectDelay,
			wantRegisterExp: 600000 * time.Second,
			wantSIPPort:     5060,
			wantSIPT1:       2 * time.Second,
			wantSIPTF:       128 * time.Second,
			wantSMSTR1:      130 * time.Second,
		},
		{
			name: "explicit ims profile values are preserved",
			cfg: Config{
				IMEI: testIMEI,
				IMS: IMSConfig{
					AccessNetworkInfo:      "IEEE-802.11ac;i-wlan-node-id=aabbcc",
					PhoneContextDomain:     "ims.example",
					SIPServerPort:          5070,
					SIPTimers:              imssession.TransactionTimers{T1: time.Second, TF: 45 * time.Second},
					SMSSubmitReportTimeout: 45 * time.Second,
				},
			},
			wantIMEI:        testIMEI,
			wantEPDG:        "epdg.epc.mnc001.mcc001.pub.3gppnetwork.org",
			wantTransport:   "tcp",
			wantIMSIMEI:     testIMEI,
			wantPhoneCtx:    "ims.example",
			wantAccessInfo:  "IEEE-802.11ac;i-wlan-node-id=aabbcc",
			wantReconnect:   defaultReconnectDelay,
			wantRegisterExp: 600000 * time.Second,
			wantSIPPort:     5070,
			wantSIPT1:       time.Second,
			wantSIPTF:       45 * time.Second,
			wantSMSTR1:      45 * time.Second,
		},
		{
			name: "missing imei fails",
			cfg: Config{
				Logger: logger,
			},
			wantErr: true,
		},
		{
			name: "negative reconnect delay fails",
			cfg: Config{
				IMEI:           testIMEI,
				ReconnectDelay: -time.Second,
			},
			wantErr: true,
		},
		{
			name: "negative sip timer fails",
			cfg: Config{
				IMEI: testIMEI,
				IMS: IMSConfig{
					SIPTimers: imssession.TransactionTimers{T1: -time.Second},
				},
			},
			wantErr: true,
		},
		{
			name: "negative sms submit report timeout fails",
			cfg: Config{
				IMEI: testIMEI,
				IMS: IMSConfig{
					SMSSubmitReportTimeout: -time.Second,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid sip server port fails",
			cfg: Config{
				IMEI: testIMEI,
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
			if got.IMEI != tt.wantIMEI {
				t.Fatalf("IMEI = %q, want %q", got.IMEI, tt.wantIMEI)
			}
			if got.EPDG != tt.wantEPDG {
				t.Fatalf("EPDG = %q, want %q", got.EPDG, tt.wantEPDG)
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
			if got.IMS.RegisterExpires != tt.wantRegisterExp {
				t.Fatalf("IMS.RegisterExpires = %v, want %v", got.IMS.RegisterExpires, tt.wantRegisterExp)
			}
			if got.Tunnel.SIPPort != tt.wantSIPPort {
				t.Fatalf("Tunnel.SIPPort = %d, want %d", got.Tunnel.SIPPort, tt.wantSIPPort)
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
			if got.IMS.SMSSubmitReportTimeout != tt.wantSMSTR1 {
				t.Fatalf("IMS.SMSSubmitReportTimeout = %v, want %v", got.IMS.SMSSubmitReportTimeout, tt.wantSMSTR1)
			}
		})
	}
}
