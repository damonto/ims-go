package imsclient

import (
	"log/slog"
	"testing"
	"time"
)

func TestConfigNormalized(t *testing.T) {
	logger := slog.Default()
	tests := []struct {
		name            string
		cfg             Config
		wantErr         bool
		wantIMEI        string
		wantEPDG        string
		wantRegion      string
		wantTransport   string
		wantIMSIMEI     string
		wantReconnect   time.Duration
		wantRegisterExp time.Duration
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
			wantRegion:      "US",
			wantTransport:   "tcp",
			wantIMSIMEI:     "12345",
			wantReconnect:   defaultReconnectDelay,
			wantRegisterExp: 10 * time.Minute,
		},
		{
			name: "explicit epdg wins over automatic default",
			cfg: Config{
				IMEI: "root-imei",
				EPDG: " epdg.example.com ",
			},
			wantIMEI:        "root-imei",
			wantEPDG:        "epdg.example.com",
			wantRegion:      "US",
			wantTransport:   "tcp",
			wantIMSIMEI:     "root-imei",
			wantReconnect:   defaultReconnectDelay,
			wantRegisterExp: 10 * time.Minute,
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
			wantRegion:      "US",
			wantTransport:   "tcp",
			wantIMSIMEI:     testIMEI,
			wantReconnect:   defaultReconnectDelay,
			wantRegisterExp: 10 * time.Minute,
		},
		{
			name: "explicit ims transport is preserved",
			cfg: Config{
				IMEI: testIMEI,
				IMS: IMSConfig{
					Transport: "udp",
					Region:    " NZ ",
				},
			},
			wantIMEI:        testIMEI,
			wantEPDG:        "epdg.epc.mnc001.mcc001.pub.3gppnetwork.org",
			wantRegion:      "NZ",
			wantTransport:   "udp",
			wantIMSIMEI:     testIMEI,
			wantReconnect:   defaultReconnectDelay,
			wantRegisterExp: 10 * time.Minute,
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
			if got.IMS.Region != tt.wantRegion {
				t.Fatalf("IMS.Region = %q, want %q", got.IMS.Region, tt.wantRegion)
			}
			if got.IMS.IMEI != tt.wantIMSIMEI {
				t.Fatalf("IMS.IMEI = %q, want %q", got.IMS.IMEI, tt.wantIMSIMEI)
			}
			if got.ReconnectDelay != tt.wantReconnect {
				t.Fatalf("ReconnectDelay = %v, want %v", got.ReconnectDelay, tt.wantReconnect)
			}
			if got.IMS.RegisterExpires != tt.wantRegisterExp {
				t.Fatalf("IMS.RegisterExpires = %v, want %v", got.IMS.RegisterExpires, tt.wantRegisterExp)
			}
		})
	}
}
