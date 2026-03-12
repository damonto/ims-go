package imsclient

import (
	"log/slog"
	"testing"
	"time"

	"github.com/damonto/ims-client/ims"
)

func TestConfigNormalized(t *testing.T) {
	logger := slog.Default()
	tests := []struct {
		name               string
		cfg                Config
		wantErr            bool
		wantIMEI           string
		wantPCSCFAddress   string
		wantIMSProxyAddr   string
		wantIMSUserAgent   string
		wantIMSIMEI        string
		wantIMSRegisterExp time.Duration
	}{
		{
			name: "propagates defaults",
			cfg: Config{
				Logger:          logger,
				IMEI:            " 12345 ",
				PCSCFAddress:    " 127.0.0.1:5060 ",
				UserAgent:       " test-agent ",
				RegisterExpires: 1,
				IMS:             ims.Config{},
			},
			wantIMEI:           "12345",
			wantPCSCFAddress:   "127.0.0.1:5060",
			wantIMSProxyAddr:   "127.0.0.1:5060",
			wantIMSUserAgent:   "test-agent",
			wantIMSIMEI:        "12345",
			wantIMSRegisterExp: 1,
		},
		{
			name: "keeps explicit ims values",
			cfg: Config{
				IMEI:            "root-imei",
				PCSCFAddress:    "root.proxy:5060",
				UserAgent:       "root-agent",
				RegisterExpires: time.Minute,
				IMS: ims.Config{
					ProxyAddr:       "ims.proxy:5060",
					UserAgent:       "ims-agent",
					IMEI:            "ims-imei",
					RegisterExpires: 2 * time.Minute,
				},
			},
			wantIMEI:           "root-imei",
			wantPCSCFAddress:   "root.proxy:5060",
			wantIMSProxyAddr:   "ims.proxy:5060",
			wantIMSUserAgent:   "ims-agent",
			wantIMSIMEI:        "ims-imei",
			wantIMSRegisterExp: 2 * time.Minute,
		},
		{
			name:    "rejects negative register expires",
			cfg:     Config{RegisterExpires: -1},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.normalized()
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
			if got.PCSCFAddress != tt.wantPCSCFAddress {
				t.Fatalf("PCSCFAddress = %q, want %q", got.PCSCFAddress, tt.wantPCSCFAddress)
			}
			if got.IMS.ProxyAddr != tt.wantIMSProxyAddr {
				t.Fatalf("IMS.ProxyAddr = %q, want %q", got.IMS.ProxyAddr, tt.wantIMSProxyAddr)
			}
			if got.IMS.UserAgent != tt.wantIMSUserAgent {
				t.Fatalf("IMS.UserAgent = %q, want %q", got.IMS.UserAgent, tt.wantIMSUserAgent)
			}
			if got.IMS.IMEI != tt.wantIMSIMEI {
				t.Fatalf("IMS.IMEI = %q, want %q", got.IMS.IMEI, tt.wantIMSIMEI)
			}
			if got.IMS.RegisterExpires != tt.wantIMSRegisterExp {
				t.Fatalf("IMS.RegisterExpires = %v, want %v", got.IMS.RegisterExpires, tt.wantIMSRegisterExp)
			}
		})
	}
}
