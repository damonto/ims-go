package tunnel

import (
	"strings"
	"testing"
	"time"
)

func TestConfigNormalized(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "defaults",
			cfg: Config{
				RemoteAddr: " 127.0.0.1:500 ",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			if got.RemoteAddr != "127.0.0.1:500" {
				t.Fatalf("RemoteAddr = %q, want %q", got.RemoteAddr, "127.0.0.1:500")
			}
			if got.NATTPort != 4500 || got.LocalSIPPort != 5062 || got.SIPPort != 5060 {
				t.Fatalf("ports = %+v", got)
			}
			if len(got.DHGroups) != 1 || got.DHGroups[0] != transformDH2048MODP {
				t.Fatalf("DHGroups = %v, want [14]", got.DHGroups)
			}
			if len(got.IKEEncryptionKeyLens) != 2 || got.IKEEncryptionKeyLens[0] != 128 || got.IKEEncryptionKeyLens[1] != 256 {
				t.Fatalf("IKEEncryptionKeyLens = %v, want [128 256]", got.IKEEncryptionKeyLens)
			}
			if len(got.IKEIntegrity) != 1 || got.IKEIntegrity[0] != transformINTEGHMACSHA256 {
				t.Fatalf("IKEIntegrity = %v, want [12]", got.IKEIntegrity)
			}
			if len(got.IKEPRF) != 2 || got.IKEPRF[0] != transformPRFHMACSHA1 || got.IKEPRF[1] != transformPRFHMACSHA256 {
				t.Fatalf("IKEPRF = %v, want [2 5]", got.IKEPRF)
			}
			if len(got.ChildEncryptionKeyLens) != 2 || got.ChildEncryptionKeyLens[0] != 128 || got.ChildEncryptionKeyLens[1] != 256 {
				t.Fatalf("ChildEncryptionKeyLens = %v, want [128 256]", got.ChildEncryptionKeyLens)
			}
			if len(got.ChildIntegrity) != 1 || got.ChildIntegrity[0] != transformINTEGHMACSHA256 {
				t.Fatalf("ChildIntegrity = %v, want [12]", got.ChildIntegrity)
			}
			if got.NATKeepaliveInterval != 20*time.Second {
				t.Fatalf("NATKeepaliveInterval = %s, want 20s", got.NATKeepaliveInterval)
			}
			if len(got.IKERetransmitDelays) != len(defaultIKERetransmitDelays) {
				t.Fatalf("IKERetransmitDelays = %v, want %v", got.IKERetransmitDelays, defaultIKERetransmitDelays)
			}
			if got.Logger == nil {
				t.Fatal("Logger = nil, want default logger")
			}
		})
	}
}

func TestConfigNormalizedAdvancedFields(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
		check   func(t *testing.T, got Config)
	}{
		{
			name: "custom carrier timers and dh groups",
			cfg: Config{
				RemoteAddr:             "127.0.0.1",
				DHGroups:               []uint16{transformDH2048MODP},
				IKEEncryptionKeyLens:   []uint16{256},
				IKEIntegrity:           []uint16{transformINTEGHMACSHA196},
				IKEPRF:                 []uint16{transformPRFHMACSHA1},
				ChildEncryptionKeyLens: []uint16{128},
				ChildIntegrity:         []uint16{transformINTEGHMACSHA196},
				NATKeepaliveInterval:   30 * time.Second,
				IKERetransmitDelays:    []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second},
			},
			check: func(t *testing.T, got Config) {
				t.Helper()
				if len(got.DHGroups) != 1 || got.DHGroups[0] != transformDH2048MODP {
					t.Fatalf("DHGroups = %v, want [14]", got.DHGroups)
				}
				if len(got.IKEEncryptionKeyLens) != 1 || got.IKEEncryptionKeyLens[0] != 256 {
					t.Fatalf("IKEEncryptionKeyLens = %v, want [256]", got.IKEEncryptionKeyLens)
				}
				if len(got.IKEIntegrity) != 1 || got.IKEIntegrity[0] != transformINTEGHMACSHA196 {
					t.Fatalf("IKEIntegrity = %v, want [2]", got.IKEIntegrity)
				}
				if len(got.IKEPRF) != 1 || got.IKEPRF[0] != transformPRFHMACSHA1 {
					t.Fatalf("IKEPRF = %v, want [2]", got.IKEPRF)
				}
				if len(got.ChildEncryptionKeyLens) != 1 || got.ChildEncryptionKeyLens[0] != 128 {
					t.Fatalf("ChildEncryptionKeyLens = %v, want [128]", got.ChildEncryptionKeyLens)
				}
				if len(got.ChildIntegrity) != 1 || got.ChildIntegrity[0] != transformINTEGHMACSHA196 {
					t.Fatalf("ChildIntegrity = %v, want [2]", got.ChildIntegrity)
				}
				if got.NATKeepaliveInterval != 30*time.Second {
					t.Fatalf("NATKeepaliveInterval = %s, want 30s", got.NATKeepaliveInterval)
				}
				if len(got.IKERetransmitDelays) != 4 || got.IKERetransmitDelays[0] != time.Second || got.IKERetransmitDelays[3] != 8*time.Second {
					t.Fatalf("IKERetransmitDelays = %v, want [1s 2s 4s 8s]", got.IKERetransmitDelays)
				}
			},
		},
		{
			name: "unsupported dh group",
			cfg: Config{
				RemoteAddr: "127.0.0.1",
				DHGroups:   []uint16{15},
			},
			wantErr: "dh group 15 is unsupported",
		},
		{
			name: "unsupported ike integrity",
			cfg: Config{
				RemoteAddr:   "127.0.0.1",
				IKEIntegrity: []uint16{5},
			},
			wantErr: "ike integrity transforms value 5 is unsupported",
		},
		{
			name: "unsupported ike prf",
			cfg: Config{
				RemoteAddr: "127.0.0.1",
				IKEPRF:     []uint16{4},
			},
			wantErr: "ike prf transforms value 4 is unsupported",
		},
		{
			name: "short ike retransmit delay",
			cfg: Config{
				RemoteAddr:          "127.0.0.1",
				IKERetransmitDelays: []time.Duration{499 * time.Millisecond},
			},
			wantErr: "ike retransmit delays entry 499ms must be between 500ms and 30m",
		},
		{
			name: "negative natt keepalive",
			cfg: Config{
				RemoteAddr:           "127.0.0.1",
				NATKeepaliveInterval: -time.Second,
			},
			wantErr: "natt keepalive interval must be >= 0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.Normalized()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Normalized() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			tt.check(t, got)
		})
	}
}
