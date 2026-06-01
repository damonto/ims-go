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
			if got.AKAPrimeNetworkName != defaultAKAPrimeNetworkName {
				t.Fatalf("AKAPrimeNetworkName = %q, want %q", got.AKAPrimeNetworkName, defaultAKAPrimeNetworkName)
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
			if got.LivenessTimeout != defaultLivenessTimeout {
				t.Fatalf("LivenessTimeout = %s, want %s", got.LivenessTimeout, defaultLivenessTimeout)
			}
			if got.IKESALifetime != defaultIKESARekeyHardTimer || got.IKESARekeyMargin != defaultIKESARekeyHardTimer-defaultIKESARekeySoftTimer {
				t.Fatalf("IKE SA lifetime = %s/%s, want WFC default hard/soft timers", got.IKESALifetime, got.IKESARekeyMargin)
			}
			if got.ChildSALifetime != defaultChildSARekeyHardTimer || got.ChildSARekeyMargin != defaultChildSARekeyHardTimer-defaultChildSARekeySoftTimer {
				t.Fatalf("Child SA lifetime = %s/%s, want WFC default hard/soft timers", got.ChildSALifetime, got.ChildSARekeyMargin)
			}
			if len(got.IKERetransmitDelays) != len(defaultIKERetransmitDelays) {
				t.Fatalf("IKERetransmitDelays = %v, want %v", got.IKERetransmitDelays, defaultIKERetransmitDelays)
			}
			var retransmitWindow time.Duration
			for i, delay := range got.IKERetransmitDelays {
				retransmitWindow += delay
				if i > 0 && delay < got.IKERetransmitDelays[i-1]*2 {
					t.Fatalf("IKERetransmitDelays[%d] = %s, previous = %s", i, delay, got.IKERetransmitDelays[i-1])
				}
			}
			if len(got.IKERetransmitDelays) < 12 || retransmitWindow < 3*time.Minute {
				t.Fatalf("IKERetransmitDelays = %v, want at least 12 attempts over several minutes", got.IKERetransmitDelays)
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
				RemoteAddr:                       "127.0.0.1",
				DHGroups:                         []uint16{transformDH2048MODP},
				IKEEncryptionKeyLens:             []uint16{256},
				IKEIntegrity:                     []uint16{transformINTEGHMACSHA196},
				IKEPRF:                           []uint16{transformPRFHMACSHA1},
				ChildEncryptionKeyLens:           []uint16{128},
				ChildIntegrity:                   []uint16{transformINTEGHMACSHA196},
				NATKeepaliveInterval:             30 * time.Second,
				LivenessTimeout:                  90 * time.Second,
				IKERetransmitDelays:              []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second},
				IKESALifetime:                    2 * time.Hour,
				IKESARekeyMargin:                 15 * time.Minute,
				IKESAByteLifetime:                2048,
				IKESAByteRekeyMargin:             256,
				ChildSALifetime:                  time.Hour,
				ChildSARekeyMargin:               10 * time.Minute,
				ChildSAByteLifetime:              1024,
				ChildSAByteRekeyMargin:           128,
				AKAPrimeNetworkName:              " WLAN:example ",
				AllowAKAPrimeNetworkNameMismatch: true,
			},
			check: func(t *testing.T, got Config) {
				t.Helper()
				if got.AKAPrimeNetworkName != "WLAN:example" {
					t.Fatalf("AKAPrimeNetworkName = %q, want %q", got.AKAPrimeNetworkName, "WLAN:example")
				}
				if !got.AllowAKAPrimeNetworkNameMismatch {
					t.Fatal("AllowAKAPrimeNetworkNameMismatch = false, want true")
				}
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
				if got.LivenessTimeout != 90*time.Second {
					t.Fatalf("LivenessTimeout = %s, want 90s", got.LivenessTimeout)
				}
				if len(got.IKERetransmitDelays) != 4 || got.IKERetransmitDelays[0] != time.Second || got.IKERetransmitDelays[3] != 8*time.Second {
					t.Fatalf("IKERetransmitDelays = %v, want [1s 2s 4s 8s]", got.IKERetransmitDelays)
				}
				if got.IKESALifetime != 2*time.Hour || got.IKESARekeyMargin != 15*time.Minute {
					t.Fatalf("IKE SA lifetimes = (%s, %s), want (2h0m0s, 15m0s)", got.IKESALifetime, got.IKESARekeyMargin)
				}
				if got.IKESAByteLifetime != 2048 || got.IKESAByteRekeyMargin != 256 {
					t.Fatalf("IKE SA byte lifetimes = (%d, %d), want (2048, 256)", got.IKESAByteLifetime, got.IKESAByteRekeyMargin)
				}
				if got.ChildSALifetime != time.Hour || got.ChildSARekeyMargin != 10*time.Minute {
					t.Fatalf("Child SA lifetimes = (%s, %s), want (1h0m0s, 10m0s)", got.ChildSALifetime, got.ChildSARekeyMargin)
				}
				if got.ChildSAByteLifetime != 1024 || got.ChildSAByteRekeyMargin != 128 {
					t.Fatalf("Child SA byte lifetimes = (%d, %d), want (1024, 128)", got.ChildSAByteLifetime, got.ChildSAByteRekeyMargin)
				}
			},
		},
		{
			name: "default child sa soft lifetime",
			cfg: Config{
				RemoteAddr:      "127.0.0.1",
				ChildSALifetime: time.Hour,
			},
			check: func(t *testing.T, got Config) {
				t.Helper()
				if got.ChildSARekeyMargin != 5*time.Minute {
					t.Fatalf("ChildSARekeyMargin = %s, want 5m0s", got.ChildSARekeyMargin)
				}
			},
		},
		{
			name: "default ike sa soft lifetime",
			cfg: Config{
				RemoteAddr:    "127.0.0.1",
				IKESALifetime: time.Hour,
			},
			check: func(t *testing.T, got Config) {
				t.Helper()
				if got.IKESARekeyMargin != 5*time.Minute {
					t.Fatalf("IKESARekeyMargin = %s, want 5m0s", got.IKESARekeyMargin)
				}
			},
		},
		{
			name: "default ike sa byte soft lifetime",
			cfg: Config{
				RemoteAddr:        "127.0.0.1",
				IKESAByteLifetime: 2000,
			},
			check: func(t *testing.T, got Config) {
				t.Helper()
				if got.IKESAByteRekeyMargin != 200 {
					t.Fatalf("IKESAByteRekeyMargin = %d, want 200", got.IKESAByteRekeyMargin)
				}
			},
		},
		{
			name: "default child sa byte soft lifetime",
			cfg: Config{
				RemoteAddr:          "127.0.0.1",
				ChildSAByteLifetime: 1000,
			},
			check: func(t *testing.T, got Config) {
				t.Helper()
				if got.ChildSAByteRekeyMargin != 100 {
					t.Fatalf("ChildSAByteRekeyMargin = %d, want 100", got.ChildSAByteRekeyMargin)
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
			name: "non exponential ike retransmit delay",
			cfg: Config{
				RemoteAddr:          "127.0.0.1",
				IKERetransmitDelays: []time.Duration{500 * time.Millisecond, 750 * time.Millisecond},
			},
			wantErr: "ike retransmit delays entry 750ms must be at least double previous entry 500ms",
		},
		{
			name: "negative natt keepalive",
			cfg: Config{
				RemoteAddr:           "127.0.0.1",
				NATKeepaliveInterval: -time.Second,
			},
			wantErr: "natt keepalive interval must be >= 0",
		},
		{
			name: "negative liveness timeout",
			cfg: Config{
				RemoteAddr:      "127.0.0.1",
				LivenessTimeout: -time.Second,
			},
			wantErr: "liveness timeout must be >= 0",
		},
		{
			name: "negative child sa lifetime",
			cfg: Config{
				RemoteAddr:      "127.0.0.1",
				ChildSALifetime: -time.Second,
			},
			wantErr: "child sa lifetime must be >= 0",
		},
		{
			name: "ike sa rekey margin without hard lifetime",
			cfg: Config{
				RemoteAddr:       "127.0.0.1",
				IKESARekeyMargin: time.Minute,
			},
			wantErr: "ike sa rekey margin requires ike sa lifetime",
		},
		{
			name: "child sa rekey margin without hard lifetime",
			cfg: Config{
				RemoteAddr:         "127.0.0.1",
				ChildSARekeyMargin: time.Minute,
			},
			wantErr: "child sa rekey margin requires child sa lifetime",
		},
		{
			name: "child sa rekey margin reaches hard lifetime",
			cfg: Config{
				RemoteAddr:         "127.0.0.1",
				ChildSALifetime:    time.Minute,
				ChildSARekeyMargin: time.Minute,
			},
			wantErr: "child sa rekey margin must be shorter than child sa lifetime",
		},
		{
			name: "ike sa byte rekey margin without hard lifetime",
			cfg: Config{
				RemoteAddr:           "127.0.0.1",
				IKESAByteRekeyMargin: 1,
			},
			wantErr: "ike sa byte rekey margin requires ike sa byte lifetime",
		},
		{
			name: "ike sa byte rekey margin reaches hard lifetime",
			cfg: Config{
				RemoteAddr:           "127.0.0.1",
				IKESAByteLifetime:    100,
				IKESAByteRekeyMargin: 100,
			},
			wantErr: "ike sa byte rekey margin must be shorter than ike sa byte lifetime",
		},
		{
			name: "child sa byte rekey margin without hard lifetime",
			cfg: Config{
				RemoteAddr:             "127.0.0.1",
				ChildSAByteRekeyMargin: 1,
			},
			wantErr: "child sa byte rekey margin requires child sa byte lifetime",
		},
		{
			name: "child sa byte rekey margin reaches hard lifetime",
			cfg: Config{
				RemoteAddr:             "127.0.0.1",
				ChildSAByteLifetime:    100,
				ChildSAByteRekeyMargin: 100,
			},
			wantErr: "child sa byte rekey margin must be shorter than child sa byte lifetime",
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
