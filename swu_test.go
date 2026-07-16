package ims

import (
	"testing"

	swutunnel "github.com/damonto/ims-go/swu/tunnel"
)

func TestSWUAPNPolicyKeys(t *testing.T) {
	tests := []struct {
		name string
		cfg  swutunnel.Config
		want string
	}{
		{name: "implicit ims apn", want: swutunnel.DefaultAPN},
		{name: "explicit apn", cfg: swutunnel.Config{APN: " Internet "}, want: "internet"},
		{name: "network default apn", cfg: swutunnel.Config{RequestDefaultAPN: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Access: VoWiFi(VoWiFiConfig{Tunnel: tt.cfg})}
			if got := swuBackoffAPNFor(cfg); got != tt.want {
				t.Errorf("swuBackoffAPNFor() = %q, want %q", got, tt.want)
			}
			if got := swuPDNTypeRestrictionAPNFor(tt.cfg); got != tt.want {
				t.Errorf("swuPDNTypeRestrictionAPNFor() = %q, want %q", got, tt.want)
			}
		})
	}
}
