package tunnel

import "testing"

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
			if got.Logger == nil {
				t.Fatal("Logger = nil, want default logger")
			}
		})
	}
}
