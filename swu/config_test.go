package swu

import "testing"

func TestConfigNormalized(t *testing.T) {
	tests := []struct {
		name     string
		cfg      Config
		wantNATT int
		wantErr  bool
	}{
		{name: "defaults ports", cfg: Config{}, wantNATT: 4500},
		{name: "rejects invalid sip port", cfg: Config{SIPPort: 70000}, wantErr: true},
		{name: "rejects invalid natt port", cfg: Config{NATTPort: -1}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.Normalized()
			if tt.wantErr {
				if err == nil {
					t.Fatal("normalized() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalized() error = %v", err)
			}
			if got.NATTPort != tt.wantNATT {
				t.Fatalf("NATTPort = %d, want %d", got.NATTPort, tt.wantNATT)
			}
			if got.Logger == nil {
				t.Fatal("Logger = nil, want non-nil")
			}
		})
	}
}
