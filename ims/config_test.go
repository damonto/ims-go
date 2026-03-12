package ims

import "testing"

func TestConfigNormalized(t *testing.T) {
	tests := []struct {
		name          string
		cfg           Config
		wantTransport string
		wantErr       bool
	}{
		{name: "defaults", cfg: Config{}, wantTransport: "udp"},
		{name: "lowercases transport", cfg: Config{Transport: " TCP "}, wantTransport: "tcp"},
		{name: "rejects invalid transport", cfg: Config{Transport: "sctp"}, wantErr: true},
		{name: "rejects negative expires", cfg: Config{RegisterExpires: -1}, wantErr: true},
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
			if got.Transport != tt.wantTransport {
				t.Fatalf("Transport = %q, want %q", got.Transport, tt.wantTransport)
			}
			if got.Logger == nil {
				t.Fatal("Logger = nil, want non-nil")
			}
		})
	}
}
