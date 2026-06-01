package transport

import (
	"testing"

	"github.com/damonto/vowifi-go/swu/esp"
)

func TestAcceptInboundESPReplayRequiresIntegrity(t *testing.T) {
	tests := []struct {
		name      string
		integrity string
		want      []bool
	}{
		{
			name:      "integrity enabled rejects duplicate sequence",
			integrity: esp.IntegrityHMACSHA196,
			want:      []bool{true, false},
		},
		{
			name:      "integrity none leaves replay disabled",
			integrity: esp.IntegrityNone,
			want:      []bool{true, true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/udp", func(t *testing.T) {
			conn := &UDPConn{inboundESP: esp.Codec{Integrity: tt.integrity}, associations: NewSecurityAssociations()}
			for i, want := range tt.want {
				if got := conn.acceptInboundESP(1); got != want {
					t.Fatalf("acceptInboundESP call %d = %t, want %t", i+1, got, want)
				}
			}
		})
		t.Run(tt.name+"/tcp", func(t *testing.T) {
			conn := &TCPConn{inboundESP: esp.Codec{Integrity: tt.integrity}, associations: NewSecurityAssociations()}
			for i, want := range tt.want {
				if got := conn.acceptInboundESP(1); got != want {
					t.Fatalf("acceptInboundESP call %d = %t, want %t", i+1, got, want)
				}
			}
		})
	}
}
