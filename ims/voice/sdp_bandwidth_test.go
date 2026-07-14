package voice

import (
	"net"
	"testing"
	"time"
)

func TestCodecBandwidthAS(t *testing.T) {
	tests := []struct {
		name  string
		codec AudioCodecConfig
		ip    net.IP
		ptime time.Duration
		want  int
	}{
		{name: "EVS IPv4", codec: AudioCodecConfig{Name: CodecEVS, Bitrate: "5.9-13.2"}, ip: net.IPv4(192, 0, 2, 1), ptime: 20 * time.Millisecond, want: 30},
		{name: "EVS IPv6", codec: AudioCodecConfig{Name: CodecEVS, Bitrate: "5.9-13.2"}, ip: net.ParseIP("2001:db8::1"), ptime: 20 * time.Millisecond, want: 38},
		{name: "AMR bandwidth efficient IPv4", codec: AudioCodecConfig{Name: CodecAMR}, ip: net.IPv4(192, 0, 2, 1), ptime: 20 * time.Millisecond, want: 29},
		{name: "AMR bandwidth efficient IPv6", codec: AudioCodecConfig{Name: CodecAMR}, ip: net.ParseIP("2001:db8::1"), ptime: 20 * time.Millisecond, want: 37},
		{name: "AMR octet aligned IPv4", codec: AudioCodecConfig{Name: CodecAMR, OctetAlign: true}, ip: net.IPv4(192, 0, 2, 1), ptime: 20 * time.Millisecond, want: 30},
		{name: "AMR-WB bandwidth efficient IPv6", codec: AudioCodecConfig{Name: CodecAMRWB}, ip: net.ParseIP("2001:db8::1"), ptime: 20 * time.Millisecond, want: 49},
		{name: "AMR-WB octet aligned IPv4", codec: AudioCodecConfig{Name: CodecAMRWB, OctetAlign: true}, ip: net.IPv4(192, 0, 2, 1), ptime: 20 * time.Millisecond, want: 42},
		{name: "PCMU IPv4", codec: AudioCodecConfig{Name: CodecPCMU}, ip: net.IPv4(192, 0, 2, 1), ptime: 20 * time.Millisecond, want: 80},
		{name: "PCMU IPv6", codec: AudioCodecConfig{Name: CodecPCMU}, ip: net.ParseIP("2001:db8::1"), ptime: 20 * time.Millisecond, want: 88},
		{name: "PCMU IPv6 aggregated", codec: AudioCodecConfig{Name: CodecPCMU}, ip: net.ParseIP("2001:db8::1"), ptime: 40 * time.Millisecond, want: 76},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := codecBandwidthAS(tt.codec, tt.ip, tt.ptime); got != tt.want {
				t.Fatalf("codecBandwidthAS() = %d, want %d", got, tt.want)
			}
		})
	}
}
