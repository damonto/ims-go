package transport

import (
	"net"
	"strings"
	"testing"

	"github.com/damonto/vowifi-go/swu/esp"
	"github.com/damonto/vowifi-go/swu/packet"
)

func TestRemoteAddrOverridesIP(t *testing.T) {
	innerRemote := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5060}
	override := net.IPv4(10, 0, 0, 2)

	tcp := tcpRemoteAddr(innerRemote, 6000, override)
	if !tcp.IP.Equal(override) || tcp.Port != 6000 {
		t.Fatalf("tcp remote = %s, want %s:6000", tcp, override)
	}

	udp := udpRemoteAddr(innerRemote, 6000, override)
	if !udp.IP.Equal(override) || udp.Port != 6000 {
		t.Fatalf("udp remote = %s, want %s:6000", udp, override)
	}
}

func TestSecureEncryption(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "empty defaults to null", want: esp.EncryptionNull},
		{name: "null", value: " NULL ", want: esp.EncryptionNull},
		{name: "aes cbc", value: "AES-CBC", want: esp.EncryptionAESCBC},
		{name: "unsupported", value: "aes-gcm", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := secureEncryption(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatal("secureEncryption() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("secureEncryption() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("secureEncryption() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateSecureESPConfigRequiresIntegrity(t *testing.T) {
	tests := []struct {
		name       string
		encryption string
		key        []byte
	}{
		{name: "null encryption"},
		{name: "aes cbc encryption", encryption: esp.EncryptionAESCBC, key: []byte("0123456789abcdef")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSecureESPConfig(tt.encryption, esp.IntegrityNone, tt.key, nil)
			if err == nil {
				t.Fatal("validateSecureESPConfig() error = nil, want integrity error")
			}
			if !strings.Contains(err.Error(), "integrity must be enabled") {
				t.Fatalf("validateSecureESPConfig() error = %v, want integrity error", err)
			}
		})
	}
}

func TestValidateSecureSPIsRejectsReservedValues(t *testing.T) {
	tests := []struct {
		name     string
		outbound uint32
		inbound  uint32
		wantErr  bool
	}{
		{name: "valid", outbound: 256, inbound: 257},
		{name: "zero outbound", outbound: 0, inbound: 257, wantErr: true},
		{name: "reserved inbound", outbound: 256, inbound: 255, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSecureSPIs(tt.outbound, tt.inbound)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "spi is reserved") {
					t.Fatalf("validateSecureSPIs() error = %v, want reserved spi", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateSecureSPIs() error = %v", err)
			}
		})
	}
}

func TestUDPFlowMatches(t *testing.T) {
	local := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40000}
	remote := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5060}

	tests := []struct {
		name    string
		segment *packet.UDPSegment
		want    bool
	}{
		{
			name: "matching four tuple",
			segment: &packet.UDPSegment{
				Src: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5060},
				Dst: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40000},
			},
			want: true,
		},
		{
			name: "different local IP",
			segment: &packet.UDPSegment{
				Src: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5060},
				Dst: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 3), Port: 40000},
			},
		},
		{
			name: "different remote port",
			segment: &packet.UDPSegment{
				Src: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 6000},
				Dst: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40000},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := udpFlowMatches(tt.segment, local, remote); got != tt.want {
				t.Fatalf("udpFlowMatches() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestTCPFlowMatches(t *testing.T) {
	local := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40000}
	remote := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5060}

	tests := []struct {
		name    string
		segment *packet.TCPSegment
		want    bool
	}{
		{
			name: "matching four tuple",
			segment: &packet.TCPSegment{
				Src: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5060},
				Dst: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40000},
			},
			want: true,
		},
		{
			name: "different local IP",
			segment: &packet.TCPSegment{
				Src: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5060},
				Dst: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 3), Port: 40000},
			},
		},
		{
			name: "different remote port",
			segment: &packet.TCPSegment{
				Src: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 6000},
				Dst: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40000},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tcpFlowMatches(tt.segment, local, remote); got != tt.want {
				t.Fatalf("tcpFlowMatches() = %t, want %t", got, tt.want)
			}
		})
	}
}
