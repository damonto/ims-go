package transport

import (
	"net"
	"testing"

	"github.com/damonto/vowifi-go/swu/esp"
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

func TestValidateSecureESPConfigRejectsNullEncryptionWithoutIntegrity(t *testing.T) {
	err := validateSecureESPConfig("testing secure transport", esp.EncryptionNull, esp.IntegrityNone, nil, nil)
	if err == nil {
		t.Fatal("validateSecureESPConfig() error = nil, want error")
	}
}
