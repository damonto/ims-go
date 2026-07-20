package transport

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/damonto/ims-go/ipsec/esp"
	"github.com/damonto/ims-go/ipsec/packet"
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
		{name: "aes gcm", value: "aes-gcm", want: esp.EncryptionAESGCM},
		{name: "unsupported", value: "des-ede3-cbc", wantErr: true},
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

func TestSecureMode(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "empty defaults to transport", want: SecureModeTransport},
		{name: "transport", value: " TRANS ", want: SecureModeTransport},
		{name: "udp encapsulated tunnel", value: "udp-enc-tun", want: SecureModeUDPEncTunnel},
		{name: "bare tunnel unsupported", value: "tun", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := secureMode(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatal("secureMode() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("secureMode() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("secureMode() = %q, want %q", got, tt.want)
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

func TestValidateSecureESPConfigAllowsAESGCMNullIntegrity(t *testing.T) {
	tests := []struct {
		name      string
		integrity string
		wantErr   bool
	}{
		{name: "null integrity", integrity: esp.IntegrityNull},
		{name: "none integrity", integrity: esp.IntegrityNone},
		{name: "hmac integrity rejected", integrity: esp.IntegrityHMACSHA196RFC, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSecureESPConfig(esp.EncryptionAESGCM, tt.integrity, []byte("0123456789abcdef"), nil)
			if tt.wantErr {
				if err == nil {
					t.Fatal("validateSecureESPConfig() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("validateSecureESPConfig() error = %v", err)
			}
		})
	}
}

func TestValidateSecureESPConfigRejectsAESGMACWithEncryption(t *testing.T) {
	tests := []struct {
		name       string
		encryption string
		wantErr    bool
	}{
		{name: "null encryption", encryption: esp.EncryptionNull},
		{name: "aes cbc encryption", encryption: esp.EncryptionAESCBC, wantErr: true},
		{name: "aes gcm encryption", encryption: esp.EncryptionAESGCM, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSecureESPConfig(tt.encryption, esp.IntegrityAESGMAC, []byte("0123456789abcdef"), []byte("0123456789abcdef"))
			if tt.wantErr {
				if err == nil {
					t.Fatal("validateSecureESPConfig() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("validateSecureESPConfig() error = %v", err)
			}
		})
	}
}

func TestValidateSecureESPConfigValidatesTS33203KeysAndAlgorithms(t *testing.T) {
	tests := []struct {
		name          string
		encryption    string
		integrity     string
		encryptionKey []byte
		integrityKey  []byte
		wantErr       bool
	}{
		{
			name:         "hmac sha1 key is 160 bits",
			encryption:   esp.EncryptionNull,
			integrity:    esp.IntegrityHMACSHA196RFC,
			integrityKey: []byte("0123456789abcdef0123"),
		},
		{
			name:         "short hmac sha1 key",
			encryption:   esp.EncryptionNull,
			integrity:    esp.IntegrityHMACSHA196RFC,
			integrityKey: []byte("0123456789abcdef"),
			wantErr:      true,
		},
		{
			name:          "aes cbc key is 128 bits",
			encryption:    esp.EncryptionAESCBC,
			integrity:     esp.IntegrityHMACSHA196RFC,
			encryptionKey: []byte("0123456789abcdef"),
			integrityKey:  []byte("0123456789abcdef0123"),
		},
		{
			name:          "aes cbc rejects 192 bit key",
			encryption:    esp.EncryptionAESCBC,
			integrity:     esp.IntegrityHMACSHA196RFC,
			encryptionKey: []byte("0123456789abcdefghijklmn"),
			integrityKey:  []byte("0123456789abcdef0123"),
			wantErr:       true,
		},
		{
			name:         "aes gmac key is 128 bits",
			encryption:   esp.EncryptionNull,
			integrity:    esp.IntegrityAESGMAC,
			integrityKey: []byte("0123456789abcdef"),
		},
		{
			name:         "legacy hmac md5 key is 128 bits",
			encryption:   esp.EncryptionNull,
			integrity:    esp.IntegrityHMACMD596,
			integrityKey: []byte("0123456789abcdef"),
		},
		{
			name:         "short hmac md5 key",
			encryption:   esp.EncryptionNull,
			integrity:    esp.IntegrityHMACMD596,
			integrityKey: []byte("0123456789abcde"),
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSecureESPConfig(tt.encryption, tt.integrity, tt.encryptionKey, tt.integrityKey)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateSecureESPConfig() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSecureSPIsRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name     string
		outbound uint32
		inbound  uint32
		wantErr  string
	}{
		{name: "valid", outbound: 256, inbound: 257},
		{name: "zero outbound", outbound: 0, inbound: 257, wantErr: "spi is reserved"},
		{name: "reserved inbound", outbound: 256, inbound: 255, wantErr: "spi is reserved"},
		{name: "duplicate spis", outbound: 256, inbound: 256, wantErr: "spi values must be unique"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSecureSPIs(tt.outbound, tt.inbound)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("validateSecureSPIs() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateSecureSPIs() error = %v", err)
			}
		})
	}
}

func TestValidateSecureTransportPorts(t *testing.T) {
	tests := []struct {
		name   string
		local  int
		remote int
		ok     bool
	}{
		{name: "negotiated protected ports", local: 4062, remote: 4060, ok: true},
		{name: "local missing", remote: 4060},
		{name: "remote missing", local: 4062},
		{name: "local out of range", local: 65536, remote: 4060},
		{name: "remote out of range", local: 4062, remote: 65536},
		{name: "standard SIP local", local: standardSIPPort, remote: 4060},
		{name: "standard SIPS remote", local: 4062, remote: standardSecureSIPPort},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSecureTransportPorts(tt.local, tt.remote)
			if (err == nil) != tt.ok {
				t.Fatalf("validateSecureTransportPorts() error = %v, ok %t", err, tt.ok)
			}
		})
	}
}

func TestSecureInnerPacketAndESPPayload(t *testing.T) {
	local := net.IPv4(10, 0, 0, 1)
	remote := net.IPv4(10, 0, 0, 2)
	payload := []byte("esp-payload")
	tests := []struct {
		name string
		mode string
	}{
		{name: "transport", mode: SecureModeTransport},
		{name: "udp encapsulated tunnel", mode: SecureModeUDPEncTunnel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inner, err := secureInnerPacket(local, remote, tt.mode, payload)
			if err != nil {
				t.Fatalf("secureInnerPacket() error = %v", err)
			}
			got, ok := secureESPPayload(inner, tt.mode)
			if !ok {
				t.Fatal("secureESPPayload() ok = false, want true")
			}
			if string(got) != string(payload) {
				t.Fatalf("secureESPPayload() = %q, want %q", got, payload)
			}
			switch tt.mode {
			case SecureModeTransport:
				if inner.IP.Protocol != packet.ProtocolESP {
					t.Fatalf("transport protocol = %d, want ESP", inner.IP.Protocol)
				}
			case SecureModeUDPEncTunnel:
				if inner.UDP == nil {
					t.Fatal("UDP-enc-tun packet UDP = nil")
				}
				if inner.UDP.Src.Port != udpEncapsulatedESPPort || inner.UDP.Dst.Port != udpEncapsulatedESPPort {
					t.Fatalf("UDP-enc-tun ports = %d/%d, want 4500/4500", inner.UDP.Src.Port, inner.UDP.Dst.Port)
				}
				wire, err := inner.UDP.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				if got := binary.BigEndian.Uint16(wire[6:8]); got != 0 {
					t.Fatalf("UDP-enc-tun IPv4 checksum = %#04x, want zero", got)
				}
			}
		})
	}
}

func TestSecureESPPayloadDecodesUDPEncapsulatedIPPacket(t *testing.T) {
	local := net.IPv4(10, 0, 0, 1)
	remote := net.IPv4(10, 0, 0, 2)
	payload := []byte("esp-payload")
	udpWire, err := (packet.UDPSegment{
		Src:     &net.UDPAddr{IP: local, Port: udpEncapsulatedESPPort},
		Dst:     &net.UDPAddr{IP: remote, Port: udpEncapsulatedESPPort},
		Payload: payload,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	got, ok := secureESPPayload(packet.InnerPacket{
		IP: packet.IPPacket{
			SrcIP:    local,
			DstIP:    remote,
			Protocol: packet.ProtocolUDP,
			Payload:  udpWire,
		},
	}, SecureModeUDPEncTunnel)
	if !ok {
		t.Fatal("secureESPPayload() ok = false, want true")
	}
	if string(got) != string(payload) {
		t.Fatalf("secureESPPayload() = %q, want %q", got, payload)
	}
}

func TestSecureESPPayloadRequiresTS33203UDPPorts(t *testing.T) {
	tests := []struct {
		name    string
		srcPort int
		dstPort int
		want    bool
	}{
		{name: "both ports 4500", srcPort: udpEncapsulatedESPPort, dstPort: udpEncapsulatedESPPort, want: true},
		{name: "wrong source port", srcPort: 4501, dstPort: udpEncapsulatedESPPort},
		{name: "wrong destination port", srcPort: udpEncapsulatedESPPort, dstPort: 4501},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inner := packet.InnerPacket{UDP: &packet.UDPSegment{
				Src:     &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: tt.srcPort},
				Dst:     &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: tt.dstPort},
				Payload: []byte("esp-payload"),
			}}
			_, ok := secureESPPayload(inner, SecureModeUDPEncTunnel)
			if ok != tt.want {
				t.Fatalf("secureESPPayload() ok = %t, want %t", ok, tt.want)
			}
		})
	}
}

func TestSecureOuterDestinationMatches(t *testing.T) {
	localIP := net.IPv4(10, 0, 0, 1)
	tests := []struct {
		name string
		mode string
		pkt  packet.InnerPacket
		want bool
	}{
		{
			name: "transport mode uses inner flow validation",
			mode: SecureModeTransport,
			want: true,
		},
		{
			name: "matching IP packet destination",
			mode: SecureModeUDPEncTunnel,
			pkt:  packet.InnerPacket{IP: packet.IPPacket{DstIP: localIP}},
			want: true,
		},
		{
			name: "matching decoded UDP destination",
			mode: SecureModeUDPEncTunnel,
			pkt: packet.InnerPacket{UDP: &packet.UDPSegment{
				Dst: &net.UDPAddr{IP: localIP, Port: udpEncapsulatedESPPort},
			}},
			want: true,
		},
		{
			name: "wrong tunnel destination",
			mode: SecureModeUDPEncTunnel,
			pkt:  packet.InnerPacket{IP: packet.IPPacket{DstIP: net.IPv4(10, 0, 0, 2)}},
		},
		{name: "missing tunnel destination", mode: SecureModeUDPEncTunnel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := secureOuterDestinationMatches(tt.pkt, localIP, tt.mode); got != tt.want {
				t.Fatalf("secureOuterDestinationMatches() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestUDPEncTunnelKeepalivePacket(t *testing.T) {
	local := net.IPv4(10, 0, 0, 1)
	remote := net.IPv4(10, 0, 0, 2)

	inner, err := udpEncTunnelKeepalivePacket(local, remote)
	if err != nil {
		t.Fatalf("udpEncTunnelKeepalivePacket() error = %v", err)
	}
	if inner.UDP == nil {
		t.Fatal("udpEncTunnelKeepalivePacket() UDP = nil")
	}
	if inner.UDP.Src.Port != udpEncapsulatedESPPort || inner.UDP.Dst.Port != udpEncapsulatedESPPort {
		t.Fatalf("keepalive ports = %d/%d, want 4500/4500", inner.UDP.Src.Port, inner.UDP.Dst.Port)
	}
	if got := inner.UDP.Payload; len(got) != 1 || got[0] != udpEncapsulatedESPKeepalivePayload {
		t.Fatalf("keepalive payload = % X, want FF", got)
	}
	if payload, ok := secureESPPayload(inner, SecureModeUDPEncTunnel); ok || payload != nil {
		t.Fatalf("secureESPPayload() = % X, %t; want ignored keepalive", payload, ok)
	}
}
