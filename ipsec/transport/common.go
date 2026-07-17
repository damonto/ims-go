package transport

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	ipsecbase "github.com/damonto/ims-go/ipsec"
	"github.com/damonto/ims-go/ipsec/esp"
	"github.com/damonto/ims-go/ipsec/packet"
)

func packetStartLine(data []byte) string {
	line, _, _ := bytes.Cut(data, []byte("\n"))
	return strings.TrimSpace(string(line))
}

const (
	SecureModeTransport    = "trans"
	SecureModeUDPEncTunnel = "UDP-enc-tun"

	standardSIPPort                    = 5060
	standardSecureSIPPort              = 5061
	udpEncapsulatedESPPort             = 4500
	udpEncapsulatedESPKeepalivePayload = 0xff
	udpEncapsulatedESPKeepaliveTimeout = 2 * time.Second
	udpEncapsulatedESPKeepaliveTick    = 20 * time.Second
)

func randomUint32() (uint32, error) {
	buf := make([]byte, 4)
	if _, err := crand.Read(buf); err != nil {
		return 0, fmt.Errorf("generating random value: %w", err)
	}
	return binary.BigEndian.Uint32(buf), nil
}

func secureEncryption(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, esp.EncryptionNull) {
		return esp.EncryptionNull, nil
	}
	if strings.EqualFold(value, esp.EncryptionAESCBC) {
		return esp.EncryptionAESCBC, nil
	}
	if strings.EqualFold(value, esp.EncryptionAESGCM) {
		return esp.EncryptionAESGCM, nil
	}
	return "", fmt.Errorf("unsupported encryption %q", value)
}

func secureMode(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, SecureModeTransport) {
		return SecureModeTransport, nil
	}
	if strings.EqualFold(value, SecureModeUDPEncTunnel) {
		return SecureModeUDPEncTunnel, nil
	}
	return "", fmt.Errorf("unsupported ipsec mode %q", value)
}

func espReplayProtected(codec esp.Codec) bool {
	return strings.EqualFold(codec.Encryption, esp.EncryptionAESGCM) || !espIntegrityDisabled(codec.Integrity)
}

func espIntegrityDisabled(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == esp.IntegrityNone || value == esp.IntegrityNull
}

func validateSecureESPConfig(encryption, integrity string, encryptionKey, integrityKey []byte) error {
	integrity = strings.ToLower(strings.TrimSpace(integrity))
	switch integrity {
	case esp.IntegrityHMACSHA196, esp.IntegrityHMACSHA196RFC:
		if len(integrityKey) != 20 {
			return fmt.Errorf("HMAC-SHA1 integrity key must be 20 bytes, got %d", len(integrityKey))
		}
	case esp.IntegrityAESGMAC:
		if len(integrityKey) != 16 {
			return fmt.Errorf("AES-GMAC integrity key must be 16 bytes, got %d", len(integrityKey))
		}
	case esp.IntegrityNone, esp.IntegrityNull:
	default:
		return fmt.Errorf("unsupported integrity %q", integrity)
	}
	if (encryption == esp.EncryptionAESCBC || encryption == esp.EncryptionAESGCM) && len(encryptionKey) != 16 {
		return fmt.Errorf("AES encryption key must be 16 bytes, got %d", len(encryptionKey))
	}
	integrityDisabled := espIntegrityDisabled(integrity)
	if encryption == esp.EncryptionAESGCM {
		if !integrityDisabled {
			return errors.New("AES-GCM requires null integrity")
		}
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(integrity), esp.IntegrityAESGMAC) && encryption != esp.EncryptionNull {
		return errors.New("AES-GMAC requires null encryption")
	}
	if integrityDisabled {
		return errors.New("integrity must be enabled")
	}
	return nil
}

func validateSecureSPIs(outbound, inbound uint32) error {
	if !esp.ValidSPI(outbound) || !esp.ValidSPI(inbound) {
		return errors.New("spi is reserved")
	}
	if outbound == inbound {
		return errors.New("spi values must be unique")
	}
	return nil
}

func validateSecureTransportPorts(local, remote int) error {
	ports := []struct {
		name string
		port int
	}{
		{name: "local", port: local},
		{name: "remote", port: remote},
	}
	for _, value := range ports {
		if value.port <= 0 || value.port > 65535 {
			return fmt.Errorf("%s protected port %d is out of range", value.name, value.port)
		}
		if value.port == standardSIPPort || value.port == standardSecureSIPPort {
			return fmt.Errorf("%s protected port %d is a standard SIP port", value.name, value.port)
		}
	}
	return nil
}

func secureAssociations(associations *SecurityAssociations) *SecurityAssociations {
	if associations != nil {
		return associations
	}
	return NewSecurityAssociations()
}

func secureESPCodec(spi uint32, encryption string, encryptionKey []byte, integrity string, integrityKey []byte, salt [4]byte) esp.Codec {
	return esp.Codec{
		SPI:           spi,
		Encryption:    encryption,
		EncryptionKey: append([]byte(nil), encryptionKey...),
		Integrity:     integrity,
		IntegrityKey:  append([]byte(nil), integrityKey...),
		Salt:          salt,
	}
}

func secureInnerPacket(localIP, remoteIP net.IP, mode string, payload []byte) (packet.InnerPacket, error) {
	switch mode {
	case SecureModeUDPEncTunnel:
		outer := packet.UDPSegment{
			Src:              &net.UDPAddr{IP: append(net.IP(nil), localIP...), Port: udpEncapsulatedESPPort},
			Dst:              &net.UDPAddr{IP: append(net.IP(nil), remoteIP...), Port: udpEncapsulatedESPPort},
			Payload:          append([]byte(nil), payload...),
			ZeroIPv4Checksum: true,
		}
		return packet.InnerPacket{UDP: &outer}, nil
	case SecureModeTransport:
		return packet.InnerPacket{
			IP: packet.IPPacket{
				SrcIP:    append(net.IP(nil), localIP...),
				DstIP:    append(net.IP(nil), remoteIP...),
				Protocol: packet.ProtocolESP,
				Payload:  append([]byte(nil), payload...),
			},
		}, nil
	default:
		return packet.InnerPacket{}, fmt.Errorf("building secure inner packet: unsupported ipsec mode %q", mode)
	}
}

func secureESPPayload(pkt packet.InnerPacket, mode string) ([]byte, bool) {
	switch mode {
	case SecureModeUDPEncTunnel:
		udp := pkt.UDP
		if udp == nil {
			inner, err := packet.DecodePayload(packet.ProtocolUDP, pkt.IP.SrcIP, pkt.IP.DstIP, pkt.IP.Payload)
			if err != nil {
				return nil, false
			}
			udp = inner.UDP
		}
		if udp == nil || udp.Src == nil || udp.Dst == nil ||
			udp.Src.Port != udpEncapsulatedESPPort || udp.Dst.Port != udpEncapsulatedESPPort ||
			len(udp.Payload) == 0 {
			return nil, false
		}
		if udpEncapsulatedESPKeepalive(udp.Payload) {
			return nil, false
		}
		return udp.Payload, true
	case SecureModeTransport:
		if pkt.IP.Protocol != packet.ProtocolESP {
			return nil, false
		}
		return pkt.IP.Payload, true
	default:
		return nil, false
	}
}

func secureOuterDestinationMatches(pkt packet.InnerPacket, localIP net.IP, mode string) bool {
	if mode != SecureModeUDPEncTunnel {
		return true
	}
	dstIP := pkt.IP.DstIP
	if pkt.UDP != nil && pkt.UDP.Dst != nil {
		dstIP = pkt.UDP.Dst.IP
	}
	return len(dstIP) > 0 && dstIP.Equal(localIP)
}

func secureTunnelNextHeader(srcIP, dstIP net.IP) (byte, error) {
	return (packet.InnerPacket{IP: packet.IPPacket{SrcIP: srcIP, DstIP: dstIP}}).OuterNextHeader()
}

func udpEncapsulatedESPKeepalive(payload []byte) bool {
	return len(payload) == 1 && payload[0] == udpEncapsulatedESPKeepalivePayload
}

func udpEncapsulatedESPKeepalivePacket(pkt packet.InnerPacket) bool {
	udp := pkt.UDP
	if udp == nil || udp.Src == nil || udp.Dst == nil {
		return false
	}
	return udp.Src.Port == udpEncapsulatedESPPort &&
		udp.Dst.Port == udpEncapsulatedESPPort &&
		udpEncapsulatedESPKeepalive(udp.Payload)
}

func udpEncTunnelKeepalivePacket(localIP, remoteIP net.IP) (packet.InnerPacket, error) {
	return secureInnerPacket(localIP, remoteIP, SecureModeUDPEncTunnel, []byte{udpEncapsulatedESPKeepalivePayload})
}

type PacketSession = ipsecbase.PacketSession

type Attachment = ipsecbase.Attachment

func writeUDPEncTunnelKeepalive(ctx context.Context, session PacketSession, localIP, remoteIP net.IP) error {
	if session == nil {
		return errors.New("writing UDP-enc-tun keepalive: session is nil")
	}
	inner, err := udpEncTunnelKeepalivePacket(localIP, remoteIP)
	if err != nil {
		return fmt.Errorf("writing UDP-enc-tun keepalive: %w", err)
	}
	return session.WriteInnerPacket(ctx, inner)
}

func connectedUDPAddrs(s PacketSession, remoteIP net.IP) (*net.UDPAddr, *net.UDPAddr, error) {
	if s == nil {
		return nil, nil, errors.New("session is nil")
	}
	localIP, resolvedRemoteIP, err := s.InnerIPsForRemote(remoteIP)
	if err != nil {
		return nil, nil, err
	}
	return &net.UDPAddr{IP: localIP}, &net.UDPAddr{IP: resolvedRemoteIP}, nil
}

func udpRemoteAddr(innerRemote *net.UDPAddr, port int, remoteIP net.IP) *net.UDPAddr {
	ip := innerRemote.IP
	if len(remoteIP) != 0 {
		ip = remoteIP
	}
	return &net.UDPAddr{IP: append(net.IP(nil), ip...), Port: port, Zone: innerRemote.Zone}
}

func tcpRemoteAddr(innerRemote *net.UDPAddr, port int, remoteIP net.IP) *net.TCPAddr {
	ip := innerRemote.IP
	if len(remoteIP) != 0 {
		ip = remoteIP
	}
	return &net.TCPAddr{IP: append(net.IP(nil), ip...), Port: port, Zone: innerRemote.Zone}
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}

func cloneTCPAddr(addr *net.TCPAddr) *net.TCPAddr {
	if addr == nil {
		return nil
	}
	return &net.TCPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}

func packetSPI(packet []byte) uint32 {
	if len(packet) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(packet[:4])
}

func packetESPSequence(packet []byte) (uint32, bool) {
	if len(packet) < 8 {
		return 0, false
	}
	return binary.BigEndian.Uint32(packet[4:8]), true
}
