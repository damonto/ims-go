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
	integrityDisabled := espIntegrityDisabled(integrity)
	if encryption == esp.EncryptionAESGCM {
		if !integrityDisabled {
			return errors.New("AES-GCM requires null integrity")
		}
		if len(encryptionKey) == 0 {
			return errors.New("encryption key is empty")
		}
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(integrity), esp.IntegrityAESGMAC) && encryption != esp.EncryptionNull {
		return errors.New("AES-GMAC requires null encryption")
	}
	if integrityDisabled {
		return errors.New("integrity must be enabled")
	}
	if encryption == esp.EncryptionAESCBC && len(encryptionKey) == 0 {
		return errors.New("encryption key is empty")
	}
	if len(integrityKey) == 0 {
		return errors.New("integrity key is empty")
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
			Src:     &net.UDPAddr{IP: append(net.IP(nil), localIP...), Port: udpEncapsulatedESPPort},
			Dst:     &net.UDPAddr{IP: append(net.IP(nil), remoteIP...), Port: udpEncapsulatedESPPort},
			Payload: append([]byte(nil), payload...),
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
		if udp == nil || udp.Dst == nil || udp.Dst.Port != udpEncapsulatedESPPort || len(udp.Payload) == 0 {
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

func secureTunnelNextHeader(srcIP, dstIP net.IP) (byte, error) {
	return (packet.InnerPacket{IP: packet.IPPacket{SrcIP: srcIP, DstIP: dstIP}}).OuterNextHeader()
}

func udpEncapsulatedESPKeepalive(payload []byte) bool {
	return len(payload) == 1 && payload[0] == udpEncapsulatedESPKeepalivePayload
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

func startUDPEncTunnelKeepalive(done <-chan struct{}, write func(context.Context) error, logErr func(error)) {
	go func() {
		ticker := time.NewTicker(udpEncapsulatedESPKeepaliveTick)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
			}

			ctx, cancel := context.WithTimeout(context.Background(), udpEncapsulatedESPKeepaliveTimeout)
			err := write(ctx)
			cancel()
			if err == nil {
				continue
			}
			select {
			case <-done:
				return
			default:
			}
			if logErr != nil {
				logErr(err)
			}
		}
	}()
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

func udpFlowMatches(segment *packet.UDPSegment, local, remote *net.UDPAddr) bool {
	if segment == nil || segment.Src == nil || segment.Dst == nil || local == nil || remote == nil {
		return false
	}
	return segment.Src.IP.Equal(remote.IP) &&
		segment.Src.Port == remote.Port &&
		segment.Dst.IP.Equal(local.IP) &&
		segment.Dst.Port == local.Port
}

func tcpFlowMatches(segment *packet.TCPSegment, local, remote *net.TCPAddr) bool {
	if segment == nil || segment.Src == nil || segment.Dst == nil || local == nil || remote == nil {
		return false
	}
	return segment.Src.IP.Equal(remote.IP) &&
		segment.Src.Port == remote.Port &&
		segment.Dst.IP.Equal(local.IP) &&
		segment.Dst.Port == local.Port
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
