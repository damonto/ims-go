package transport

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/damonto/vowifi-go/swu/esp"
	"github.com/damonto/vowifi-go/swu/packet"
	"github.com/damonto/vowifi-go/swu/tunnel"
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
	return "", fmt.Errorf("unsupported encryption %q", value)
}

func espIntegrityEnabled(value string) bool {
	return !strings.EqualFold(strings.TrimSpace(value), esp.IntegrityNone)
}

func validateSecureESPConfig(encryption, integrity string, encryptionKey, integrityKey []byte) error {
	if strings.EqualFold(strings.TrimSpace(integrity), esp.IntegrityNone) {
		return errors.New("integrity must be enabled")
	}
	if encryption == esp.EncryptionAESCBC && len(encryptionKey) == 0 {
		return errors.New("encryption key is empty")
	}
	if espIntegrityEnabled(integrity) && len(integrityKey) == 0 {
		return errors.New("integrity key is empty")
	}
	return nil
}

func validateSecureSPIs(outbound, inbound uint32) error {
	if !esp.ValidSPI(outbound) || !esp.ValidSPI(inbound) {
		return errors.New("spi is reserved")
	}
	return nil
}

func secureAssociations(associations *SecurityAssociations) *SecurityAssociations {
	if associations != nil {
		return associations
	}
	return NewSecurityAssociations()
}

func connectedUDPAddrs(s *tunnel.Session) (*net.UDPAddr, *net.UDPAddr, error) {
	if s == nil {
		return nil, nil, errors.New("session is nil")
	}
	info := s.Info()
	if len(info.InnerIP) == 0 {
		return nil, nil, errors.New("session is not connected")
	}
	local, ok := s.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil {
		return nil, nil, errors.New("session local address is not an inner udp address")
	}
	remote, ok := s.RemoteAddr().(*net.UDPAddr)
	if !ok || remote == nil {
		return nil, nil, errors.New("session remote address is not an inner udp address")
	}
	return cloneUDPAddr(local), cloneUDPAddr(remote), nil
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
