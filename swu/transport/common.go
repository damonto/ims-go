package transport

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/damonto/ims-client/swu/esp"
	"github.com/damonto/ims-client/swu/tunnel"
)

func randomUint32() (uint32, error) {
	buf := make([]byte, 4)
	if _, err := crand.Read(buf); err != nil {
		return 0, fmt.Errorf("generating random value: %w", err)
	}
	return binary.BigEndian.Uint32(buf), nil
}

func secureEncryption(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), esp.EncryptionAESCBC) {
		return esp.EncryptionAESCBC
	}
	return esp.EncryptionNull
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
