package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	stunBindingIndication = 0x0011
	stunMagicCookie       = 0x2112A442
	stunHeaderBytes       = 20
)

var sipCRLFKeepAlive = []byte("\r\n\r\n")

func (s *Session) SendKeepAlive(ctx context.Context) error {
	if err := s.ensureOpen(); err != nil {
		return fmt.Errorf("sending SIP keepalive: %w", err)
	}
	transport := s.primaryTransport()
	packet, err := keepAlivePacket(transport.LocalAddr())
	if err != nil {
		return fmt.Errorf("sending SIP keepalive: %w", err)
	}
	return s.writePacket(ctx, transport, packet)
}

func keepAlivePacket(addr net.Addr) ([]byte, error) {
	switch addr.(type) {
	case *net.TCPAddr:
		return append([]byte(nil), sipCRLFKeepAlive...), nil
	default:
		return newSTUNBindingIndication()
	}
}

func newSTUNBindingIndication() ([]byte, error) {
	packet := make([]byte, stunHeaderBytes)
	binary.BigEndian.PutUint16(packet[0:2], stunBindingIndication)
	binary.BigEndian.PutUint16(packet[2:4], 0)
	binary.BigEndian.PutUint32(packet[4:8], stunMagicCookie)
	if _, err := rand.Read(packet[8:20]); err != nil {
		return nil, err
	}
	return packet, nil
}

func isKeepAlivePacket(packet []byte) bool {
	return isCRLFKeepAlivePacket(packet) || isSTUNPacket(packet)
}

func isCRLFKeepAlivePacket(packet []byte) bool {
	return len(bytes.Trim(packet, "\r\n")) == 0
}

func isSTUNPacket(packet []byte) bool {
	if len(packet) < stunHeaderBytes {
		return false
	}
	if packet[0]&0xc0 != 0 {
		return false
	}
	if binary.BigEndian.Uint32(packet[4:8]) != stunMagicCookie {
		return false
	}
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	return stunHeaderBytes+length == len(packet)
}
