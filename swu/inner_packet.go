package swu

import (
	"encoding/binary"
	"fmt"
	"net"
)

func buildInnerIPPacket(srcIP, dstIP net.IP, proto byte, payload []byte) ([]byte, byte, error) {
	src := append(net.IP(nil), srcIP...)
	dst := append(net.IP(nil), dstIP...)
	if src.To4() != nil && dst.To4() != nil {
		src4 := src.To4()
		dst4 := dst.To4()
		packet := make([]byte, 20+len(payload))
		packet[0] = 0x45
		packet[1] = 0x00
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		packet[8] = 64
		packet[9] = proto
		copy(packet[12:16], src4)
		copy(packet[16:20], dst4)
		binary.BigEndian.PutUint16(packet[10:12], ipv4HeaderChecksum(packet[:20]))
		copy(packet[20:], payload)
		return packet, 4, nil
	}
	if src.To16() == nil || dst.To16() == nil {
		return nil, 0, fmt.Errorf("building inner ip packet: mismatched ip family")
	}
	src16 := src.To16()
	dst16 := dst.To16()
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6] = proto
	packet[7] = 64
	copy(packet[8:24], src16)
	copy(packet[24:40], dst16)
	copy(packet[40:], payload)
	return packet, 41, nil
}

func buildInnerUDPPacket(src, dst *net.UDPAddr, payload []byte) ([]byte, byte, error) {
	if src == nil || dst == nil {
		return nil, 0, fmt.Errorf("building inner udp packet: endpoint is nil")
	}
	srcIP := append(net.IP(nil), src.IP...)
	dstIP := append(net.IP(nil), dst.IP...)
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], uint16(src.Port))
	binary.BigEndian.PutUint16(udp[2:4], uint16(dst.Port))
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)

	if srcIP.To4() != nil && dstIP.To4() != nil {
		src4 := srcIP.To4()
		dst4 := dstIP.To4()
		binary.BigEndian.PutUint16(udp[6:8], udpChecksumIPv4(src4, dst4, udp))
		return buildInnerIPPacket(src4, dst4, 17, udp)
	}
	if srcIP.To16() == nil || dstIP.To16() == nil {
		return nil, 0, fmt.Errorf("building inner udp packet: mismatched ip family")
	}
	src16 := srcIP.To16()
	dst16 := dstIP.To16()
	binary.BigEndian.PutUint16(udp[6:8], udpChecksumIPv6(src16, dst16, udp))
	return buildInnerIPPacket(src16, dst16, 17, udp)
}

func decodeUDPDatagram(srcIP net.IP, payload []byte, localPort int) ([]byte, net.Addr, error) {
	if len(payload) < 8 {
		return nil, nil, fmt.Errorf("parsing udp datagram: packet too short")
	}
	srcPort := int(binary.BigEndian.Uint16(payload[0:2]))
	dstPort := int(binary.BigEndian.Uint16(payload[2:4]))
	length := int(binary.BigEndian.Uint16(payload[4:6]))
	if len(payload) < length || length < 8 {
		return nil, nil, fmt.Errorf("parsing udp datagram: invalid udp length")
	}
	if localPort != 0 && dstPort != localPort {
		return nil, nil, fmt.Errorf("parsing udp datagram: unexpected destination port %d", dstPort)
	}
	peer := &net.UDPAddr{IP: append(net.IP(nil), srcIP...), Port: srcPort}
	return append([]byte(nil), payload[8:length]...), peer, nil
}

func ipv4HeaderChecksum(header []byte) uint16 {
	return checksum(header)
}

func udpChecksumIPv4(src, dst net.IP, udp []byte) uint16 {
	pseudo := make([]byte, 12+len(udp))
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[8] = 0
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	copy(pseudo[12:], udp)
	return checksum(pseudo)
}

func udpChecksumIPv6(src, dst net.IP, udp []byte) uint16 {
	pseudo := make([]byte, 40+len(udp))
	copy(pseudo[0:16], src)
	copy(pseudo[16:32], dst)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(udp)))
	pseudo[39] = 17
	copy(pseudo[40:], udp)
	return checksum(pseudo)
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

type innerPacket struct {
	Payload []byte
	Source  net.Addr
}

func decodeInnerPacket(payload []byte, nextHeader byte, localPort int) (innerPacket, error) {
	proto, srcIP, _, data, err := decodeInnerIPPacket(payload, nextHeader)
	if err != nil {
		return innerPacket{}, err
	}
	if proto != 17 {
		return innerPacket{}, fmt.Errorf("parsing inner udp packet: unsupported protocol %d", proto)
	}
	payloadData, source, err := decodeUDPDatagram(srcIP, data, localPort)
	if err != nil {
		return innerPacket{}, err
	}
	return innerPacket{Payload: payloadData, Source: source}, nil
}

func decodeInnerUDPPacket(payload []byte, nextHeader byte, localPort int) ([]byte, net.Addr, error) {
	packet, err := decodeInnerPacket(payload, nextHeader, localPort)
	if err != nil {
		return nil, nil, err
	}
	return packet.Payload, packet.Source, nil
}
