package packet

import (
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/damonto/vowifi-go/swu/esp"
)

const (
	ProtocolTCP byte = 6
	ProtocolUDP byte = 17
	ProtocolESP byte = 50

	IPVersion4 int = 4
	IPVersion6 int = 6

	OuterIPv4 byte = 4
	OuterIPv6 byte = 41

	TCPFlagFIN byte = 0x01
	TCPFlagSYN byte = 0x02
	TCPFlagRST byte = 0x04
	TCPFlagPSH byte = 0x08
	TCPFlagACK byte = 0x10
)

var (
	_ encoding.BinaryMarshaler   = IPPacket{}
	_ encoding.BinaryUnmarshaler = (*IPPacket)(nil)
	_ encoding.BinaryMarshaler   = UDPSegment{}
	_ encoding.BinaryUnmarshaler = (*UDPSegment)(nil)
	_ encoding.BinaryMarshaler   = TCPSegment{}
	_ encoding.BinaryUnmarshaler = (*TCPSegment)(nil)
	_ encoding.BinaryMarshaler   = InnerPacket{}
	_ encoding.BinaryUnmarshaler = (*InnerPacket)(nil)
)

type IPPacket struct {
	Version  int
	Protocol byte
	SrcIP    net.IP
	DstIP    net.IP
	Payload  []byte
}

type UDPSegment struct {
	Src     *net.UDPAddr
	Dst     *net.UDPAddr
	Payload []byte
}

type TCPSegment struct {
	Src     *net.TCPAddr
	Dst     *net.TCPAddr
	Seq     uint32
	Ack     uint32
	Flags   byte
	Window  uint16
	Payload []byte
}

type InnerPacket struct {
	IP  IPPacket
	UDP *UDPSegment
	TCP *TCPSegment
	ESP *esp.ESPPacket
}

func NextHeaderForVersion(version int) (byte, error) {
	switch version {
	case IPVersion4:
		return OuterIPv4, nil
	case IPVersion6:
		return OuterIPv6, nil
	default:
		return 0, fmt.Errorf("resolving outer next header: unsupported ip version %d", version)
	}
}

func DecodePayload(proto byte, srcIP, dstIP net.IP, payload []byte) (InnerPacket, error) {
	version, src, dst, err := normalizeIPPair(srcIP, dstIP, 0)
	if err != nil {
		return InnerPacket{}, err
	}
	packet := InnerPacket{
		IP: IPPacket{
			Version:  version,
			Protocol: proto,
			SrcIP:    src,
			DstIP:    dst,
			Payload:  append([]byte(nil), payload...),
		},
	}
	switch proto {
	case ProtocolUDP:
		segment, err := decodeUDPSegment(src, dst, payload)
		if err != nil {
			return InnerPacket{}, err
		}
		packet.UDP = &segment
	case ProtocolTCP:
		segment, err := decodeTCPSegment(src, dst, payload)
		if err != nil {
			return InnerPacket{}, err
		}
		packet.TCP = &segment
	case ProtocolESP:
		espPacket, err := decodeOpaqueESPPacket(payload)
		if err != nil {
			return InnerPacket{}, err
		}
		packet.ESP = &espPacket
	}
	return packet, nil
}

func (p IPPacket) MarshalBinary() ([]byte, error) {
	version, src, dst, err := normalizeIPPair(p.SrcIP, p.DstIP, p.Version)
	if err != nil {
		return nil, err
	}
	payload := append([]byte(nil), p.Payload...)
	switch version {
	case IPVersion4:
		packet := make([]byte, 20+len(payload))
		packet[0] = 0x45
		packet[1] = 0x00
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		packet[8] = 64
		packet[9] = p.Protocol
		copy(packet[12:16], src.To4())
		copy(packet[16:20], dst.To4())
		binary.BigEndian.PutUint16(packet[10:12], ipv4HeaderChecksum(packet[:20]))
		copy(packet[20:], payload)
		return packet, nil
	case IPVersion6:
		packet := make([]byte, 40+len(payload))
		packet[0] = 0x60
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
		packet[6] = p.Protocol
		packet[7] = 64
		copy(packet[8:24], src.To16())
		copy(packet[24:40], dst.To16())
		copy(packet[40:], payload)
		return packet, nil
	default:
		return nil, fmt.Errorf("marshalling ip packet: unsupported ip version %d", version)
	}
}

func (p *IPPacket) UnmarshalBinary(data []byte) error {
	version, proto, src, dst, payload, err := decodeIPPacket(data)
	if err != nil {
		return err
	}
	*p = IPPacket{
		Version:  version,
		Protocol: proto,
		SrcIP:    src,
		DstIP:    dst,
		Payload:  payload,
	}
	return nil
}

func (s UDPSegment) MarshalBinary() ([]byte, error) {
	if s.Src == nil || s.Dst == nil {
		return nil, errors.New("marshalling udp segment: endpoint is nil")
	}
	_, src, dst, err := normalizeIPPair(s.Src.IP, s.Dst.IP, 0)
	if err != nil {
		return nil, err
	}
	udp := make([]byte, 8+len(s.Payload))
	binary.BigEndian.PutUint16(udp[0:2], uint16(s.Src.Port))
	binary.BigEndian.PutUint16(udp[2:4], uint16(s.Dst.Port))
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], s.Payload)
	if src.To4() != nil {
		binary.BigEndian.PutUint16(udp[6:8], udpChecksumIPv4(src.To4(), dst.To4(), udp))
		return udp, nil
	}
	binary.BigEndian.PutUint16(udp[6:8], udpChecksumIPv6(src.To16(), dst.To16(), udp))
	return udp, nil
}

func (s *UDPSegment) UnmarshalBinary(data []byte) error {
	return s.decode(data, ipFromUDPAddr(s.Src), ipFromUDPAddr(s.Dst))
}

func (s *UDPSegment) decode(data []byte, srcIP, dstIP net.IP) error {
	segment, err := decodeUDPSegment(srcIP, dstIP, data)
	if err != nil {
		return err
	}
	*s = segment
	return nil
}

func (s TCPSegment) MarshalBinary() ([]byte, error) {
	if s.Src == nil || s.Dst == nil {
		return nil, errors.New("marshalling tcp segment: endpoint is nil")
	}
	_, src, dst, err := normalizeIPPair(s.Src.IP, s.Dst.IP, 0)
	if err != nil {
		return nil, err
	}
	options := tcpOptionsForFlags(s.Flags)
	options = padTCPOptions(options)
	headerLen := 20 + len(options)
	tcp := make([]byte, headerLen+len(s.Payload))
	binary.BigEndian.PutUint16(tcp[0:2], uint16(s.Src.Port))
	binary.BigEndian.PutUint16(tcp[2:4], uint16(s.Dst.Port))
	binary.BigEndian.PutUint32(tcp[4:8], s.Seq)
	binary.BigEndian.PutUint32(tcp[8:12], s.Ack)
	tcp[12] = byte((headerLen / 4) << 4)
	tcp[13] = s.Flags
	binary.BigEndian.PutUint16(tcp[14:16], s.Window)
	copy(tcp[20:headerLen], options)
	copy(tcp[headerLen:], s.Payload)
	if src.To4() != nil {
		binary.BigEndian.PutUint16(tcp[16:18], tcpChecksumIPv4(src.To4(), dst.To4(), tcp))
		return tcp, nil
	}
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksumIPv6(src.To16(), dst.To16(), tcp))
	return tcp, nil
}

func (s *TCPSegment) UnmarshalBinary(data []byte) error {
	return s.decode(data, ipFromTCPAddr(s.Src), ipFromTCPAddr(s.Dst))
}

func (s *TCPSegment) decode(data []byte, srcIP, dstIP net.IP) error {
	segment, err := decodeTCPSegment(srcIP, dstIP, data)
	if err != nil {
		return err
	}
	*s = segment
	return nil
}

func (p InnerPacket) MarshalBinary() ([]byte, error) {
	ip := p.IP
	switch {
	case p.UDP != nil:
		wire, err := p.UDP.MarshalBinary()
		if err != nil {
			return nil, err
		}
		ip.Protocol = ProtocolUDP
		ip.SrcIP = append(net.IP(nil), p.UDP.Src.IP...)
		ip.DstIP = append(net.IP(nil), p.UDP.Dst.IP...)
		ip.Payload = wire
	case p.TCP != nil:
		wire, err := p.TCP.MarshalBinary()
		if err != nil {
			return nil, err
		}
		ip.Protocol = ProtocolTCP
		ip.SrcIP = append(net.IP(nil), p.TCP.Src.IP...)
		ip.DstIP = append(net.IP(nil), p.TCP.Dst.IP...)
		ip.Payload = wire
	case p.ESP != nil:
		wire, err := p.ESP.MarshalBinary()
		if err != nil {
			return nil, err
		}
		ip.Protocol = ProtocolESP
		ip.Payload = wire
	default:
		if len(ip.Payload) == 0 {
			return nil, errors.New("marshalling inner packet: payload is empty")
		}
	}
	return ip.MarshalBinary()
}

func (p *InnerPacket) UnmarshalBinary(data []byte) error {
	var ip IPPacket
	if err := ip.UnmarshalBinary(data); err != nil {
		return err
	}
	packet := InnerPacket{IP: ip}
	switch ip.Protocol {
	case ProtocolUDP:
		segment, err := decodeUDPSegment(ip.SrcIP, ip.DstIP, ip.Payload)
		if err != nil {
			return err
		}
		packet.UDP = &segment
	case ProtocolTCP:
		segment, err := decodeTCPSegment(ip.SrcIP, ip.DstIP, ip.Payload)
		if err != nil {
			return err
		}
		packet.TCP = &segment
	case ProtocolESP:
		espPacket, err := decodeOpaqueESPPacket(ip.Payload)
		if err != nil {
			return err
		}
		packet.ESP = &espPacket
	}
	*p = packet
	return nil
}

func (p InnerPacket) OuterNextHeader() (byte, error) {
	version, err := p.normalizedIPVersion()
	if err != nil {
		return 0, err
	}
	return NextHeaderForVersion(version)
}

func (p InnerPacket) normalizedIPVersion() (int, error) {
	srcIP := append(net.IP(nil), p.IP.SrcIP...)
	dstIP := append(net.IP(nil), p.IP.DstIP...)
	switch {
	case p.UDP != nil:
		srcIP = ipFromUDPAddr(p.UDP.Src)
		dstIP = ipFromUDPAddr(p.UDP.Dst)
	case p.TCP != nil:
		srcIP = ipFromTCPAddr(p.TCP.Src)
		dstIP = ipFromTCPAddr(p.TCP.Dst)
	}
	version, _, _, err := normalizeIPPair(srcIP, dstIP, p.IP.Version)
	if err != nil {
		return 0, err
	}
	return version, nil
}

func decodeIPPacket(packet []byte) (int, byte, net.IP, net.IP, []byte, error) {
	if len(packet) == 0 {
		return 0, 0, nil, nil, nil, errors.New("parsing ip packet: packet is empty")
	}
	switch int(packet[0] >> 4) {
	case IPVersion4:
		return decodeIPv4Packet(packet)
	case IPVersion6:
		return decodeIPv6Packet(packet)
	default:
		return 0, 0, nil, nil, nil, fmt.Errorf("parsing ip packet: unsupported version %d", packet[0]>>4)
	}
}

func decodeIPv4Packet(packet []byte) (int, byte, net.IP, net.IP, []byte, error) {
	if len(packet) < 20 {
		return 0, 0, nil, nil, nil, errors.New("parsing ipv4 packet: packet too short")
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return 0, 0, nil, nil, nil, errors.New("parsing ipv4 packet: invalid header length")
	}
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if total < ihl || len(packet) < total {
		return 0, 0, nil, nil, nil, errors.New("parsing ipv4 packet: invalid total length")
	}
	return IPVersion4, packet[9], append(net.IP(nil), packet[12:16]...), append(net.IP(nil), packet[16:20]...), append([]byte(nil), packet[ihl:total]...), nil
}

func decodeIPv6Packet(packet []byte) (int, byte, net.IP, net.IP, []byte, error) {
	if len(packet) < 40 {
		return 0, 0, nil, nil, nil, errors.New("parsing ipv6 packet: packet too short")
	}
	length := int(binary.BigEndian.Uint16(packet[4:6]))
	if len(packet) < 40+length {
		return 0, 0, nil, nil, nil, errors.New("parsing ipv6 packet: invalid payload length")
	}
	return IPVersion6, packet[6], append(net.IP(nil), packet[8:24]...), append(net.IP(nil), packet[24:40]...), append([]byte(nil), packet[40:40+length]...), nil
}

func decodeUDPSegment(srcIP, dstIP net.IP, payload []byte) (UDPSegment, error) {
	if len(payload) < 8 {
		return UDPSegment{}, errors.New("parsing udp segment: packet too short")
	}
	length := int(binary.BigEndian.Uint16(payload[4:6]))
	if length < 8 || len(payload) < length {
		return UDPSegment{}, errors.New("parsing udp segment: invalid udp length")
	}
	return UDPSegment{
		Src:     &net.UDPAddr{IP: append(net.IP(nil), srcIP...), Port: int(binary.BigEndian.Uint16(payload[0:2]))},
		Dst:     &net.UDPAddr{IP: append(net.IP(nil), dstIP...), Port: int(binary.BigEndian.Uint16(payload[2:4]))},
		Payload: append([]byte(nil), payload[8:length]...),
	}, nil
}

func decodeTCPSegment(srcIP, dstIP net.IP, payload []byte) (TCPSegment, error) {
	if len(payload) < 20 {
		return TCPSegment{}, errors.New("parsing tcp segment: packet too short")
	}
	offset := int(payload[12]>>4) * 4
	if offset < 20 || len(payload) < offset {
		return TCPSegment{}, errors.New("parsing tcp segment: invalid data offset")
	}
	return TCPSegment{
		Src:     &net.TCPAddr{IP: append(net.IP(nil), srcIP...), Port: int(binary.BigEndian.Uint16(payload[0:2]))},
		Dst:     &net.TCPAddr{IP: append(net.IP(nil), dstIP...), Port: int(binary.BigEndian.Uint16(payload[2:4]))},
		Seq:     binary.BigEndian.Uint32(payload[4:8]),
		Ack:     binary.BigEndian.Uint32(payload[8:12]),
		Flags:   payload[13],
		Window:  binary.BigEndian.Uint16(payload[14:16]),
		Payload: append([]byte(nil), payload[offset:]...),
	}, nil
}

func normalizeIPPair(srcIP, dstIP net.IP, version int) (int, net.IP, net.IP, error) {
	src := append(net.IP(nil), srcIP...)
	dst := append(net.IP(nil), dstIP...)
	switch {
	case src.To4() != nil && dst.To4() != nil:
		if version != 0 && version != IPVersion4 {
			return 0, nil, nil, fmt.Errorf("normalizing ip packet: mismatched ip version %d", version)
		}
		return IPVersion4, src.To4(), dst.To4(), nil
	case src.To16() != nil && dst.To16() != nil:
		if version != 0 && version != IPVersion6 {
			return 0, nil, nil, fmt.Errorf("normalizing ip packet: mismatched ip version %d", version)
		}
		return IPVersion6, src.To16(), dst.To16(), nil
	default:
		return 0, nil, nil, errors.New("normalizing ip packet: mismatched ip family")
	}
}

func decodeOpaqueESPPacket(data []byte) (esp.ESPPacket, error) {
	if len(data) < 8 {
		return esp.ESPPacket{}, errors.New("parsing esp packet: packet too short")
	}
	packet := esp.ESPPacket{
		SPI:      binary.BigEndian.Uint32(data[:4]),
		Sequence: binary.BigEndian.Uint32(data[4:8]),
		Payload:  append([]byte(nil), data[8:]...),
	}
	var decoded esp.ESPPacket
	if err := decoded.UnmarshalBinary(data); err == nil {
		packet.NextHeader = decoded.NextHeader
		packet.Payload = decoded.Payload
	}
	return packet, nil
}

func tcpOptionsForFlags(flags byte) []byte {
	if flags&TCPFlagSYN == 0 || flags&TCPFlagACK != 0 {
		return nil
	}
	return []byte{
		0x02, 0x04, 0x05, 0x50,
		0x04, 0x02,
		0x01,
		0x03, 0x03, 0x07,
	}
}

func padTCPOptions(options []byte) []byte {
	if len(options) == 0 {
		return nil
	}
	padded := append([]byte(nil), options...)
	for len(padded)%4 != 0 {
		padded = append(padded, 0x01)
	}
	return padded
}

func ipv4HeaderChecksum(header []byte) uint16 {
	return checksum(header)
}

func udpChecksumIPv4(src, dst net.IP, udp []byte) uint16 {
	pseudo := make([]byte, 12+len(udp))
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[9] = ProtocolUDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	copy(pseudo[12:], udp)
	return checksum(pseudo)
}

func udpChecksumIPv6(src, dst net.IP, udp []byte) uint16 {
	pseudo := make([]byte, 40+len(udp))
	copy(pseudo[0:16], src)
	copy(pseudo[16:32], dst)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(udp)))
	pseudo[39] = ProtocolUDP
	copy(pseudo[40:], udp)
	return checksum(pseudo)
}

func tcpChecksumIPv4(src, dst net.IP, tcp []byte) uint16 {
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[9] = ProtocolTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	return checksum(pseudo)
}

func tcpChecksumIPv6(src, dst net.IP, tcp []byte) uint16 {
	pseudo := make([]byte, 40+len(tcp))
	copy(pseudo[0:16], src)
	copy(pseudo[16:32], dst)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(tcp)))
	pseudo[39] = ProtocolTCP
	copy(pseudo[40:], tcp)
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

func ipFromUDPAddr(addr *net.UDPAddr) net.IP {
	if addr == nil {
		return nil
	}
	return append(net.IP(nil), addr.IP...)
}

func ipFromTCPAddr(addr *net.TCPAddr) net.IP {
	if addr == nil {
		return nil
	}
	return append(net.IP(nil), addr.IP...)
}
