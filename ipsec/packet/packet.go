package packet

import (
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/damonto/ims-go/ipsec/esp"
)

const (
	ProtocolICMP   byte = 1
	ProtocolTCP    byte = 6
	ProtocolUDP    byte = 17
	ProtocolESP    byte = 50
	ProtocolICMPv6 byte = 58

	IPVersion4 int = 4
	IPVersion6 int = 6

	OuterIPv4 byte = 4
	OuterIPv6 byte = 41

	TCPFlagFIN byte = 0x01
	TCPFlagSYN byte = 0x02
	TCPFlagRST byte = 0x04
	TCPFlagPSH byte = 0x08
	TCPFlagACK byte = 0x10

	tcpDefaultMSS uint16 = 1360

	maxTransportPort   = 65535
	maxIPPacketBytes   = 65535
	maxIPPayloadBytes  = 65535
	maxUDPSegmentBytes = 65535
	maxTCPSegmentBytes = 65535
)

var (
	_ encoding.BinaryAppender    = IPPacket{}
	_ encoding.BinaryMarshaler   = IPPacket{}
	_ encoding.BinaryUnmarshaler = (*IPPacket)(nil)
	_ encoding.BinaryAppender    = UDPSegment{}
	_ encoding.BinaryMarshaler   = UDPSegment{}
	_ encoding.BinaryAppender    = TCPSegment{}
	_ encoding.BinaryMarshaler   = TCPSegment{}
	_ encoding.BinaryAppender    = InnerPacket{}
	_ encoding.BinaryMarshaler   = InnerPacket{}
	_ encoding.BinaryUnmarshaler = (*InnerPacket)(nil)
)

type IPPacket struct {
	Version        int
	Protocol       byte
	SrcIP          net.IP
	DstIP          net.IP
	Payload        []byte
	FragmentOffset uint16
	MoreFragments  bool
}

type UDPSegment struct {
	Src     *net.UDPAddr
	Dst     *net.UDPAddr
	Payload []byte
	// ZeroIPv4Checksum is used by RFC 3948 UDP-encapsulated ESP packets.
	ZeroIPv4Checksum bool
}

type TCPSegment struct {
	Src     *net.TCPAddr
	Dst     *net.TCPAddr
	Seq     uint32
	Ack     uint32
	Flags   byte
	Window  uint16
	MSS     uint16
	Options []byte
	Payload []byte
}

type InnerPacket struct {
	IP   IPPacket
	UDP  *UDPSegment
	TCP  *TCPSegment
	ESP  *esp.ESPPacket
	wire []byte
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
	return p.AppendBinary(nil)
}

func (p IPPacket) AppendBinary(dst []byte) ([]byte, error) {
	version, srcIP, dstIP, err := normalizeIPPair(p.SrcIP, p.DstIP, p.Version)
	if err != nil {
		return nil, err
	}
	switch version {
	case IPVersion4:
		if len(p.Payload) > maxIPPacketBytes-20 {
			return nil, fmt.Errorf("marshalling ipv4 packet: payload length %d exceeds %d", len(p.Payload), maxIPPacketBytes-20)
		}
		start := len(dst)
		dst = append(dst, make([]byte, 20)...)
		dst = append(dst, p.Payload...)
		packet := dst[start:]
		packet[0] = 0x45
		packet[1] = 0x00
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		packet[8] = 64
		packet[9] = p.Protocol
		copy(packet[12:16], srcIP.To4())
		copy(packet[16:20], dstIP.To4())
		binary.BigEndian.PutUint16(packet[10:12], ipv4HeaderChecksum(packet[:20]))
		return dst, nil
	case IPVersion6:
		if len(p.Payload) > maxIPPayloadBytes {
			return nil, fmt.Errorf("marshalling ipv6 packet: payload length %d exceeds %d", len(p.Payload), maxIPPayloadBytes)
		}
		start := len(dst)
		dst = append(dst, make([]byte, 40)...)
		dst = append(dst, p.Payload...)
		packet := dst[start:]
		packet[0] = 0x60
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(p.Payload)))
		packet[6] = p.Protocol
		packet[7] = 64
		copy(packet[8:24], srcIP.To16())
		copy(packet[24:40], dstIP.To16())
		return dst, nil
	default:
		return nil, fmt.Errorf("marshalling ip packet: unsupported ip version %d", version)
	}
}

func (p *IPPacket) UnmarshalBinary(data []byte) error {
	if len(data) == 0 {
		return errors.New("parsing ip packet: packet is empty")
	}
	var decoded IPPacket
	var err error
	switch int(data[0] >> 4) {
	case IPVersion4:
		err = decoded.unmarshalIPv4(data)
	case IPVersion6:
		err = decoded.unmarshalIPv6(data)
	default:
		err = fmt.Errorf("parsing ip packet: unsupported version %d", data[0]>>4)
	}
	if err != nil {
		return err
	}
	*p = decoded
	return nil
}

func (s UDPSegment) MarshalBinary() ([]byte, error) {
	return s.AppendBinary(nil)
}

func (s UDPSegment) AppendBinary(dst []byte) ([]byte, error) {
	if s.Src == nil || s.Dst == nil {
		return nil, errors.New("marshalling udp segment: endpoint is nil")
	}
	if err := validateTransportPort("source", s.Src.Port); err != nil {
		return nil, fmt.Errorf("marshalling udp segment: %w", err)
	}
	if err := validateTransportPort("destination", s.Dst.Port); err != nil {
		return nil, fmt.Errorf("marshalling udp segment: %w", err)
	}
	_, srcIP, dstIP, err := normalizeIPPair(s.Src.IP, s.Dst.IP, 0)
	if err != nil {
		return nil, err
	}
	if len(s.Payload) > maxUDPSegmentBytes-8 {
		return nil, fmt.Errorf("marshalling udp segment: payload length %d exceeds %d", len(s.Payload), maxUDPSegmentBytes-8)
	}
	start := len(dst)
	dst = append(dst, make([]byte, 8)...)
	dst = append(dst, s.Payload...)
	udp := dst[start:]
	binary.BigEndian.PutUint16(udp[0:2], uint16(s.Src.Port))
	binary.BigEndian.PutUint16(udp[2:4], uint16(s.Dst.Port))
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	if srcIP.To4() != nil {
		if s.ZeroIPv4Checksum {
			return dst, nil
		}
		binary.BigEndian.PutUint16(udp[6:8], udpWireChecksum(udpChecksumIPv4(srcIP.To4(), dstIP.To4(), udp)))
		return dst, nil
	}
	binary.BigEndian.PutUint16(udp[6:8], udpWireChecksum(udpChecksumIPv6(srcIP.To16(), dstIP.To16(), udp)))
	return dst, nil
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
	return s.AppendBinary(nil)
}

func (s TCPSegment) AppendBinary(dst []byte) ([]byte, error) {
	if s.Src == nil || s.Dst == nil {
		return nil, errors.New("marshalling tcp segment: endpoint is nil")
	}
	if err := validateTransportPort("source", s.Src.Port); err != nil {
		return nil, fmt.Errorf("marshalling tcp segment: %w", err)
	}
	if err := validateTransportPort("destination", s.Dst.Port); err != nil {
		return nil, fmt.Errorf("marshalling tcp segment: %w", err)
	}
	_, srcIP, dstIP, err := normalizeIPPair(s.Src.IP, s.Dst.IP, 0)
	if err != nil {
		return nil, err
	}
	options := append([]byte(nil), s.Options...)
	if len(options) == 0 {
		options = tcpOptionsForFlags(s.Flags, s.MSS)
	}
	options = padTCPOptions(options)
	headerLen := 20 + len(options)
	if len(s.Payload) > maxTCPSegmentBytes-headerLen {
		return nil, fmt.Errorf("marshalling tcp segment: payload length %d exceeds %d", len(s.Payload), maxTCPSegmentBytes-headerLen)
	}
	start := len(dst)
	dst = append(dst, make([]byte, headerLen)...)
	dst = append(dst, s.Payload...)
	tcp := dst[start:]
	binary.BigEndian.PutUint16(tcp[0:2], uint16(s.Src.Port))
	binary.BigEndian.PutUint16(tcp[2:4], uint16(s.Dst.Port))
	binary.BigEndian.PutUint32(tcp[4:8], s.Seq)
	binary.BigEndian.PutUint32(tcp[8:12], s.Ack)
	tcp[12] = byte((headerLen / 4) << 4)
	tcp[13] = s.Flags
	binary.BigEndian.PutUint16(tcp[14:16], s.Window)
	copy(tcp[20:headerLen], options)
	if srcIP.To4() != nil {
		binary.BigEndian.PutUint16(tcp[16:18], tcpChecksumIPv4(srcIP.To4(), dstIP.To4(), tcp))
		return dst, nil
	}
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksumIPv6(srcIP.To16(), dstIP.To16(), tcp))
	return dst, nil
}

func validateTransportPort(name string, port int) error {
	if port <= 0 || port > maxTransportPort {
		return fmt.Errorf("%s port %d is out of range", name, port)
	}
	return nil
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
	return p.AppendBinary(nil)
}

func (p InnerPacket) AppendBinary(dst []byte) ([]byte, error) {
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
	return ip.AppendBinary(dst)
}

func (p *InnerPacket) UnmarshalBinary(data []byte) error {
	var ip IPPacket
	if err := ip.UnmarshalBinary(data); err != nil {
		return err
	}
	packet := InnerPacket{IP: ip, wire: append([]byte(nil), data...)}
	if ip.FragmentOffset != 0 || ip.MoreFragments {
		*p = packet
		return nil
	}
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

// OriginalWire returns the exact IP packet accepted by UnmarshalBinary.
// Callers should use MarshalBinary after changing structured fields.
func (p InnerPacket) OriginalWire() []byte {
	return append([]byte(nil), p.wire...)
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

func (p *IPPacket) unmarshalIPv4(packet []byte) error {
	if len(packet) < 20 {
		return errors.New("parsing ipv4 packet: packet too short")
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return errors.New("parsing ipv4 packet: invalid header length")
	}
	if ipv4HeaderChecksum(packet[:ihl]) != 0 {
		return errors.New("parsing ipv4 packet: invalid header checksum")
	}
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if total < ihl || len(packet) < total {
		return errors.New("parsing ipv4 packet: invalid total length")
	}
	fragment := binary.BigEndian.Uint16(packet[6:8])
	*p = IPPacket{
		Version:        IPVersion4,
		Protocol:       packet[9],
		SrcIP:          append(net.IP(nil), packet[12:16]...),
		DstIP:          append(net.IP(nil), packet[16:20]...),
		Payload:        append([]byte(nil), packet[ihl:total]...),
		FragmentOffset: fragment & 0x1fff,
		MoreFragments:  fragment&0x2000 != 0,
	}
	return nil
}

func (p *IPPacket) unmarshalIPv6(packet []byte) error {
	if len(packet) < 40 {
		return errors.New("parsing ipv6 packet: packet too short")
	}
	length := int(binary.BigEndian.Uint16(packet[4:6]))
	if len(packet) < 40+length {
		return errors.New("parsing ipv6 packet: invalid payload length")
	}
	total := 40 + length
	protocol := packet[6]
	offset := 40
	var fragmentOffset uint16
	var moreFragments bool
	for {
		switch protocol {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options.
			if offset+2 > total {
				return errors.New("parsing ipv6 packet: truncated extension header")
			}
			next := packet[offset]
			headerLength := (int(packet[offset+1]) + 1) * 8
			if headerLength < 8 || offset+headerLength > total {
				return errors.New("parsing ipv6 packet: invalid extension header length")
			}
			protocol = next
			offset += headerLength
		case 44: // Fragment.
			if offset+8 > total {
				return errors.New("parsing ipv6 packet: truncated fragment header")
			}
			fragment := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
			fragmentOffset = fragment >> 3
			moreFragments = fragment&1 != 0
			protocol = packet[offset]
			offset += 8
			if fragmentOffset != 0 {
				*p = IPPacket{
					Version:        IPVersion6,
					Protocol:       protocol,
					SrcIP:          append(net.IP(nil), packet[8:24]...),
					DstIP:          append(net.IP(nil), packet[24:40]...),
					Payload:        append([]byte(nil), packet[offset:total]...),
					FragmentOffset: fragmentOffset,
					MoreFragments:  moreFragments,
				}
				return nil
			}
		case 51: // Authentication Header.
			if offset+2 > total {
				return errors.New("parsing ipv6 packet: truncated authentication header")
			}
			next := packet[offset]
			headerLength := (int(packet[offset+1]) + 2) * 4
			if headerLength < 8 || offset+headerLength > total {
				return errors.New("parsing ipv6 packet: invalid authentication header length")
			}
			protocol = next
			offset += headerLength
		default:
			*p = IPPacket{
				Version:        IPVersion6,
				Protocol:       protocol,
				SrcIP:          append(net.IP(nil), packet[8:24]...),
				DstIP:          append(net.IP(nil), packet[24:40]...),
				Payload:        append([]byte(nil), packet[offset:total]...),
				FragmentOffset: fragmentOffset,
				MoreFragments:  moreFragments,
			}
			return nil
		}
	}
}

func decodeUDPSegment(srcIP, dstIP net.IP, payload []byte) (UDPSegment, error) {
	if len(payload) < 8 {
		return UDPSegment{}, errors.New("parsing udp segment: packet too short")
	}
	version, src, dst, validateChecksum, err := transportChecksumContext(srcIP, dstIP)
	if err != nil {
		return UDPSegment{}, fmt.Errorf("parsing udp segment: %w", err)
	}
	length := int(binary.BigEndian.Uint16(payload[4:6]))
	if length < 8 || len(payload) < length {
		return UDPSegment{}, errors.New("parsing udp segment: invalid udp length")
	}
	wire := payload[:length]
	if validateChecksum {
		if err := validateUDPChecksum(version, src, dst, wire); err != nil {
			return UDPSegment{}, err
		}
	}
	return UDPSegment{
		Src:     &net.UDPAddr{IP: src, Port: int(binary.BigEndian.Uint16(wire[0:2]))},
		Dst:     &net.UDPAddr{IP: dst, Port: int(binary.BigEndian.Uint16(wire[2:4]))},
		Payload: append([]byte(nil), wire[8:]...),
	}, nil
}

func decodeTCPSegment(srcIP, dstIP net.IP, payload []byte) (TCPSegment, error) {
	if len(payload) < 20 {
		return TCPSegment{}, errors.New("parsing tcp segment: packet too short")
	}
	version, src, dst, validateChecksum, err := transportChecksumContext(srcIP, dstIP)
	if err != nil {
		return TCPSegment{}, fmt.Errorf("parsing tcp segment: %w", err)
	}
	offset := int(payload[12]>>4) * 4
	if offset < 20 || len(payload) < offset {
		return TCPSegment{}, errors.New("parsing tcp segment: invalid data offset")
	}
	if validateChecksum && tcpSegmentChecksum(version, src, dst, payload) != 0 {
		return TCPSegment{}, errors.New("parsing tcp segment: invalid checksum")
	}
	options := payload[20:offset]
	return TCPSegment{
		Src:     &net.TCPAddr{IP: src, Port: int(binary.BigEndian.Uint16(payload[0:2]))},
		Dst:     &net.TCPAddr{IP: dst, Port: int(binary.BigEndian.Uint16(payload[2:4]))},
		Seq:     binary.BigEndian.Uint32(payload[4:8]),
		Ack:     binary.BigEndian.Uint32(payload[8:12]),
		Flags:   payload[13],
		Window:  binary.BigEndian.Uint16(payload[14:16]),
		MSS:     tcpMSSOption(options),
		Options: append([]byte(nil), options...),
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

func transportChecksumContext(srcIP, dstIP net.IP) (int, net.IP, net.IP, bool, error) {
	if len(srcIP) == 0 && len(dstIP) == 0 {
		return 0, nil, nil, false, nil
	}
	version, src, dst, err := normalizeIPPair(srcIP, dstIP, 0)
	if err != nil {
		return 0, nil, nil, false, err
	}
	return version, src, dst, true, nil
}

func decodeOpaqueESPPacket(data []byte) (esp.ESPPacket, error) {
	if len(data) < 8 {
		return esp.ESPPacket{}, errors.New("parsing esp packet: packet too short")
	}
	spi := binary.BigEndian.Uint32(data[:4])
	sequence := binary.BigEndian.Uint32(data[4:8])
	if !esp.ValidSPI(spi) {
		return esp.ESPPacket{}, errors.New("parsing esp packet: invalid spi")
	}
	if sequence == 0 {
		return esp.ESPPacket{}, errors.New("parsing esp packet: invalid sequence number")
	}
	packet := esp.ESPPacket{
		SPI:      spi,
		Sequence: sequence,
		Payload:  append([]byte(nil), data[8:]...),
	}
	var decoded esp.ESPPacket
	if err := decoded.UnmarshalBinary(data); err == nil {
		packet.NextHeader = decoded.NextHeader
		packet.Payload = decoded.Payload
	}
	return packet, nil
}

func tcpOptionsForFlags(flags byte, mss uint16) []byte {
	if flags&TCPFlagSYN == 0 {
		return nil
	}
	if mss == 0 {
		mss = tcpDefaultMSS
	}
	return []byte{
		0x02, 0x04, byte(mss >> 8), byte(mss & 0xff),
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

func tcpMSSOption(options []byte) uint16 {
	for i := 0; i < len(options); {
		kind := options[i]
		switch kind {
		case 0:
			return 0
		case 1:
			i++
			continue
		}
		if i+1 >= len(options) {
			return 0
		}
		length := int(options[i+1])
		if length < 2 || i+length > len(options) {
			return 0
		}
		if kind == 2 && length == 4 {
			return binary.BigEndian.Uint16(options[i+2 : i+4])
		}
		i += length
	}
	return 0
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

func udpWireChecksum(sum uint16) uint16 {
	if sum == 0 {
		return 0xffff
	}
	return sum
}

func validateUDPChecksum(version int, src, dst net.IP, udp []byte) error {
	wireChecksum := binary.BigEndian.Uint16(udp[6:8])
	if wireChecksum == 0 {
		if version == IPVersion4 {
			return nil
		}
		return errors.New("parsing udp segment: checksum is zero")
	}
	var got uint16
	if version == IPVersion4 {
		got = udpChecksumIPv4(src.To4(), dst.To4(), udp)
	} else {
		got = udpChecksumIPv6(src.To16(), dst.To16(), udp)
	}
	if got != 0 {
		return errors.New("parsing udp segment: invalid checksum")
	}
	return nil
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

func tcpSegmentChecksum(version int, src, dst net.IP, tcp []byte) uint16 {
	if version == IPVersion4 {
		return tcpChecksumIPv4(src.To4(), dst.To4(), tcp)
	}
	return tcpChecksumIPv6(src.To16(), dst.To16(), tcp)
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
