package packet

import (
	"encoding/binary"
	"net"
	"slices"
	"testing"

	"github.com/damonto/vowifi-go/swu/esp"
)

func TestIPPacketRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		packet IPPacket
	}{
		{
			name: "ipv4",
			packet: IPPacket{
				Version:  IPVersion4,
				Protocol: ProtocolUDP,
				SrcIP:    net.IPv4(10, 0, 0, 1),
				DstIP:    net.IPv4(10, 0, 0, 2),
				Payload:  []byte{0x01, 0x02, 0x03},
			},
		},
		{
			name: "ipv6",
			packet: IPPacket{
				Version:  IPVersion6,
				Protocol: ProtocolTCP,
				SrcIP:    net.ParseIP("2001:db8::1"),
				DstIP:    net.ParseIP("2001:db8::2"),
				Payload:  []byte{0x04, 0x05, 0x06},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.packet.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			var got IPPacket
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.Version != tt.packet.Version || got.Protocol != tt.packet.Protocol || !got.SrcIP.Equal(tt.packet.SrcIP) || !got.DstIP.Equal(tt.packet.DstIP) || string(got.Payload) != string(tt.packet.Payload) {
				t.Fatalf("IPPacket = %+v, want %+v", got, tt.packet)
			}
		})
	}
}

func TestInnerPacketRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		packet InnerPacket
		check  func(t *testing.T, got InnerPacket)
	}{
		{
			name: "udp",
			packet: InnerPacket{
				UDP: &UDPSegment{
					Src:     &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5062},
					Dst:     &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5060},
					Payload: []byte("sip"),
				},
			},
			check: func(t *testing.T, got InnerPacket) {
				t.Helper()
				if got.UDP == nil || got.UDP.Src.Port != 5062 || got.UDP.Dst.Port != 5060 || string(got.UDP.Payload) != "sip" {
					t.Fatalf("UDP = %+v", got.UDP)
				}
			},
		},
		{
			name: "tcp",
			packet: InnerPacket{
				TCP: &TCPSegment{
					Src:     &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40000},
					Dst:     &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 5060},
					Seq:     10,
					Ack:     20,
					Flags:   TCPFlagACK | TCPFlagPSH,
					Window:  65535,
					Payload: []byte("REGISTER sip"),
				},
			},
			check: func(t *testing.T, got InnerPacket) {
				t.Helper()
				if got.TCP == nil || got.TCP.Seq != 10 || got.TCP.Ack != 20 || string(got.TCP.Payload) != "REGISTER sip" {
					t.Fatalf("TCP = %+v", got.TCP)
				}
			},
		},
		{
			name: "esp opaque",
			packet: InnerPacket{
				IP: IPPacket{
					Version: IPVersion4,
					SrcIP:   net.IPv4(10, 0, 0, 1),
					DstIP:   net.IPv4(10, 0, 0, 2),
				},
				ESP: &esp.ESPPacket{
					SPI:      0x01020304,
					Sequence: 0x05060708,
					Payload:  []byte{0xaa, 0xbb},
				},
			},
			check: func(t *testing.T, got InnerPacket) {
				t.Helper()
				if got.ESP == nil || got.ESP.SPI != 0x01020304 || got.ESP.Sequence != 0x05060708 || string(got.ESP.Payload) != string([]byte{0xaa, 0xbb}) {
					t.Fatalf("ESP = %+v", got.ESP)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.packet.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			var got InnerPacket
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			tt.check(t, got)
		})
	}
}

func TestDecodePayload(t *testing.T) {
	tests := []struct {
		name    string
		proto   byte
		payload []byte
		check   func(t *testing.T, pkt InnerPacket)
	}{
		{
			name:  "udp dispatch",
			proto: ProtocolUDP,
			payload: func() []byte {
				wire, _ := (UDPSegment{
					Src:     &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5062},
					Dst:     &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5060},
					Payload: []byte("ok"),
				}).MarshalBinary()
				return wire
			}(),
			check: func(t *testing.T, pkt InnerPacket) {
				t.Helper()
				if pkt.UDP == nil || string(pkt.UDP.Payload) != "ok" {
					t.Fatalf("UDP = %+v", pkt.UDP)
				}
			},
		},
		{
			name:    "esp dispatch keeps opaque payload",
			proto:   ProtocolESP,
			payload: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xaa},
			check: func(t *testing.T, pkt InnerPacket) {
				t.Helper()
				if pkt.ESP == nil || pkt.ESP.SPI != 0x01020304 || pkt.ESP.Sequence != 0x05060708 || string(pkt.ESP.Payload) != string([]byte{0xaa}) {
					t.Fatalf("ESP = %+v", pkt.ESP)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt, err := DecodePayload(tt.proto, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), tt.payload)
			if err != nil {
				t.Fatalf("DecodePayload() error = %v", err)
			}
			tt.check(t, pkt)
		})
	}
}

func TestDecodePayloadRejectsShortESP(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "empty"},
		{name: "short header", payload: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodePayload(ProtocolESP, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), tt.payload)
			if err == nil {
				t.Fatal("DecodePayload() error = nil, want short ESP error")
			}
		})
	}
}

func TestUDPSegmentMarshalNormalizesZeroChecksum(t *testing.T) {
	tests := []struct {
		name string
		src  net.IP
		dst  net.IP
	}{
		{name: "ipv4", src: net.IPv4(10, 0, 0, 1), dst: net.IPv4(10, 0, 0, 2)},
		{name: "ipv6", src: net.ParseIP("2001:db8::1"), dst: net.ParseIP("2001:db8::2")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := udpPayloadForChecksum(t, tt.src, tt.dst, 5062, 5060, 0)
			wire, err := (UDPSegment{
				Src:     &net.UDPAddr{IP: tt.src, Port: 5062},
				Dst:     &net.UDPAddr{IP: tt.dst, Port: 5060},
				Payload: payload,
			}).MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if got := binary.BigEndian.Uint16(wire[6:8]); got != 0xffff {
				t.Fatalf("UDP checksum = %#04x, want 0xffff", got)
			}
		})
	}
}

func TestIPPacketUnmarshalRejectsInvalidIPv4Checksum(t *testing.T) {
	wire, err := (IPPacket{
		Version:  IPVersion4,
		Protocol: ProtocolUDP,
		SrcIP:    net.IPv4(10, 0, 0, 1),
		DstIP:    net.IPv4(10, 0, 0, 2),
		Payload:  []byte{0x01, 0x02, 0x03},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	wire[10] ^= 0xff

	var pkt IPPacket
	if err := pkt.UnmarshalBinary(wire); err == nil {
		t.Fatal("UnmarshalBinary() error = nil, want checksum error")
	}
}

func TestDecodePayloadValidatesTransportChecksum(t *testing.T) {
	tests := []struct {
		name    string
		proto   byte
		src     net.IP
		dst     net.IP
		payload func(t *testing.T, src, dst net.IP) []byte
		wantErr bool
	}{
		{
			name:  "udp ipv4 invalid nonzero checksum",
			proto: ProtocolUDP,
			src:   net.IPv4(10, 0, 0, 1),
			dst:   net.IPv4(10, 0, 0, 2),
			payload: func(t *testing.T, src, dst net.IP) []byte {
				t.Helper()
				wire, err := (UDPSegment{
					Src:     &net.UDPAddr{IP: src, Port: 5062},
					Dst:     &net.UDPAddr{IP: dst, Port: 5060},
					Payload: []byte("sip"),
				}).MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				wire[len(wire)-1] ^= 0xff
				return wire
			},
			wantErr: true,
		},
		{
			name:  "udp ipv4 zero checksum allowed",
			proto: ProtocolUDP,
			src:   net.IPv4(10, 0, 0, 1),
			dst:   net.IPv4(10, 0, 0, 2),
			payload: func(t *testing.T, src, dst net.IP) []byte {
				t.Helper()
				wire, err := (UDPSegment{
					Src:     &net.UDPAddr{IP: src, Port: 5062},
					Dst:     &net.UDPAddr{IP: dst, Port: 5060},
					Payload: []byte("sip"),
				}).MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				binary.BigEndian.PutUint16(wire[6:8], 0)
				return wire
			},
		},
		{
			name:  "udp ipv6 zero checksum rejected",
			proto: ProtocolUDP,
			src:   net.ParseIP("2001:db8::1"),
			dst:   net.ParseIP("2001:db8::2"),
			payload: func(t *testing.T, src, dst net.IP) []byte {
				t.Helper()
				wire, err := (UDPSegment{
					Src:     &net.UDPAddr{IP: src, Port: 5062},
					Dst:     &net.UDPAddr{IP: dst, Port: 5060},
					Payload: []byte("sip"),
				}).MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				binary.BigEndian.PutUint16(wire[6:8], 0)
				return wire
			},
			wantErr: true,
		},
		{
			name:  "tcp invalid checksum",
			proto: ProtocolTCP,
			src:   net.ParseIP("2001:db8::1"),
			dst:   net.ParseIP("2001:db8::2"),
			payload: func(t *testing.T, src, dst net.IP) []byte {
				t.Helper()
				wire, err := (TCPSegment{
					Src:     &net.TCPAddr{IP: src, Port: 40000},
					Dst:     &net.TCPAddr{IP: dst, Port: 5060},
					Seq:     1,
					Ack:     2,
					Flags:   TCPFlagACK | TCPFlagPSH,
					Window:  65535,
					Payload: []byte("REGISTER"),
				}).MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				wire[len(wire)-1] ^= 0xff
				return wire
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodePayload(tt.proto, tt.src, tt.dst, tt.payload(t, tt.src, tt.dst))
			if tt.wantErr {
				if err == nil {
					t.Fatal("DecodePayload() error = nil, want checksum error")
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodePayload() error = %v", err)
			}
		})
	}
}

func TestTCPOptionsOnlyAdvertiseImplementedCapabilities(t *testing.T) {
	tests := []struct {
		name  string
		flags byte
		want  []byte
	}{
		{name: "syn", flags: TCPFlagSYN, want: []byte{0x02, 0x04, 0x05, 0x50}},
		{name: "syn ack", flags: TCPFlagSYN | TCPFlagACK, want: []byte{0x02, 0x04, 0x05, 0x50}},
		{name: "ack", flags: TCPFlagACK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tcpOptionsForFlags(tt.flags)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("tcpOptionsForFlags() = %x, want %x", got, tt.want)
			}
		})
	}
}

func TestTCPSegmentDecodeReadsMSSOption(t *testing.T) {
	tests := []struct {
		name  string
		flags byte
		want  uint16
	}{
		{name: "syn", flags: TCPFlagSYN, want: tcpDefaultMSS},
		{name: "syn ack", flags: TCPFlagSYN | TCPFlagACK, want: tcpDefaultMSS},
		{name: "ack without mss", flags: TCPFlagACK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := (TCPSegment{
				Src:    &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40000},
				Dst:    &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5060},
				Seq:    1,
				Ack:    2,
				Flags:  tt.flags,
				Window: 65535,
			}).MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			var got TCPSegment
			got.Src = &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1)}
			got.Dst = &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2)}
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.MSS != tt.want {
				t.Fatalf("MSS = %d, want %d", got.MSS, tt.want)
			}
		})
	}
}

func udpPayloadForChecksum(t *testing.T, src, dst net.IP, srcPort, dstPort int, want uint16) []byte {
	t.Helper()
	payload := make([]byte, 2)
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udp[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	var sum uint16
	if src.To4() != nil {
		sum = udpChecksumIPv4(src.To4(), dst.To4(), udp)
	} else {
		sum = udpChecksumIPv6(src.To16(), dst.To16(), udp)
	}
	binary.BigEndian.PutUint16(payload, sum-want)
	return payload
}

func TestTransportSegmentsRejectInvalidPorts(t *testing.T) {
	tests := []struct {
		name    string
		marshal func() ([]byte, error)
	}{
		{
			name: "udp source port wraps uint16",
			marshal: func() ([]byte, error) {
				return (UDPSegment{
					Src: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 65536},
					Dst: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5060},
				}).MarshalBinary()
			},
		},
		{
			name: "udp destination port is zero",
			marshal: func() ([]byte, error) {
				return (UDPSegment{
					Src: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5062},
					Dst: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2)},
				}).MarshalBinary()
			},
		},
		{
			name: "tcp source port is negative",
			marshal: func() ([]byte, error) {
				return (TCPSegment{
					Src: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: -1},
					Dst: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5060},
				}).MarshalBinary()
			},
		},
		{
			name: "tcp destination port wraps uint16",
			marshal: func() ([]byte, error) {
				return (TCPSegment{
					Src: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5062},
					Dst: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 70000},
				}).MarshalBinary()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.marshal(); err == nil {
				t.Fatal("MarshalBinary() error = nil, want invalid port error")
			}
		})
	}
}

func TestPacketsRejectLengthOverflow(t *testing.T) {
	tests := []struct {
		name    string
		marshal func() ([]byte, error)
	}{
		{
			name: "ipv4 total length",
			marshal: func() ([]byte, error) {
				return (IPPacket{
					Version:  IPVersion4,
					Protocol: ProtocolUDP,
					SrcIP:    net.IPv4(10, 0, 0, 1),
					DstIP:    net.IPv4(10, 0, 0, 2),
					Payload:  make([]byte, maxIPPacketBytes-20+1),
				}).MarshalBinary()
			},
		},
		{
			name: "ipv6 payload length",
			marshal: func() ([]byte, error) {
				return (IPPacket{
					Version:  IPVersion6,
					Protocol: ProtocolTCP,
					SrcIP:    net.ParseIP("2001:db8::1"),
					DstIP:    net.ParseIP("2001:db8::2"),
					Payload:  make([]byte, maxIPPayloadBytes+1),
				}).MarshalBinary()
			},
		},
		{
			name: "udp length",
			marshal: func() ([]byte, error) {
				return (UDPSegment{
					Src:     &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5062},
					Dst:     &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5060},
					Payload: make([]byte, maxUDPSegmentBytes-8+1),
				}).MarshalBinary()
			},
		},
		{
			name: "tcp length",
			marshal: func() ([]byte, error) {
				return (TCPSegment{
					Src:     &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5062},
					Dst:     &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5060},
					Flags:   TCPFlagACK,
					Payload: make([]byte, maxTCPSegmentBytes-20+1),
				}).MarshalBinary()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.marshal(); err == nil {
				t.Fatal("MarshalBinary() error = nil, want length overflow error")
			}
		})
	}
}

func TestInnerPacketOuterNextHeader(t *testing.T) {
	tests := []struct {
		name   string
		packet InnerPacket
		want   byte
	}{
		{
			name: "udp infers ipv4 from endpoints",
			packet: InnerPacket{
				UDP: &UDPSegment{
					Src:     &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5062},
					Dst:     &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5060},
					Payload: []byte("sip"),
				},
			},
			want: OuterIPv4,
		},
		{
			name: "tcp infers ipv6 from endpoints",
			packet: InnerPacket{
				TCP: &TCPSegment{
					Src:     &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40000},
					Dst:     &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 5060},
					Seq:     10,
					Ack:     20,
					Flags:   TCPFlagACK,
					Window:  65535,
					Payload: []byte("REGISTER"),
				},
			},
			want: OuterIPv6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.packet.OuterNextHeader()
			if err != nil {
				t.Fatalf("OuterNextHeader() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("OuterNextHeader() = %d, want %d", got, tt.want)
			}
		})
	}
}
