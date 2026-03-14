package packet

import (
	"net"
	"testing"
)

func TestIPPacketRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		packet IPPacket
	}{
		{
			name: "ipv4",
			packet: IPPacket{
				Version:  4,
				Protocol: ProtocolUDP,
				SrcIP:    net.IPv4(10, 0, 0, 1),
				DstIP:    net.IPv4(10, 0, 0, 2),
				Payload:  []byte{0x01, 0x02, 0x03},
			},
		},
		{
			name: "ipv6",
			packet: IPPacket{
				Version:  6,
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
