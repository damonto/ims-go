package imsclient

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"

	imscall "github.com/damonto/ims-client/ims/call"
	"github.com/damonto/ims-client/swu/packet"
)

func TestTunnelMediaTransportHandlesRTPAndRTCPPorts(t *testing.T) {
	tests := []struct {
		name       string
		srcPort    int
		dstPort    int
		remote     *net.UDPAddr
		wantHandle bool
	}{
		{name: "rtp", srcPort: 50000, dstPort: 40000, remote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000}, wantHandle: true},
		{name: "rtcp", srcPort: 50001, dstPort: 40001, remote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000}, wantHandle: true},
		{name: "rtp from alternate source port", srcPort: 51000, dstPort: 40000, remote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000}, wantHandle: true},
		{name: "unrelated destination", srcPort: 50000, dstPort: 40002, remote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000}, wantHandle: false},
		{name: "prepared rtp before remote is known", srcPort: 50000, dstPort: 40000, wantHandle: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &tunnelMediaTransport{
				logger: testMediaLogger(),
				local:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40000},
				remote: tt.remote,
				readCh: make(chan tunnelMediaPacket, 1),
				rtcpCh: make(chan tunnelMediaPacket, 1),
				done:   make(chan struct{}),
			}
			got := transport.HandleInnerPacket(packet.InnerPacket{
				UDP: &packet.UDPSegment{
					Src:     &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: tt.srcPort},
					Dst:     &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: tt.dstPort},
					Payload: []byte("media"),
				},
			})
			if got != tt.wantHandle {
				t.Fatalf("HandleInnerPacket() = %v, want %v", got, tt.wantHandle)
			}
			if !tt.wantHandle {
				return
			}
			readPacket := transport.ReadPacket
			if tt.dstPort == 40001 {
				readPacket = transport.ReadRTCP
			}
			payload, peer, err := readPacket(context.Background())
			if err != nil {
				t.Fatalf("ReadPacket() error = %v", err)
			}
			if string(payload) != "media" {
				t.Fatalf("payload = %q, want media", string(payload))
			}
			udpPeer, ok := peer.(*net.UDPAddr)
			if !ok {
				t.Fatalf("peer = %T, want *net.UDPAddr", peer)
			}
			if udpPeer.Port != tt.srcPort {
				t.Fatalf("peer port = %d, want %d", udpPeer.Port, tt.srcPort)
			}
		})
	}
}

func TestTunnelMediaTransportConfiguresRemoteAfterPrepare(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "remote is initially empty then configured"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &tunnelMediaTransport{
				logger: testMediaLogger(),
				local:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40000},
				readCh: make(chan tunnelMediaPacket, 1),
				rtcpCh: make(chan tunnelMediaPacket, 1),
				done:   make(chan struct{}),
			}
			if got, ok := transport.RemoteAddr().(*net.UDPAddr); ok && got != nil {
				t.Fatalf("RemoteAddr() = %v, want nil", got)
			}
			err := transport.ConfigureRemote(context.Background(), mediaConfigForTest(net.IPv4(192, 0, 2, 10), 50000))
			if err != nil {
				t.Fatalf("ConfigureRemote() error = %v", err)
			}
			remote, ok := transport.RemoteAddr().(*net.UDPAddr)
			if !ok {
				t.Fatalf("RemoteAddr() = %T, want *net.UDPAddr", transport.RemoteAddr())
			}
			if remote.Port != 50000 || !remote.IP.Equal(net.IPv4(192, 0, 2, 10)) {
				t.Fatalf("RemoteAddr() = %v, want 192.0.2.10:50000", remote)
			}
		})
	}
}

func TestTunnelMediaTransportNotifiesMediaPackets(t *testing.T) {
	tests := []struct {
		name     string
		dstPort  int
		payload  []byte
		wantRTCP bool
		wantBye  bool
	}{
		{name: "rtp packet", dstPort: 40000, payload: []byte("media")},
		{name: "rtcp packet", dstPort: 40001, payload: []byte{0x80, 201, 0, 1, 0, 0, 0, 1}, wantRTCP: true},
		{name: "compound rtcp bye packet", dstPort: 40001, payload: []byte{0x80, 201, 0, 1, 0, 0, 0, 1, 0x81, 203, 0, 1, 0, 0, 0, 1}, wantRTCP: true, wantBye: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := make(chan imscall.MediaPacket, 1)
			transport := &tunnelMediaTransport{
				logger:   testMediaLogger(),
				local:    &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40000},
				remote:   &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000},
				readCh:   make(chan tunnelMediaPacket, 1),
				rtcpCh:   make(chan tunnelMediaPacket, 1),
				done:     make(chan struct{}),
				onPacket: func(packet imscall.MediaPacket) { events <- packet },
			}
			if !transport.HandleInnerPacket(packet.InnerPacket{
				UDP: &packet.UDPSegment{
					Src:     &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000},
					Dst:     &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: tt.dstPort},
					Payload: tt.payload,
				},
			}) {
				t.Fatal("HandleInnerPacket() = false, want true")
			}
			got := <-events
			if got.RTCP != tt.wantRTCP {
				t.Fatalf("MediaPacket.RTCP = %v, want %v", got.RTCP, tt.wantRTCP)
			}
			if got.RTCPBye != tt.wantBye {
				t.Fatalf("MediaPacket.RTCPBye = %v, want %v", got.RTCPBye, tt.wantBye)
			}
		})
	}
}

func mediaConfigForTest(ip net.IP, port int) imscall.MediaConfig {
	return imscall.MediaConfig{RemoteIP: ip, RemotePort: port}
}

func testMediaLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
