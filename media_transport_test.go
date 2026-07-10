package ims

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"

	imsvoice "github.com/damonto/ims-go/ims/voice"
	"github.com/damonto/ims-go/swu/packet"
)

func TestTunnelMediaTransportHandlesRTPAndRTCPPorts(t *testing.T) {
	tests := []struct {
		name       string
		srcPort    int
		dstPort    int
		remote     *net.UDPAddr
		wantHandle bool
		wantQueue  bool
	}{
		{name: "rtp", srcPort: 50000, dstPort: 40000, remote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000}, wantHandle: true, wantQueue: true},
		{name: "rtcp", srcPort: 50001, dstPort: 40001, remote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000}, wantHandle: true, wantQueue: true},
		{name: "rtp from alternate source port", srcPort: 51000, dstPort: 40000, remote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000}, wantHandle: true, wantQueue: true},
		{name: "unrelated destination", srcPort: 50000, dstPort: 40002, remote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000}, wantHandle: false},
		{name: "prepared rtp before remote is known", srcPort: 50000, dstPort: 40000, wantHandle: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &tunnelMediaTransport{
				logger: testMediaLogger(),
				local:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40000},
				remote: imsvoice.MediaRemote{RTP: tt.remote},
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
			if !tt.wantQueue {
				if len(transport.readCh) != 0 || len(transport.rtcpCh) != 0 {
					t.Fatal("HandleInnerPacket() queued media before remote was configured")
				}
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
		name           string
		cfg            imsvoice.MediaConfig
		wantRTCPPort   int
		wantRTCPMux    bool
		wantRemoteRTCP *net.UDPAddr
	}{
		{
			name:         "remote is initially empty then configured",
			cfg:          mediaConfigForTest(net.IPv4(192, 0, 2, 10), 50000),
			wantRTCPPort: 50001,
		},
		{
			name:           "explicit remote rtcp port",
			cfg:            imsvoice.MediaConfig{RemoteIP: net.IPv4(192, 0, 2, 10), RemotePort: 50000, RemoteRTCPPort: 51000},
			wantRTCPPort:   51000,
			wantRemoteRTCP: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 51000},
		},
		{
			name:           "explicit remote rtcp address",
			cfg:            imsvoice.MediaConfig{RemoteIP: net.IPv4(192, 0, 2, 10), RemotePort: 50000, RemoteRTCPIP: net.IPv4(192, 0, 2, 20), RemoteRTCPPort: 51000},
			wantRTCPPort:   51000,
			wantRemoteRTCP: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 51000},
		},
		{
			name:           "rtcp mux uses rtp remote",
			cfg:            imsvoice.MediaConfig{RemoteIP: net.IPv4(192, 0, 2, 10), RemotePort: 50000, RemoteRTCPPort: 51000, RTCPMux: true},
			wantRTCPPort:   50000,
			wantRTCPMux:    true,
			wantRemoteRTCP: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000},
		},
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
			err := transport.ConfigureRemote(context.Background(), tt.cfg)
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
			transport.mu.Lock()
			rtcpRemote := transport.remote.Addr(true)
			rtcpMux := transport.remote.RTCPMux
			transport.mu.Unlock()
			if rtcpMux != tt.wantRTCPMux {
				t.Fatalf("rtcpMux = %v, want %v", rtcpMux, tt.wantRTCPMux)
			}
			if rtcpRemote.Port != tt.wantRTCPPort {
				t.Fatalf("remote rtcp port = %d, want %d", rtcpRemote.Port, tt.wantRTCPPort)
			}
			if tt.wantRemoteRTCP != nil && !imsvoice.UDPAddrMatches(rtcpRemote, tt.wantRemoteRTCP) {
				t.Fatalf("remote rtcp addr = %v, want %v", rtcpRemote, tt.wantRemoteRTCP)
			}
		})
	}
}

func TestTunnelMediaTransportHandlesRTCPMux(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		wantRTCP bool
		wantBye  bool
	}{
		{name: "rtp on mux port", payload: []byte{0x80, 104, 0, 1, 0, 0, 0, 1}},
		{name: "rtcp on mux port", payload: []byte{0x80, 201, 0, 1, 0, 0, 0, 1}, wantRTCP: true},
		{name: "rtcp bye on mux port", payload: []byte{0x81, 203, 0, 1, 0, 0, 0, 1}, wantRTCP: true, wantBye: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := make(chan imsvoice.MediaPacket, 1)
			transport := &tunnelMediaTransport{
				logger:   testMediaLogger(),
				local:    &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40000},
				remote:   imsvoice.MediaRemote{RTP: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000}, RTCPMux: true},
				readCh:   make(chan tunnelMediaPacket, 1),
				rtcpCh:   make(chan tunnelMediaPacket, 1),
				done:     make(chan struct{}),
				onPacket: func(packet imsvoice.MediaPacket) { events <- packet },
			}
			if !transport.HandleInnerPacket(packet.InnerPacket{
				UDP: &packet.UDPSegment{
					Src:     &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000},
					Dst:     &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40000},
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
			if tt.wantRTCP {
				if len(transport.rtcpCh) != 1 || len(transport.readCh) != 0 {
					t.Fatalf("queues = rtp:%d rtcp:%d, want rtcp only", len(transport.readCh), len(transport.rtcpCh))
				}
				return
			}
			if len(transport.readCh) != 1 || len(transport.rtcpCh) != 0 {
				t.Fatalf("queues = rtp:%d rtcp:%d, want rtp only", len(transport.readCh), len(transport.rtcpCh))
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
			events := make(chan imsvoice.MediaPacket, 1)
			transport := &tunnelMediaTransport{
				logger:   testMediaLogger(),
				local:    &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40000},
				remote:   imsvoice.MediaRemote{RTP: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000}},
				readCh:   make(chan tunnelMediaPacket, 1),
				rtcpCh:   make(chan tunnelMediaPacket, 1),
				done:     make(chan struct{}),
				onPacket: func(packet imsvoice.MediaPacket) { events <- packet },
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

func TestTunnelMediaTransportDrainsPacketsAfterClose(t *testing.T) {
	tests := []struct {
		name       string
		srcIP      net.IP
		srcPort    int
		dstPort    int
		wantHandle bool
	}{
		{name: "closed rtp from negotiated remote", srcIP: net.IPv4(192, 0, 2, 10), srcPort: 50000, dstPort: 40000, wantHandle: true},
		{name: "closed rtcp from negotiated remote", srcIP: net.IPv4(192, 0, 2, 10), srcPort: 50001, dstPort: 40001, wantHandle: true},
		{name: "closed rtp from new remote", srcIP: net.IPv4(192, 0, 2, 20), srcPort: 51000, dstPort: 40000},
		{name: "closed rtp from alternate source port", srcIP: net.IPv4(192, 0, 2, 10), srcPort: 51000, dstPort: 40000},
		{name: "closed unrelated destination", srcIP: net.IPv4(192, 0, 2, 10), srcPort: 50000, dstPort: 40002},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := make(chan imsvoice.MediaPacket, 1)
			transport := &tunnelMediaTransport{
				logger:   testMediaLogger(),
				local:    &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40000},
				remote:   imsvoice.MediaRemote{RTP: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000}},
				readCh:   make(chan tunnelMediaPacket, 1),
				rtcpCh:   make(chan tunnelMediaPacket, 1),
				done:     make(chan struct{}),
				onPacket: func(packet imsvoice.MediaPacket) { events <- packet },
			}
			if err := transport.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			got := transport.HandleInnerPacket(packet.InnerPacket{
				UDP: &packet.UDPSegment{
					Src:     &net.UDPAddr{IP: tt.srcIP, Port: tt.srcPort},
					Dst:     &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: tt.dstPort},
					Payload: []byte("late media"),
				},
			})
			if got != tt.wantHandle {
				t.Fatalf("HandleInnerPacket() = %v, want %v", got, tt.wantHandle)
			}
			if len(events) != 0 {
				t.Fatal("HandleInnerPacket() notified media activity after close")
			}
			if len(transport.readCh) != 0 || len(transport.rtcpCh) != 0 {
				t.Fatal("HandleInnerPacket() queued media after close")
			}
		})
	}
}

func mediaConfigForTest(ip net.IP, port int) imsvoice.MediaConfig {
	return imsvoice.MediaConfig{RemoteIP: ip, RemotePort: port}
}

func testMediaLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
