package voice

import (
	"net"
	"strings"
	"testing"
)

func TestRTCPPacketClassification(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		wantRTCP bool
		wantBye  bool
	}{
		{name: "rtp payload", payload: []byte{0x80, 104, 0, 1, 0, 0, 0, 1}},
		{name: "rtcp receiver report", payload: []byte{0x80, 201, 0, 1, 0, 0, 0, 1}, wantRTCP: true},
		{name: "rtcp bye", payload: []byte{0x81, 203, 0, 1, 0, 0, 0, 1}, wantRTCP: true, wantBye: true},
		{name: "truncated rtcp", payload: []byte{0x80, 201, 0, 2, 0, 0, 0, 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRTCPPacket(tt.payload); got != tt.wantRTCP {
				t.Fatalf("IsRTCPPacket() = %v, want %v", got, tt.wantRTCP)
			}
			if got := HasRTCPBye(tt.payload); got != tt.wantBye {
				t.Fatalf("HasRTCPBye() = %v, want %v", got, tt.wantBye)
			}
		})
	}
}

func TestMediaUDPAddressOperations(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 40000, Zone: "zone"}
	cloned := CloneUDPAddr(addr)
	if cloned == addr || !UDPAddrMatches(cloned, addr) || cloned.Zone != addr.Zone {
		t.Fatalf("CloneUDPAddr() = %v, want independent matching addr", cloned)
	}
	cloned.IP[0] = 198
	if addr.IP[0] == 198 {
		t.Fatal("CloneUDPAddr() shared IP backing array")
	}
	rtcp := RTCPAddr(addr)
	if rtcp.Port != 40001 || !rtcp.IP.Equal(addr.IP) || rtcp.Zone != addr.Zone {
		t.Fatalf("RTCPAddr() = %v, want same IP/zone and port 40001", rtcp)
	}
}

func TestMediaRemoteFromConfig(t *testing.T) {
	tests := []struct {
		name        string
		cfg         MediaConfig
		wantRemote  *net.UDPAddr
		wantRTCP    *net.UDPAddr
		wantRTCPMux bool
		wantErr     bool
		wantErrIn   string
	}{
		{
			name:       "rtp only",
			cfg:        MediaConfig{RemoteIP: net.IPv4(192, 0, 2, 10), RemotePort: 50000},
			wantRemote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000},
			wantRTCP:   &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50001},
		},
		{
			name:       "explicit rtcp port",
			cfg:        MediaConfig{RemoteIP: net.IPv4(192, 0, 2, 10), RemotePort: 50000, RemoteRTCPPort: 51000},
			wantRemote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000},
			wantRTCP:   &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 51000},
		},
		{
			name:       "explicit rtcp address",
			cfg:        MediaConfig{RemoteIP: net.IPv4(192, 0, 2, 10), RemotePort: 50000, RemoteRTCPIP: net.IPv4(192, 0, 2, 20), RemoteRTCPPort: 51000},
			wantRemote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000},
			wantRTCP:   &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 51000},
		},
		{
			name:        "rtcp mux",
			cfg:         MediaConfig{RemoteIP: net.IPv4(192, 0, 2, 10), RemotePort: 50000, RemoteRTCPPort: 51000, RTCPMux: true},
			wantRemote:  &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000},
			wantRTCP:    &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50000},
			wantRTCPMux: true,
		},
		{
			name:      "missing remote",
			cfg:       MediaConfig{},
			wantErr:   true,
			wantErrIn: "remote address is required",
		},
		{
			name:      "invalid rtcp port",
			cfg:       MediaConfig{RemoteIP: net.IPv4(192, 0, 2, 10), RemotePort: 50000, RemoteRTCPPort: 70000},
			wantErr:   true,
			wantErrIn: "remote rtcp port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			remote, err := MediaRemoteFromConfig(tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("MediaRemoteFromConfig() error = nil, want non-nil")
				}
				if tt.wantErrIn != "" && !strings.Contains(err.Error(), tt.wantErrIn) {
					t.Fatalf("MediaRemoteFromConfig() error = %v, want containing %q", err, tt.wantErrIn)
				}
				return
			}
			if err != nil {
				t.Fatalf("MediaRemoteFromConfig() error = %v", err)
			}
			if !UDPAddrMatches(remote.Addr(false), tt.wantRemote) {
				t.Fatalf("remote = %v, want %v", remote.Addr(false), tt.wantRemote)
			}
			if !UDPAddrMatches(remote.Addr(true), tt.wantRTCP) {
				t.Fatalf("rtcp = %v, want %v", remote.Addr(true), tt.wantRTCP)
			}
			if remote.RTCPMux != tt.wantRTCPMux {
				t.Fatalf("rtcpMux = %v, want %v", remote.RTCPMux, tt.wantRTCPMux)
			}
		})
	}
}
