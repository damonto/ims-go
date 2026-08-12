//go:build linux

package ims

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenVoLTEMediaTransportBindsIMSInterface(t *testing.T) {
	tests := []struct {
		name          string
		interfaceName string
		wantErr       bool
	}{
		{name: "loopback", interfaceName: "lo"},
		{name: "missing interface", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network, err := newVoLTENetwork(net.InterfaceByName, tt.interfaceName)
			var conn *net.UDPConn
			if err == nil {
				conn, err = network.ListenUDP(t.Context(), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			}
			if tt.wantErr {
				if err == nil {
					if closeErr := conn.Close(); closeErr != nil {
						t.Errorf("Close() error = %v", closeErr)
					}
					t.Fatal("opening VoLTE UDP listener error = nil, want error")
				}
				return
			}
			if err != nil {
				if errors.Is(err, syscall.EPERM) {
					t.Skip("sandbox does not permit binding a UDP socket to an interface")
				}
				t.Fatalf("opening VoLTE UDP listener: %v", err)
			}
			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Errorf("Close() error = %v", err)
				}
			})
			raw, err := conn.SyscallConn()
			if err != nil {
				t.Fatalf("SyscallConn() error = %v", err)
			}
			var got string
			var sockoptErr error
			if controlErr := raw.Control(func(fd uintptr) {
				got, sockoptErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
			}); controlErr != nil {
				t.Fatalf("Control() error = %v", controlErr)
			}
			if sockoptErr != nil {
				t.Fatalf("GetsockoptString() error = %v", sockoptErr)
			}
			if got != tt.interfaceName {
				t.Fatalf("SO_BINDTODEVICE = %q, want %q", got, tt.interfaceName)
			}
		})
	}
}
