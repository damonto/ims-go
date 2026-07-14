//go:build linux

package ims

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func listenVoLTEPacket(ctx context.Context, interfaceName string, local *net.UDPAddr) (net.PacketConn, error) {
	listenConfig := net.ListenConfig{
		Control: func(_, _ string, raw syscall.RawConn) error {
			var bindErr error
			if err := raw.Control(func(fd uintptr) {
				bindErr = unix.BindToDevice(int(fd), interfaceName)
			}); err != nil {
				return err
			}
			return bindErr
		},
	}
	return listenConfig.ListenPacket(ctx, "udp", local.String())
}
