//go:build !linux

package ims

import (
	"context"
	"net"
)

func listenVoLTEPacket(ctx context.Context, _ string, local *net.UDPAddr) (net.PacketConn, error) {
	var listenConfig net.ListenConfig
	return listenConfig.ListenPacket(ctx, "udp", local.String())
}
