package ims

import (
	"context"
	"errors"
	"net"
)

func listenVoLTEUDP(ctx context.Context, interfaceName string, local *net.UDPAddr) (*net.UDPConn, error) {
	if interfaceName == "" {
		return nil, errors.New("IMS interface is required")
	}
	packetConn, err := listenVoLTEPacket(ctx, interfaceName, local)
	if err != nil {
		return nil, err
	}
	udp, ok := packetConn.(*net.UDPConn)
	if !ok {
		_ = packetConn.Close()
		return nil, errors.New("UDP listener has unexpected type")
	}
	return udp, nil
}
