package ipsec

import (
	"context"
	"log/slog"
	"net"

	"github.com/damonto/ims-go/ipsec/packet"
)

// InnerHandler consumes decrypted packets from an IPsec data plane.
type InnerHandler interface {
	HandleInnerPacket(pkt packet.InnerPacket) bool
	HandleError(err error)
}

// Attachment controls the lifetime of a data-plane handler registration.
type Attachment interface {
	Close() error
}

// PacketSession is the data-plane contract shared by SWu and LTE access.
type PacketSession interface {
	InnerIPsForRemote(remoteIP net.IP) (net.IP, net.IP, error)
	Attach(handler InnerHandler) (Attachment, error)
	WriteInnerPacket(ctx context.Context, pkt packet.InnerPacket) error
	Logger() *slog.Logger
	Close() error
}
