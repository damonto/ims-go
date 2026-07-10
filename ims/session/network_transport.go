package session

import (
	"context"
	"errors"
	"net"
	"time"
)

const (
	networkReadPollInterval = 250 * time.Millisecond
	maxSIPHeaderBytes       = 32 * 1024
	maxSIPMessageBytes      = 1024 * 1024
	sipReadBufferLength     = 8192
)

func networkReadDeadline(ctx context.Context) time.Time {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	return time.Now().Add(networkReadPollInterval)
}

func contextDeadline(ctx context.Context) (time.Time, bool) {
	deadline, ok := ctx.Deadline()
	return deadline, ok
}

func isNetworkTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}

func cloneTCPAddr(addr *net.TCPAddr) *net.TCPAddr {
	if addr == nil {
		return nil
	}
	return &net.TCPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}
