package ims

import (
	"context"
	"errors"
	"net"
	"sync"

	imsvoice "github.com/damonto/ims-go/ims/voice"
)

// PDNNetworkInfo contains the host-side network state negotiated for an IMS PDN.
type PDNNetworkInfo struct {
	SessionID   uint32
	LocalIPv4   net.IP
	LocalIPv6   net.IP
	IPv4Gateway net.IP
	IPv6Gateway net.IP
	PCSCFIPs    []net.IP
}

// PDNNetwork applies and removes host-side interface addresses and IMS routing state.
type PDNNetwork interface {
	Replace(context.Context, PDNNetworkInfo) (string, error)
	Close() error
}

type networkedPDNSession struct {
	imsPDNSession
	network       PDNNetwork
	interfaceName string
	closeOnce     sync.Once
	closeErr      error
}

func configurePDNNetwork(ctx context.Context, session imsPDNSession, network PDNNetwork, info PDNNetworkInfo) (imsPDNSession, error) {
	if network == nil {
		return session, nil
	}
	interfaceName, err := network.Replace(ctx, info)
	if err != nil {
		return nil, errors.Join(err, network.Close(), session.Close())
	}
	return &networkedPDNSession{
		imsPDNSession: session,
		network:       network,
		interfaceName: interfaceName,
	}, nil
}

func (s *networkedPDNSession) Info() imsPDNInfo {
	info := s.imsPDNSession.Info()
	info.InterfaceName = s.interfaceName
	return info
}

func (s *networkedPDNSession) WaitMediaReady(ctx context.Context, cfg imsvoice.MediaConfig) error {
	readiness, ok := s.imsPDNSession.(imsPDNMediaReadiness)
	if !ok {
		return errVoLTEMediaReadinessUnavailable
	}
	return readiness.WaitMediaReady(ctx, cfg)
}

func (s *networkedPDNSession) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = errors.Join(s.network.Close(), s.imsPDNSession.Close())
	})
	return s.closeErr
}
