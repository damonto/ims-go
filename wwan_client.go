package ims

import (
	"context"
	"errors"
	"net"
	"sync"

	imsvoice "github.com/damonto/ims-go/ims/voice"
)

// IMSPDNNetworkInfo contains the host-side network state negotiated for an IMS PDN.
type IMSPDNNetworkInfo struct {
	SessionID   uint32
	LocalIPv4   net.IP
	LocalIPv6   net.IP
	IPv4Gateway net.IP
	IPv6Gateway net.IP
	PCSCFIPs    []net.IP
}

// IMSPDNNetwork applies and removes host-side interface addresses and IMS routing state.
type IMSPDNNetwork interface {
	Replace(context.Context, IMSPDNNetworkInfo) (string, error)
	Close() error
}

type networkedIMSPDNSession struct {
	imsPDNSession
	network       IMSPDNNetwork
	interfaceName string
	closeOnce     sync.Once
	closeErr      error
}

func configureIMSPDNNetwork(ctx context.Context, session imsPDNSession, network IMSPDNNetwork, info IMSPDNNetworkInfo) (imsPDNSession, error) {
	if network == nil {
		return session, nil
	}
	interfaceName, err := network.Replace(ctx, info)
	if err != nil {
		return nil, errors.Join(err, network.Close(), session.Close())
	}
	return &networkedIMSPDNSession{
		imsPDNSession: session,
		network:       network,
		interfaceName: interfaceName,
	}, nil
}

func (s *networkedIMSPDNSession) Info() imsPDNInfo {
	info := s.imsPDNSession.Info()
	info.InterfaceName = s.interfaceName
	return info
}

func (s *networkedIMSPDNSession) WaitMediaReady(ctx context.Context, cfg imsvoice.MediaConfig) error {
	readiness, ok := s.imsPDNSession.(imsPDNMediaReadiness)
	if !ok {
		return errVoLTEMediaReadinessUnavailable
	}
	return readiness.WaitMediaReady(ctx, cfg)
}

func (s *networkedIMSPDNSession) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = errors.Join(s.network.Close(), s.imsPDNSession.Close())
	})
	return s.closeErr
}
