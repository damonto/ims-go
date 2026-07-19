package ims

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/damonto/wwan-go/mbim"
	"github.com/damonto/wwan-go/sim"
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

type MBIMClient struct {
	*sim.MBIM
	client  *mbim.Client
	network IMSPDNNetwork
}

// MBIMClientConfig configures MBIM-specific IMS PDN access.
type MBIMClientConfig struct {
	Network IMSPDNNetwork
}

// NewMBIMClient adapts a wwan-go MBIM client for SIM access and VoLTE IMS PDN setup.
// The returned client owns the supplied client and closes it from Close.
func NewMBIMClient(client *mbim.Client, cfg MBIMClientConfig) (*MBIMClient, error) {
	reader, err := sim.NewMBIM(client)
	if err != nil {
		return nil, err
	}
	return &MBIMClient{MBIM: reader, client: client, network: cfg.Network}, nil
}

func (c *MBIMClient) OpenIMSPDN(ctx context.Context, cfg imsPDNConfig) (imsPDNSession, error) {
	if cfg.ProfileIndex != 0 {
		return nil, errors.New("opening MBIM IMS PDN: profile index is unsupported")
	}
	ipType, err := mbimIPType(cfg.PDNType)
	if err != nil {
		return nil, err
	}
	session, err := c.client.OpenIMSPDN(ctx, mbim.IMSPDNConfig{
		APN:    cfg.APN,
		IPType: ipType,
	})
	if err != nil {
		return nil, err
	}
	adapted := mbimIMSPDNSession{session}
	info := session.Info()
	return configureIMSPDNNetwork(ctx, adapted, c.network, IMSPDNNetworkInfo{
		SessionID: info.SessionID,
		LocalIPv4: info.LocalIPv4,
		LocalIPv6: info.LocalIPv6,
		PCSCFIPs:  info.PCSCFIPs,
	})
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

func (s *networkedIMSPDNSession) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = errors.Join(s.network.Close(), s.imsPDNSession.Close())
	})
	return s.closeErr
}

type mbimIMSPDNSession struct {
	*mbim.IMSPDNSession
}

func (s mbimIMSPDNSession) Info() imsPDNInfo {
	info := s.IMSPDNSession.Info()
	return imsPDNInfo{
		LocalIPv4:       info.LocalIPv4,
		LocalIPv6:       info.LocalIPv6,
		PCSCFIPs:        info.PCSCFIPs,
		VoPSKnown:       info.VoPSKnown,
		VoPSSupported:   info.VoPSSupported,
		PacketDataReady: info.PacketDataReady,
	}
}

func mbimIPType(pdnType string) (mbim.ContextIPType, error) {
	switch pdnType {
	case "ipv4":
		return mbim.ContextIPTypeIPv4, nil
	case "ipv6":
		return mbim.ContextIPTypeIPv6, nil
	case "ipv4v6":
		return mbim.ContextIPTypeIPv4v6, nil
	default:
		return 0, fmt.Errorf("opening MBIM IMS PDN: unsupported PDN type %q", pdnType)
	}
}
