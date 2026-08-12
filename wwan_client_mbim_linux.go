//go:build linux

package ims

import (
	"context"
	"errors"
	"fmt"

	"github.com/damonto/wwan-go/mbim"
	"github.com/damonto/wwan-go/sim"
)

type MBIMClient struct {
	*sim.MBIM
	client  *mbim.Client
	network PDNNetwork
}

// MBIMClientConfig configures MBIM-specific IMS PDN access.
type MBIMClientConfig struct {
	Network PDNNetwork
}

// NewMBIMClient adapts a wwan-go MBIM client for SIM access and VoLTE IMS PDN setup.
// The returned client owns the supplied client and closes it from Close.
func NewMBIMClient(client *mbim.Client, cfg MBIMClientConfig) (*MBIMClient, error) {
	wwan, err := sim.NewMBIM(client)
	if err != nil {
		return nil, err
	}
	return &MBIMClient{MBIM: wwan, client: client, network: cfg.Network}, nil
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
	return configurePDNNetwork(ctx, adapted, c.network, PDNNetworkInfo{
		SessionID: uint32(info.SessionID),
		LocalIPv4: info.LocalIPv4,
		LocalIPv6: info.LocalIPv6,
		PCSCFIPs:  info.PCSCFIPs,
	})
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
