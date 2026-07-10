package ims

import (
	"context"
	"errors"
	"fmt"
	"net"

	imssession "github.com/damonto/ims-go/ims/session"
	imsvoice "github.com/damonto/ims-go/ims/voice"
	"github.com/damonto/ims-go/lte"
	"github.com/damonto/uicc-go/usim"
)

type imsPDNReader interface {
	OpenIMSPDN(context.Context, usim.IMSPDNConfig) (*usim.IMSPDNSession, error)
}

type voLTEAccess struct {
	info lte.Info
	pdn  *usim.IMSPDNSession
}

func (c *Client) openVoLTEAccess(ctx context.Context, setup *connectSetup) (*voLTEAccess, error) {
	reader, ok := c.reader.(imsPDNReader)
	if !ok {
		return nil, errors.New("opening VoLTE access: USIM reader does not support IMS PDN")
	}
	pdn, err := reader.OpenIMSPDN(ctx, usim.IMSPDNConfig{
		APN:     c.cfg.Access.VoLTE.APN,
		PDNType: c.cfg.Access.VoLTE.PDNType,
	})
	if err != nil {
		return nil, fmt.Errorf("opening VoLTE IMS PDN: %w", err)
	}
	info := lteInfoFromIMSPDN(*c.cfg.Access.VoLTE, pdn.Info())
	if c.cfg.Access.VoLTE.RequireVoPS && !info.VoPSSupported {
		_ = pdn.Close()
		return nil, errors.New("opening VoLTE access: LTE IMS voice over PS is unavailable")
	}
	if info.AccessNetworkInfo == "" {
		info.AccessNetworkInfo = lte.DefaultAccessNetworkInfo
	}
	if len(info.LocalIPv4) == 0 && len(info.LocalIPv6) == 0 {
		_ = pdn.Close()
		return nil, errors.New("opening VoLTE access: IMS PDN local address is unavailable")
	}
	if len(info.PCSCFIPs) == 0 {
		_ = pdn.Close()
		return nil, errors.New("opening VoLTE access: P-CSCF address is unavailable")
	}
	setup.tunnel = nil
	return &voLTEAccess{
		info: info,
		pdn:  pdn,
	}, nil
}

func (a *voLTEAccess) OpenIMS(ctx context.Context, cfg accessIMSConfig) (imsAccess, error) {
	transport, err := a.openSIPTransport(ctx, cfg)
	if err != nil {
		return imsAccess{}, err
	}
	return imsAccess{
		AccessNetworkInfo: a.info.AccessNetworkInfo,
		SIP:               transport,
		OpenMedia: func(ctx context.Context, cfg imsvoice.MediaConfig) (imsvoice.MediaTransport, error) {
			return a.openMedia(ctx, cfg)
		},
	}, nil
}

func (a *voLTEAccess) openSIPTransport(ctx context.Context, cfg accessIMSConfig) (imssession.Transport, error) {
	route, ok := a.info.RouteToPCSCF()
	if !ok {
		return nil, errors.New("opening sip transport: IMS PDN route to P-CSCF is unavailable")
	}
	remotePort := cfg.SIPServerPort
	if remotePort == 0 {
		remotePort = defaultSIPServerPort
	}
	switch cfg.Transport {
	case "tcp":
		return imssession.OpenTCPTransport(ctx, route.LocalIP, route.RemoteIP, remotePort)
	case "udp":
		return imssession.OpenUDPTransport(ctx, route.LocalIP, route.RemoteIP, remotePort)
	default:
		return nil, fmt.Errorf("opening sip transport: unsupported transport %q", cfg.Transport)
	}
}

func (a *voLTEAccess) openMedia(ctx context.Context, cfg imsvoice.MediaConfig) (imsvoice.MediaTransport, error) {
	route, ok := a.info.RouteTo(cfg.RemoteIP)
	if !ok {
		return nil, errors.New("opening voice media transport: local IMS PDN address is unavailable")
	}
	return openVoLTEMediaTransport(ctx, route.LocalIP, cfg)
}

func (a *voLTEAccess) Close() error {
	if a.pdn == nil {
		return nil
	}
	return a.pdn.Close()
}

func lteInfoFromIMSPDN(cfg lte.Config, pdn usim.IMSPDNInfo) lte.Info {
	info := lte.Info{
		InterfaceName:     cfg.InterfaceName,
		LocalIPv4:         append(net.IP(nil), pdn.LocalIPv4...),
		LocalIPv6:         append(net.IP(nil), pdn.LocalIPv6...),
		PCSCFIPs:          cloneNetIPs(pdn.PCSCFIPs),
		AccessNetworkInfo: cfg.AccessNetworkInfo,
		VoPSSupported:     pdn.VoPSSupported,
		IMSPDNConnected:   pdn.PacketDataReady,
		VoiceBearerReady:  pdn.PacketDataReady,
	}
	if len(cfg.LocalIPv4) != 0 {
		info.LocalIPv4 = append(net.IP(nil), cfg.LocalIPv4...)
	}
	if len(cfg.LocalIPv6) != 0 {
		info.LocalIPv6 = append(net.IP(nil), cfg.LocalIPv6...)
	}
	if len(cfg.PCSCFIPs) != 0 {
		info.PCSCFIPs = cloneNetIPs(cfg.PCSCFIPs)
	}
	return info
}

func cloneNetIPs(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		out = append(out, append(net.IP(nil), ip...))
	}
	return out
}
