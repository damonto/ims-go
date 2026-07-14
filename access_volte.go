package ims

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	imssession "github.com/damonto/ims-go/ims/session"
	imsvoice "github.com/damonto/ims-go/ims/voice"
	ipsectransport "github.com/damonto/ims-go/ipsec/transport"
	"github.com/damonto/ims-go/lte"
	lteipsec "github.com/damonto/ims-go/lte/ipsec"
)

type imsPDNClient interface {
	OpenIMSPDN(context.Context, imsPDNConfig) (imsPDNSession, error)
}

type imsPDNConfig struct {
	APN          string
	PDNType      string
	ProfileIndex uint8
}

type imsPDNInfo struct {
	LocalIPv4       net.IP
	LocalIPv6       net.IP
	PCSCFIPs        []net.IP
	VoPSSupported   bool
	PacketDataReady bool
}

type imsPDNSession interface {
	Info() imsPDNInfo
	Close() error
}

type voLTEAccess struct {
	mu     sync.Mutex
	info   lte.Info
	pdn    imsPDNSession
	ipsec  *lteipsec.Session
	logger *slog.Logger
}

func (c *Client) openVoLTEAccess(ctx context.Context, setup *connectSetup) (*voLTEAccess, error) {
	client, ok := c.reader.(imsPDNClient)
	if !ok {
		return nil, errors.New("opening VoLTE access: WWAN client does not support IMS PDN")
	}
	pdn, err := client.OpenIMSPDN(ctx, imsPDNConfig{
		APN:          c.cfg.Access.VoLTE.APN,
		PDNType:      c.cfg.Access.VoLTE.PDNType,
		ProfileIndex: c.cfg.Access.VoLTE.ProfileIndex,
	})
	if err != nil {
		return nil, fmt.Errorf("opening VoLTE IMS PDN: %w", err)
	}
	info := lteInfoFromIMSPDN(*c.cfg.Access.VoLTE, pdn.Info())
	if c.cfg.Access.VoLTE.RequireVoPS && !info.VoPSSupported {
		_ = pdn.Close()
		return nil, errors.New("opening VoLTE access: LTE IMS voice over PS is unavailable")
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
		info:   info,
		pdn:    pdn,
		logger: c.cfg.Logger,
	}, nil
}

func (a *voLTEAccess) OpenIMS(ctx context.Context, cfg accessIMSConfig) (imsAccess, error) {
	a.mu.Lock()
	route, ok := a.info.RouteToPCSCF()
	accessNetworkInfo := a.info.AccessNetworkInfo
	a.mu.Unlock()
	if !ok {
		return imsAccess{}, errors.New("opening IMS over VoLTE: IMS PDN route to P-CSCF is unavailable")
	}
	transport, err := a.openSIPTransportTo(ctx, cfg, route)
	if err != nil {
		return imsAccess{}, err
	}
	ipsecSession, err := lteipsec.NewSession(route.LocalIP, route.RemoteIP, a.logger)
	if err != nil {
		_ = transport.Close()
		return imsAccess{}, err
	}
	a.mu.Lock()
	a.ipsec = ipsecSession
	a.mu.Unlock()
	return imsAccess{
		AccessNetworkInfo: accessNetworkInfo,
		SIP:               transport,
		Security:          a.openSecurity(route.RemoteIP, cfg, ipsecSession),
		OpenMedia: func(ctx context.Context, cfg imsvoice.MediaConfig) (imsvoice.MediaTransport, error) {
			return a.openMedia(ctx, cfg)
		},
	}, nil
}

func (a *voLTEAccess) openSIPTransportTo(ctx context.Context, cfg accessIMSConfig, route lte.Route) (imssession.Transport, error) {
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

func (a *voLTEAccess) openSecurity(remoteIP net.IP, cfg accessIMSConfig, session *lteipsec.Session) imsSecurity {
	associations := ipsectransport.NewSecurityAssociations()
	enable := func(ctx context.Context, mode string) error {
		if err := session.Enable(ctx, mode); err != nil {
			return fmt.Errorf("opening VoLTE IPsec transport: %w", err)
		}
		return nil
	}
	return imsSecurity{
		DialSecureUDP: func(ctx context.Context, secure imssession.SecureUDPConfig) (imssession.Transport, error) {
			if err := enable(ctx, secure.Mode); err != nil {
				return nil, err
			}
			return ipsectransport.DialSecureUDP(ctx, session, ipsectransport.SecureUDPConfig{
				UDPConfig:   ipsectransport.UDPConfig{LocalPort: secure.LocalPort, RemotePort: secure.RemotePort, RemoteIP: remoteIP},
				OutboundSPI: secure.OutboundSPI, InboundSPI: secure.InboundSPI,
				Encryption: secure.Encryption, EncryptionKey: secure.EncryptionKey,
				Integrity: secure.Integrity, IntegrityKey: secure.IntegrityKey,
				Mode: secure.Mode, Salt: secure.Salt, Associations: associations,
			})
		},
		ListenSecureUDP: func(ctx context.Context, secure imssession.SecureUDPConfig) (imssession.Transport, error) {
			if err := enable(ctx, secure.Mode); err != nil {
				return nil, err
			}
			return ipsectransport.ListenSecureUDP(session, ipsectransport.SecureUDPConfig{
				UDPConfig:   ipsectransport.UDPConfig{LocalPort: secure.LocalPort, RemotePort: secure.RemotePort, RemoteIP: remoteIP},
				OutboundSPI: secure.OutboundSPI, InboundSPI: secure.InboundSPI,
				Encryption: secure.Encryption, EncryptionKey: secure.EncryptionKey,
				Integrity: secure.Integrity, IntegrityKey: secure.IntegrityKey,
				Mode: secure.Mode, Salt: secure.Salt, Associations: associations,
			})
		},
		DialSecureTCP: func(ctx context.Context, secure imssession.SecureTCPConfig) (imssession.Transport, error) {
			if err := enable(ctx, secure.Mode); err != nil {
				return nil, err
			}
			return ipsectransport.DialSecureTCP(ctx, session, ipsectransport.SecureTCPConfig{
				TCPConfig:   ipsectransport.TCPConfig{LocalPort: secure.LocalPort, RemotePort: secure.RemotePort, RemoteIP: remoteIP, DataACKTimeouts: configuredTCPDataACKTimeouts(secure.DataACKTimeouts, cfg.TCPDataACKTimeouts)},
				OutboundSPI: secure.OutboundSPI, InboundSPI: secure.InboundSPI,
				Encryption: secure.Encryption, EncryptionKey: secure.EncryptionKey,
				Integrity: secure.Integrity, IntegrityKey: secure.IntegrityKey,
				Mode: secure.Mode, Salt: secure.Salt, Associations: associations,
			})
		},
		ListenSecureTCP: func(ctx context.Context, secure imssession.SecureTCPConfig) (imssession.Transport, error) {
			if err := enable(ctx, secure.Mode); err != nil {
				return nil, err
			}
			return ipsectransport.ListenSecureTCP(session, ipsectransport.SecureTCPConfig{
				TCPConfig:   ipsectransport.TCPConfig{LocalPort: secure.LocalPort, RemotePort: secure.RemotePort, RemoteIP: remoteIP, DataACKTimeouts: configuredTCPDataACKTimeouts(secure.DataACKTimeouts, cfg.TCPDataACKTimeouts)},
				OutboundSPI: secure.OutboundSPI, InboundSPI: secure.InboundSPI,
				Encryption: secure.Encryption, EncryptionKey: secure.EncryptionKey,
				Integrity: secure.Integrity, IntegrityKey: secure.IntegrityKey,
				Mode: secure.Mode, Salt: secure.Salt, Associations: associations,
			})
		},
	}
}

func (a *voLTEAccess) openMedia(ctx context.Context, cfg imsvoice.MediaConfig) (imsvoice.MediaTransport, error) {
	a.mu.Lock()
	info := a.info.Clone()
	a.mu.Unlock()
	route, ok := info.RouteTo(cfg.RemoteIP)
	if !ok {
		return nil, errors.New("opening voice media transport: local IMS PDN address is unavailable")
	}
	return openVoLTEMediaTransport(ctx, info.InterfaceName, route.LocalIP, cfg)
}

func (a *voLTEAccess) Close() error {
	a.mu.Lock()
	ipsecSession := a.ipsec
	a.ipsec = nil
	pdn := a.pdn
	a.pdn = nil
	a.mu.Unlock()

	var err error
	if ipsecSession != nil {
		err = errors.Join(err, ipsecSession.Close())
	}
	if pdn != nil {
		err = errors.Join(err, pdn.Close())
	}
	return err
}

func (a *voLTEAccess) PCSCFCandidateCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.info.PCSCFCandidateCount()
}

func (a *voLTEAccess) SelectNextPCSCF() error {
	a.mu.Lock()
	next, ok := a.info.WithNextPCSCF()
	if !ok {
		a.mu.Unlock()
		return errors.New("selecting next P-CSCF: no alternate P-CSCF")
	}
	ipsecSession := a.ipsec
	a.ipsec = nil
	a.mu.Unlock()
	if ipsecSession != nil {
		if err := ipsecSession.Close(); err != nil {
			return fmt.Errorf("selecting next P-CSCF: closing previous LTE IPsec session: %w", err)
		}
	}
	a.mu.Lock()
	a.info = next
	a.mu.Unlock()
	return nil
}

func lteInfoFromIMSPDN(cfg lte.Config, pdn imsPDNInfo) lte.Info {
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
