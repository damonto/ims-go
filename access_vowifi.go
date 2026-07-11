package ims

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	imssession "github.com/damonto/ims-go/ims/session"
	imsvoice "github.com/damonto/ims-go/ims/voice"
	ipsectransport "github.com/damonto/ims-go/ipsec/transport"
	swutunnel "github.com/damonto/ims-go/swu/tunnel"
)

type voWiFiAccess struct {
	session   *swutunnel.Session
	tunnelCfg swutunnel.Config
	info      swutunnel.Info
}

type tunnelDatagramTransport struct {
	session *swutunnel.Session
}

func (t tunnelDatagramTransport) LocalAddr() net.Addr {
	return t.session.LocalAddr()
}

func (t tunnelDatagramTransport) RemoteAddr() net.Addr {
	return t.session.RemoteAddr()
}

func (t tunnelDatagramTransport) WritePacket(ctx context.Context, data []byte) error {
	return t.session.WritePacket(ctx, data)
}

func (t tunnelDatagramTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	return t.session.ReadPacket(ctx)
}

func (t tunnelDatagramTransport) Close() error {
	return nil
}

func (c *Client) openVoWiFiAccess(ctx context.Context, setup *connectSetup) (*voWiFiAccess, error) {
	tunnelInfo, err := c.openTunnel(ctx, setup)
	if err != nil {
		return nil, err
	}
	return &voWiFiAccess{
		session:   setup.tunnel,
		tunnelCfg: setup.tunnelCfg,
		info:      tunnelInfo,
	}, nil
}

func (a *voWiFiAccess) OpenIMS(ctx context.Context, cfg accessIMSConfig) (imsAccess, error) {
	pcscfIPs := pcscfCandidateIPs(a.info)
	associations := ipsectransport.NewSecurityAssociations()
	transport, selectedPCSCF, err := a.openSIPTransport(ctx, cfg, pcscfIPs)
	if err != nil {
		return imsAccess{}, err
	}
	return imsAccess{
		SIP:       transport,
		Security:  a.openSecurity(selectedPCSCF, cfg, associations),
		OpenMedia: a.openMedia,
	}, nil
}

func (a *voWiFiAccess) openSIPTransport(ctx context.Context, cfg accessIMSConfig, pcscfIPs []net.IP) (imssession.Transport, net.IP, error) {
	if cfg.Transport != "tcp" {
		return tunnelDatagramTransport{session: a.session}, firstPCSCFIP(pcscfIPs), nil
	}
	tcpTransport, selectedIP, err := a.dialPCSCFTCP(ctx, pcscfIPs, cfg.TCPDataACKTimeouts)
	if err != nil {
		return nil, nil, fmt.Errorf("dialing ims tcp transport: %w", err)
	}
	return tcpTransport, selectedIP, nil
}

func (a *voWiFiAccess) openSecurity(selectedPCSCF net.IP, cfg accessIMSConfig, associations *ipsectransport.SecurityAssociations) imsSecurity {
	security := imsSecurity{
		DialSecureUDP: func(ctx context.Context, cfg imssession.SecureUDPConfig) (imssession.Transport, error) {
			return ipsectransport.DialSecureUDP(ctx, a.session, ipsectransport.SecureUDPConfig{
				UDPConfig: ipsectransport.UDPConfig{
					LocalPort:  cfg.LocalPort,
					RemotePort: cfg.RemotePort,
					RemoteIP:   selectedPCSCF,
				},
				OutboundSPI:   cfg.OutboundSPI,
				InboundSPI:    cfg.InboundSPI,
				Encryption:    cfg.Encryption,
				EncryptionKey: cfg.EncryptionKey,
				Integrity:     cfg.Integrity,
				IntegrityKey:  cfg.IntegrityKey,
				Mode:          cfg.Mode,
				Salt:          cfg.Salt,
				Associations:  associations,
			})
		},
		ListenSecureUDP: func(ctx context.Context, cfg imssession.SecureUDPConfig) (imssession.Transport, error) {
			_ = ctx
			return ipsectransport.ListenSecureUDP(a.session, ipsectransport.SecureUDPConfig{
				UDPConfig: ipsectransport.UDPConfig{
					LocalPort:  cfg.LocalPort,
					RemotePort: cfg.RemotePort,
					RemoteIP:   selectedPCSCF,
				},
				OutboundSPI:   cfg.OutboundSPI,
				InboundSPI:    cfg.InboundSPI,
				Encryption:    cfg.Encryption,
				EncryptionKey: cfg.EncryptionKey,
				Integrity:     cfg.Integrity,
				IntegrityKey:  cfg.IntegrityKey,
				Mode:          cfg.Mode,
				Salt:          cfg.Salt,
				Associations:  associations,
			})
		},
	}
	if cfg.Transport == "tcp" {
		security.DialSecureTCP = func(ctx context.Context, secureCfg imssession.SecureTCPConfig) (imssession.Transport, error) {
			return ipsectransport.DialSecureTCP(ctx, a.session, ipsectransport.SecureTCPConfig{
				TCPConfig: ipsectransport.TCPConfig{
					LocalPort:       secureCfg.LocalPort,
					RemotePort:      secureCfg.RemotePort,
					RemoteIP:        selectedPCSCF,
					DataACKTimeouts: configuredTCPDataACKTimeouts(secureCfg.DataACKTimeouts, cfg.TCPDataACKTimeouts),
				},
				OutboundSPI:   secureCfg.OutboundSPI,
				InboundSPI:    secureCfg.InboundSPI,
				Encryption:    secureCfg.Encryption,
				EncryptionKey: secureCfg.EncryptionKey,
				Integrity:     secureCfg.Integrity,
				IntegrityKey:  secureCfg.IntegrityKey,
				Mode:          secureCfg.Mode,
				Salt:          secureCfg.Salt,
				Associations:  associations,
			})
		}
		security.ListenSecureTCP = func(ctx context.Context, secureCfg imssession.SecureTCPConfig) (imssession.Transport, error) {
			_ = ctx
			return ipsectransport.ListenSecureTCP(a.session, ipsectransport.SecureTCPConfig{
				TCPConfig: ipsectransport.TCPConfig{
					LocalPort:       secureCfg.LocalPort,
					RemotePort:      secureCfg.RemotePort,
					RemoteIP:        selectedPCSCF,
					DataACKTimeouts: configuredTCPDataACKTimeouts(secureCfg.DataACKTimeouts, cfg.TCPDataACKTimeouts),
				},
				OutboundSPI:   secureCfg.OutboundSPI,
				InboundSPI:    secureCfg.InboundSPI,
				Encryption:    secureCfg.Encryption,
				EncryptionKey: secureCfg.EncryptionKey,
				Integrity:     secureCfg.Integrity,
				IntegrityKey:  secureCfg.IntegrityKey,
				Mode:          secureCfg.Mode,
				Salt:          secureCfg.Salt,
				Associations:  associations,
			})
		}
	}
	return security
}

func (a *voWiFiAccess) openMedia(ctx context.Context, cfg imsvoice.MediaConfig) (imsvoice.MediaTransport, error) {
	return newTunnelMediaTransport(ctx, a.session, cfg)
}

func (a *voWiFiAccess) Close() error {
	if a.session == nil {
		return nil
	}
	return a.session.Close()
}

func (a *voWiFiAccess) dialPCSCFTCP(ctx context.Context, pcscfIPs []net.IP, dataACKTimeouts []time.Duration) (*ipsectransport.TCPConn, net.IP, error) {
	candidates := pcscfIPs
	if len(candidates) == 0 {
		candidates = []net.IP{nil}
	}
	var errs error
	for _, ip := range candidates {
		tcpTransport, err := ipsectransport.DialTCP(ctx, a.session, ipsectransport.TCPConfig{
			RemotePort:      a.tunnelCfg.SIPPort,
			RemoteIP:        ip,
			DataACKTimeouts: dataACKTimeouts,
		})
		if err == nil {
			return tcpTransport, tcpRemoteIP(tcpTransport), nil
		}
		errs = errors.Join(errs, fmt.Errorf("dialing P-CSCF %s: %w", ipLabel(ip), err))
	}
	return nil, nil, errs
}

func tcpRemoteIP(conn *ipsectransport.TCPConn) net.IP {
	remote := conn.RemoteAddr().(*net.TCPAddr)
	return append(net.IP(nil), remote.IP...)
}
