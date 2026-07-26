package ims

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	imssession "github.com/damonto/ims-go/ims/session"
	imsvoice "github.com/damonto/ims-go/ims/voice"
	ipsectransport "github.com/damonto/ims-go/ipsec/transport"
	swutunnel "github.com/damonto/ims-go/swu/tunnel"
)

type voWiFiAccess struct {
	mu        sync.Mutex
	session   *swutunnel.Session
	netstack  *ipsectransport.Netstack
	tunnelCfg swutunnel.Config
	info      swutunnel.Info
	current   net.IP
}

func (c *Client) openVoWiFiAccess(ctx context.Context, setup *connectSetup) (*voWiFiAccess, error) {
	tunnelInfo, err := c.openTunnel(ctx, setup)
	if err != nil {
		return nil, err
	}
	netstack, err := ipsectransport.NewNetstack(setup.tunnel)
	if err != nil {
		_ = setup.tunnel.Close()
		return nil, fmt.Errorf("opening VoWiFi userspace network stack: %w", err)
	}
	return &voWiFiAccess{
		session:   setup.tunnel,
		netstack:  netstack,
		tunnelCfg: setup.tunnelCfg,
		info:      tunnelInfo,
	}, nil
}

func (a *voWiFiAccess) OpenIMS(ctx context.Context, cfg accessIMSConfig) (imsAccess, error) {
	a.mu.Lock()
	info := a.info
	a.mu.Unlock()
	pcscfIPs := pcscfCandidateIPs(info)
	associations := ipsectransport.NewSecurityAssociations()
	transport, selectedPCSCF, err := a.openSIPTransport(ctx, cfg, pcscfIPs)
	if err != nil {
		return imsAccess{}, err
	}
	a.mu.Lock()
	a.current = append(net.IP(nil), selectedPCSCF...)
	a.mu.Unlock()
	return imsAccess{
		SIP: transport,
		OpenReliableSIP: func(ctx context.Context) (imssession.Transport, error) {
			reliable, _, err := a.dialPCSCFTCP(ctx, []net.IP{selectedPCSCF})
			return reliable, err
		},
		Security:       a.openSecurity(selectedPCSCF, cfg, associations),
		OpenMedia:      a.openMedia,
		WaitMediaReady: voWiFiMediaReady,
	}, nil
}

func voWiFiMediaReady(ctx context.Context, _ imsvoice.MediaConfig) error {
	return ctx.Err()
}

func (a *voWiFiAccess) PCSCFCandidateCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(pcscfCandidateIPs(a.info))
}

func (a *voWiFiAccess) SelectNextPCSCF() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	next, ok := nextPCSCFInfo(a.info, a.current)
	if !ok {
		return errors.New("selecting next P-CSCF: no alternate P-CSCF")
	}
	a.info = next
	a.current = nil
	return nil
}

func (a *voWiFiAccess) pcscfInfo() swutunnel.Info {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.info
}

func (a *voWiFiAccess) openSIPTransport(ctx context.Context, cfg accessIMSConfig, pcscfIPs []net.IP) (imssession.Transport, net.IP, error) {
	if cfg.Transport == "udp" {
		udpTransport, selectedIP, err := a.dialPCSCFUDP(ctx, pcscfIPs)
		if err != nil {
			return nil, nil, fmt.Errorf("dialing IMS UDP transport: %w", err)
		}
		return udpTransport, selectedIP, nil
	}
	if cfg.Transport != "tcp" {
		return nil, nil, fmt.Errorf("opening IMS transport: unsupported transport %q", cfg.Transport)
	}
	tcpTransport, selectedIP, err := a.dialPCSCFTCP(ctx, pcscfIPs)
	if err != nil {
		return nil, nil, fmt.Errorf("dialing ims tcp transport: %w", err)
	}
	return tcpTransport, selectedIP, nil
}

func (a *voWiFiAccess) openSecurity(selectedPCSCF net.IP, cfg accessIMSConfig, associations *ipsectransport.SecurityAssociations) imsSecurity {
	security := imsSecurity{
		DialSecureUDP: func(ctx context.Context, cfg imssession.SecureUDPConfig) (imssession.Transport, error) {
			return a.netstack.DialSecureUDP(ctx, ipsectransport.SecureUDPConfig{
				InnerLocalIP: cfg.InnerLocalIP,
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
				OutboundSalt:  cfg.OutboundSalt,
				InboundSalt:   cfg.InboundSalt,
				Associations:  associations,
			})
		},
		ListenSecureUDP: func(ctx context.Context, cfg imssession.SecureUDPConfig) (imssession.Transport, error) {
			return a.netstack.ListenSecureUDP(ctx, ipsectransport.SecureUDPConfig{
				InnerLocalIP: cfg.InnerLocalIP,
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
				OutboundSalt:  cfg.OutboundSalt,
				InboundSalt:   cfg.InboundSalt,
				Associations:  associations,
			})
		},
	}
	security.DialSecureTCP = func(ctx context.Context, secureCfg imssession.SecureTCPConfig) (imssession.Transport, error) {
		return a.netstack.DialSecureTCP(ctx, ipsectransport.SecureTCPConfig{
			InnerLocalIP: secureCfg.InnerLocalIP,
			TCPConfig: ipsectransport.TCPConfig{
				LocalPort:  secureCfg.LocalPort,
				RemotePort: secureCfg.RemotePort,
				RemoteIP:   selectedPCSCF,
			},
			OutboundSPI:   secureCfg.OutboundSPI,
			InboundSPI:    secureCfg.InboundSPI,
			Encryption:    secureCfg.Encryption,
			EncryptionKey: secureCfg.EncryptionKey,
			Integrity:     secureCfg.Integrity,
			IntegrityKey:  secureCfg.IntegrityKey,
			Mode:          secureCfg.Mode,
			OutboundSalt:  secureCfg.OutboundSalt,
			InboundSalt:   secureCfg.InboundSalt,
			Associations:  associations,
		})
	}
	if cfg.Transport == "tcp" {
		security.ListenSecureTCP = func(ctx context.Context, secureCfg imssession.SecureTCPConfig) (imssession.Transport, error) {
			return a.netstack.ListenSecureTCP(ctx, ipsectransport.SecureTCPConfig{
				InnerLocalIP: secureCfg.InnerLocalIP,
				TCPConfig: ipsectransport.TCPConfig{
					LocalPort:  secureCfg.LocalPort,
					RemotePort: secureCfg.RemotePort,
					RemoteIP:   selectedPCSCF,
				},
				OutboundSPI:   secureCfg.OutboundSPI,
				InboundSPI:    secureCfg.InboundSPI,
				Encryption:    secureCfg.Encryption,
				EncryptionKey: secureCfg.EncryptionKey,
				Integrity:     secureCfg.Integrity,
				IntegrityKey:  secureCfg.IntegrityKey,
				Mode:          secureCfg.Mode,
				OutboundSalt:  secureCfg.OutboundSalt,
				InboundSalt:   secureCfg.InboundSalt,
				Associations:  associations,
			})
		}
	}
	return security
}

func (a *voWiFiAccess) openMedia(ctx context.Context, cfg imsvoice.MediaConfig) (imsvoice.MediaTransport, error) {
	return newNetstackMediaTransport(ctx, a.session, a.netstack, cfg)
}

func (a *voWiFiAccess) Close() error {
	var err error
	if a.netstack != nil {
		err = errors.Join(err, a.netstack.Close())
	}
	if a.session != nil {
		err = errors.Join(err, a.session.Close())
	}
	return err
}

func (a *voWiFiAccess) dialPCSCFTCP(ctx context.Context, pcscfIPs []net.IP) (*ipsectransport.NetstackTCPConn, net.IP, error) {
	candidates := pcscfIPs
	if len(candidates) == 0 {
		candidates = []net.IP{nil}
	}
	var errs error
	for _, ip := range candidates {
		tcpTransport, err := a.netstack.DialTCP(ctx, ipsectransport.TCPConfig{
			RemotePort: a.tunnelCfg.SIPPort,
			RemoteIP:   ip,
		})
		if err == nil {
			return tcpTransport, tcpRemoteIP(tcpTransport), nil
		}
		errs = errors.Join(errs, fmt.Errorf("dialing P-CSCF %s: %w", ipLabel(ip), err))
	}
	return nil, nil, errs
}

func (a *voWiFiAccess) dialPCSCFUDP(ctx context.Context, pcscfIPs []net.IP) (*ipsectransport.NetstackUDPConn, net.IP, error) {
	candidates := pcscfIPs
	if len(candidates) == 0 {
		candidates = []net.IP{nil}
	}
	var errs error
	for _, ip := range candidates {
		udpTransport, err := a.netstack.DialUDP(ctx, ipsectransport.UDPConfig{
			RemotePort: a.tunnelCfg.SIPPort,
			RemoteIP:   ip,
		})
		if err == nil {
			return udpTransport, udpRemoteIP(udpTransport), nil
		}
		errs = errors.Join(errs, fmt.Errorf("dialing P-CSCF %s: %w", ipLabel(ip), err))
	}
	return nil, nil, errs
}

func tcpRemoteIP(conn *ipsectransport.NetstackTCPConn) net.IP {
	remote := conn.RemoteAddr().(*net.TCPAddr)
	return append(net.IP(nil), remote.IP...)
}

func udpRemoteIP(conn *ipsectransport.NetstackUDPConn) net.IP {
	remote := conn.RemoteAddr().(*net.UDPAddr)
	return append(net.IP(nil), remote.IP...)
}
