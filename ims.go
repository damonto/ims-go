package vowifi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/damonto/vowifi-go/ims/registration"
	imssession "github.com/damonto/vowifi-go/ims/session"
	imssms "github.com/damonto/vowifi-go/ims/sms"
	imsussd "github.com/damonto/vowifi-go/ims/ussd"
	imsvoice "github.com/damonto/vowifi-go/ims/voice"
	swutransport "github.com/damonto/vowifi-go/swu/transport"
	swutunnel "github.com/damonto/vowifi-go/swu/tunnel"
)

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

func (c *Client) openIMS(ctx context.Context, setup *connectSetup, tunnelInfo swutunnel.Info) error {
	transport, err := c.buildIMSTransport(ctx, setup, tunnelInfo)
	if err != nil {
		return err
	}

	imsSession, err := imssession.Open(imssession.Config{
		Transport:         setup.imsCfg.Transport,
		Logger:            c.cfg.Logger,
		TransactionTimers: setup.imsCfg.SIPTimers,
	}, transport)
	if err != nil {
		return fmt.Errorf("opening IMS session: %w", err)
	}
	setup.ims.sip = imsSession

	reg, err := registration.New(c.buildRegistrationConfig(setup.imsCfg), imsSession, c.card)
	if err != nil {
		return fmt.Errorf("creating IMS registrar: %w", err)
	}
	setup.ims.reg = reg

	c.logger.Info("registering IMS")
	if err := reg.Establish(ctx); err != nil {
		return fmt.Errorf("establishing IMS registration: %w", err)
	}
	if err := reg.Subscribe(ctx); err != nil {
		return fmt.Errorf("subscribing IMS registration: %w", err)
	}

	sms, err := imssms.New(imssms.Config{
		ServiceCenter:         setup.imsCfg.ServiceCenter,
		DeliveryReportTimeout: setup.imsCfg.SMSDeliveryReportTimeout,
		RequestStatusReport:   c.cfg.smsRequestStatusReport,
		OnIncoming:            c.handleSMS,
		OnStatusReport:        c.handleSMSStatusReport,
		OnError:               c.emitError,
		Logger:                c.cfg.Logger,
	}, imsSession, reg, c.card)
	if err != nil {
		return fmt.Errorf("creating SMS endpoint: %w", err)
	}
	setup.ims.sms = sms

	ussd, err := imsussd.New(imsussd.Config{
		Language:           setup.imsCfg.USSDLanguage,
		PhoneContextDomain: setup.imsCfg.PhoneContextDomain,
		Domain:             imsussd.Domain(setup.imsCfg.USSDDomain),
		OnIncoming:         c.handleUSSD,
		Logger:             c.cfg.Logger,
	}, imsSession, reg)
	if err != nil {
		return fmt.Errorf("creating USSD endpoint: %w", err)
	}
	setup.ims.ussd = ussd

	voiceCfg := setup.imsCfg.Voice
	if voiceCfg.PrepareMedia == nil {
		voiceCfg.PrepareMedia = openMediaTransport(setup.tunnel)
	}
	if voiceCfg.OpenMedia == nil {
		voiceCfg.OpenMedia = openMediaTransport(setup.tunnel)
	}
	voiceCfg.OnIncomingCall = c.handleIncomingVoice
	voiceCfg.OnCallEvent = c.handleVoiceEvent
	voiceCfg.OnError = c.emitError
	voiceCfg.Logger = c.cfg.Logger
	voice, err := imsvoice.New(voiceCfg, imsSession, reg)
	if err != nil {
		return fmt.Errorf("creating voice endpoint: %w", err)
	}
	setup.ims.voice = voice
	return nil
}

func (c *Client) buildIMSTransport(ctx context.Context, setup *connectSetup, tunnelInfo swutunnel.Info) (imssession.Transport, error) {
	setup.imsCfg.dialSecureTCP = nil
	setup.imsCfg.dialSecureUDP = nil
	setup.imsCfg.listenSecureTCP = nil
	setup.imsCfg.listenSecureUDP = nil

	pcscfIPs := pcscfCandidateIPs(tunnelInfo)
	selectedPCSCF := firstPCSCFIP(pcscfIPs)
	associations := swutransport.NewSecurityAssociations()
	var transport imssession.Transport = tunnelDatagramTransport{session: setup.tunnel}
	setup.imsCfg.dialSecureUDP = func(ctx context.Context, cfg imssession.SecureUDPConfig) (imssession.Transport, error) {
		return swutransport.DialSecureUDP(ctx, setup.tunnel, swutransport.SecureUDPConfig{
			UDPConfig: swutransport.UDPConfig{
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
	}
	setup.imsCfg.listenSecureUDP = func(ctx context.Context, cfg imssession.SecureUDPConfig) (imssession.Transport, error) {
		_ = ctx
		return swutransport.ListenSecureUDP(setup.tunnel, swutransport.SecureUDPConfig{
			UDPConfig: swutransport.UDPConfig{
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
	}
	if setup.imsCfg.Transport != "tcp" {
		return transport, nil
	}

	tcpTransport, selectedIP, err := c.dialPCSCFTCP(ctx, setup, pcscfIPs)
	if err != nil {
		return nil, fmt.Errorf("dialing ims tcp transport: %w", err)
	}
	transport = tcpTransport
	selectedPCSCF = selectedIP
	setup.imsCfg.dialSecureTCP = func(ctx context.Context, cfg imssession.SecureTCPConfig) (imssession.Transport, error) {
		return swutransport.DialSecureTCP(ctx, setup.tunnel, swutransport.SecureTCPConfig{
			TCPConfig: swutransport.TCPConfig{
				LocalPort:       cfg.LocalPort,
				RemotePort:      cfg.RemotePort,
				RemoteIP:        selectedPCSCF,
				DataACKTimeouts: configuredTCPDataACKTimeouts(cfg.DataACKTimeouts, setup.imsCfg.TCPDataACKTimeouts),
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
	}
	setup.imsCfg.listenSecureTCP = func(ctx context.Context, cfg imssession.SecureTCPConfig) (imssession.Transport, error) {
		_ = ctx
		return swutransport.ListenSecureTCP(setup.tunnel, swutransport.SecureTCPConfig{
			TCPConfig: swutransport.TCPConfig{
				LocalPort:       cfg.LocalPort,
				RemotePort:      cfg.RemotePort,
				RemoteIP:        selectedPCSCF,
				DataACKTimeouts: configuredTCPDataACKTimeouts(cfg.DataACKTimeouts, setup.imsCfg.TCPDataACKTimeouts),
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
	}
	return transport, nil
}

func (c *Client) dialPCSCFTCP(ctx context.Context, setup *connectSetup, pcscfIPs []net.IP) (*swutransport.TCPConn, net.IP, error) {
	candidates := pcscfIPs
	if len(candidates) == 0 {
		candidates = []net.IP{nil}
	}
	var errs error
	for _, ip := range candidates {
		tcpTransport, err := swutransport.DialTCP(ctx, setup.tunnel, swutransport.TCPConfig{
			RemotePort:      setup.tunnelCfg.SIPPort,
			RemoteIP:        ip,
			DataACKTimeouts: setup.imsCfg.TCPDataACKTimeouts,
		})
		if err == nil {
			return tcpTransport, tcpRemoteIP(tcpTransport), nil
		}
		errs = errors.Join(errs, fmt.Errorf("dialing P-CSCF %s: %w", ipLabel(ip), err))
	}
	return nil, nil, errs
}

func pcscfCandidateIPs(info swutunnel.Info) []net.IP {
	return uniqueIPs(info.PCSCFAddresses())
}

func firstPCSCFIP(ips []net.IP) net.IP {
	if len(ips) == 0 {
		return nil
	}
	return append(net.IP(nil), ips[0]...)
}

func tcpRemoteIP(conn *swutransport.TCPConn) net.IP {
	remote := conn.RemoteAddr().(*net.TCPAddr)
	return append(net.IP(nil), remote.IP...)
}

func configuredTCPDataACKTimeouts(primary, fallback []time.Duration) []time.Duration {
	if len(primary) > 0 {
		return append([]time.Duration(nil), primary...)
	}
	return append([]time.Duration(nil), fallback...)
}

func uniqueIPs(ips []net.IP) []net.IP {
	unique := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if len(ip) == 0 {
			continue
		}
		seen := false
		for _, existing := range unique {
			if existing.Equal(ip) {
				seen = true
				break
			}
		}
		if !seen {
			unique = append(unique, append(net.IP(nil), ip...))
		}
	}
	return unique
}

func ipLabel(ip net.IP) string {
	if len(ip) == 0 {
		return "default"
	}
	return ip.String()
}

func (c *Client) buildRegistrationConfig(cfg IMSConfig) registration.Config {
	return registration.Config{
		PrivateIdentity:         cfg.PrivateIdentity,
		PublicIdentity:          cfg.PublicIdentity,
		HomeDomain:              cfg.HomeDomain,
		UserAgent:               cfg.UserAgent,
		AccessNetworkInfo:       cfg.AccessNetworkInfo,
		WLANNodeID:              cfg.WLANNodeID,
		RegisterExpires:         cfg.RegisterExpires,
		IMEI:                    cfg.IMEI,
		AuthAlgorithm:           cfg.AuthAlgorithm,
		GeolocationPIDFRegister: cfg.GeolocationPIDFRegister,
		GeolocationCountry:      cfg.GeolocationCountry,
		UseTelURIForPIDFXML:     cfg.UseTelURIForPIDFXML,
		Logger:                  c.cfg.Logger,
		DialSecureTCP:           cfg.dialSecureTCP,
		DialSecureUDP:           cfg.dialSecureUDP,
		ListenSecureTCP:         cfg.listenSecureTCP,
		ListenSecureUDP:         cfg.listenSecureUDP,
	}
}
