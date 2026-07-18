package ims

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/damonto/ims-go/ims/registration"
	imssession "github.com/damonto/ims-go/ims/session"
	imssms "github.com/damonto/ims-go/ims/sms"
	imsussd "github.com/damonto/ims-go/ims/ussd"
	imsvoice "github.com/damonto/ims-go/ims/voice"
	swutunnel "github.com/damonto/ims-go/swu/tunnel"
)

func (c *Client) openIMS(ctx context.Context, setup *connectSetup) error {
	if setup.access == nil {
		return errors.New("opening IMS: access session is missing")
	}
	accessIMS, err := setup.access.OpenIMS(ctx, accessIMSConfig{
		Transport:     setup.imsCfg.Transport,
		SIPServerPort: setup.imsCfg.SIPServerPort,
	})
	if err != nil {
		return err
	}
	if accessIMS.SIP == nil {
		return errors.New("opening IMS: SIP transport is nil")
	}
	if setup.imsCfg.AccessNetworkInfo == "" && accessIMS.AccessNetworkInfo != "" {
		setup.imsCfg.AccessNetworkInfo = accessIMS.AccessNetworkInfo
	}

	imsSession, err := imssession.Open(imssession.Config{
		Transport:             setup.imsCfg.Transport,
		Logger:                c.cfg.Logger,
		TransactionTimers:     setup.imsCfg.SIPTimers,
		OpenReliableTransport: accessIMS.OpenReliableSIP,
	}, accessIMS.SIP)
	if err != nil {
		return fmt.Errorf("opening IMS session: %w", err)
	}
	setup.ims.sip = imsSession

	reg, err := registration.New(c.buildRegistrationConfig(setup.imsCfg, accessIMS.Security), imsSession, c.card)
	if err != nil {
		return fmt.Errorf("creating IMS registrar: %w", err)
	}
	setup.ims.reg = reg

	c.logger.Info("registering IMS")
	if err := reg.Establish(ctx); err != nil {
		return fmt.Errorf("establishing IMS registration: %w", err)
	}
	if err := reg.Subscribe(ctx); err != nil {
		return err
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
	voiceCfg.PhoneContextDomain = setup.imsCfg.PhoneContextDomain
	if voiceCfg.PrepareMedia == nil {
		voiceCfg.PrepareMedia = accessIMS.OpenMedia
	}
	if voiceCfg.OpenMedia == nil {
		voiceCfg.OpenMedia = accessIMS.OpenMedia
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

func pcscfCandidateIPs(info swutunnel.Info) []net.IP {
	return uniqueIPs(info.PCSCFAddresses())
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

func (c *Client) buildRegistrationConfig(cfg IMSConfig, security imsSecurity) registration.Config {
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
		DialSecureTCP:           security.DialSecureTCP,
		DialSecureUDP:           security.DialSecureUDP,
		ListenSecureTCP:         security.ListenSecureTCP,
		ListenSecureUDP:         security.ListenSecureUDP,
	}
}
