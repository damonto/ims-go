package ims

import (
	"context"
	"errors"
	"strings"

	imssession "github.com/damonto/ims-go/ims/session"
	imsvoice "github.com/damonto/ims-go/ims/voice"
	"github.com/damonto/ims-go/lte"
	swutunnel "github.com/damonto/ims-go/swu/tunnel"
)

const defaultSIPServerPort = 5060

type AccessConfig struct {
	VoWiFi *VoWiFiConfig
	VoLTE  *lte.Config
}

type VoWiFiConfig struct {
	EPDG     string
	Tunnel   swutunnel.Config
	Underlay Underlay
}

func VoWiFi(c VoWiFiConfig) AccessConfig {
	return AccessConfig{VoWiFi: &c}
}

func VoLTE(c lte.Config) AccessConfig {
	return AccessConfig{VoLTE: &c}
}

type accessSession interface {
	OpenIMS(ctx context.Context, c accessIMSConfig) (imsAccess, error)
	Close() error
}

type pcscfReselectingAccess interface {
	accessSession
	PCSCFCandidateCount() int
	SelectNextPCSCF() error
}

type accessIMSConfig struct {
	Transport     string
	SIPServerPort int
}

type imsAccess struct {
	AccessNetworkInfo string
	SIP               imssession.Transport
	OpenReliableSIP   func(context.Context) (imssession.Transport, error)
	Security          imsSecurity
	OpenMedia         func(context.Context, imsvoice.MediaConfig) (imsvoice.MediaTransport, error)
	WaitMediaReady    func(context.Context, imsvoice.MediaConfig) error
}

type imsSecurity struct {
	DialSecureTCP   func(context.Context, imssession.SecureTCPConfig) (imssession.Transport, error)
	DialSecureUDP   func(context.Context, imssession.SecureUDPConfig) (imssession.Transport, error)
	ListenSecureTCP func(context.Context, imssession.SecureTCPConfig) (imssession.Transport, error)
	ListenSecureUDP func(context.Context, imssession.SecureUDPConfig) (imssession.Transport, error)
}

func (c AccessConfig) normalized() (AccessConfig, error) {
	if c.VoWiFi != nil && c.VoLTE != nil {
		return AccessConfig{}, errors.New("normalizing access config: choose VoWiFi or VoLTE, not both")
	}
	if c.VoWiFi == nil && c.VoLTE == nil {
		return AccessConfig{}, errors.New("normalizing access config: choose VoWiFi or VoLTE")
	}
	if c.VoLTE != nil {
		volte, err := c.VoLTE.Normalized()
		if err != nil {
			return AccessConfig{}, err
		}
		return AccessConfig{VoLTE: &volte}, nil
	}
	wifi := *c.VoWiFi
	wifi.EPDG = strings.TrimSpace(wifi.EPDG)
	return AccessConfig{VoWiFi: &wifi}, nil
}

func (c Config) usesVoWiFi() bool {
	return c.Access.VoWiFi != nil
}

func (c Config) usesVoLTE() bool {
	return c.Access.VoLTE != nil
}
