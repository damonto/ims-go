package ims

import (
	"context"
	"fmt"
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
	EPDG   string
	Tunnel swutunnel.Config
}

func VoWiFi(cfg VoWiFiConfig) AccessConfig {
	return AccessConfig{VoWiFi: &cfg}
}

func VoLTE(cfg lte.Config) AccessConfig {
	return AccessConfig{VoLTE: &cfg}
}

type accessSession interface {
	OpenIMS(ctx context.Context, cfg accessIMSConfig) (imsAccess, error)
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
	Security          imsSecurity
	OpenMedia         func(context.Context, imsvoice.MediaConfig) (imsvoice.MediaTransport, error)
}

type imsSecurity struct {
	DialSecureTCP   func(context.Context, imssession.SecureTCPConfig) (imssession.Transport, error)
	DialSecureUDP   func(context.Context, imssession.SecureUDPConfig) (imssession.Transport, error)
	ListenSecureTCP func(context.Context, imssession.SecureTCPConfig) (imssession.Transport, error)
	ListenSecureUDP func(context.Context, imssession.SecureUDPConfig) (imssession.Transport, error)
}

func (cfg AccessConfig) normalized() (AccessConfig, error) {
	if cfg.VoWiFi != nil && cfg.VoLTE != nil {
		return AccessConfig{}, fmt.Errorf("normalizing access config: choose VoWiFi or VoLTE, not both")
	}
	if cfg.VoWiFi == nil && cfg.VoLTE == nil {
		return AccessConfig{}, fmt.Errorf("normalizing access config: choose VoWiFi or VoLTE")
	}
	if cfg.VoLTE != nil {
		volte, err := cfg.VoLTE.Normalized()
		if err != nil {
			return AccessConfig{}, err
		}
		return AccessConfig{VoLTE: &volte}, nil
	}
	wifi := *cfg.VoWiFi
	wifi.EPDG = strings.TrimSpace(wifi.EPDG)
	return AccessConfig{VoWiFi: &wifi}, nil
}

func (cfg Config) usesVoWiFi() bool {
	return cfg.Access.VoWiFi != nil
}

func (cfg Config) usesVoLTE() bool {
	return cfg.Access.VoLTE != nil
}
