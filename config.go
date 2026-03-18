package imsclient

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/damonto/ims-client/swu/tunnel"
)

func cloneConfig(cfg *Config) Config {
	if cfg == nil {
		return Config{}
	}
	return *cfg
}

func (cfg Config) normalized(card Card) (Config, error) {
	cfg = cfg.trimmed()

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}

	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ReconnectDelay == 0 {
		cfg.ReconnectDelay = defaultReconnectDelay
	}

	if cfg.IMEI == "" {
		return Config{}, errors.New("normalizing client config: imei is empty")
	}
	if cfg.EPDG == "" {
		epdg, err := defaultEPDGAddress(card)
		if err != nil {
			return Config{}, err
		}
		cfg.EPDG = epdg
	}

	tunnelCfg, err := cfg.normalizedTunnel()
	if err != nil {
		return Config{}, err
	}
	cfg.Tunnel = tunnelCfg

	imsCfg, err := cfg.normalizedIMS()
	if err != nil {
		return Config{}, err
	}
	cfg.IMS = imsCfg

	return cfg, nil
}

func (cfg Config) trimmed() Config {
	cfg.IMEI = strings.TrimSpace(cfg.IMEI)
	cfg.EPDG = strings.TrimSpace(cfg.EPDG)
	return cfg
}

func (cfg Config) validate() error {
	if cfg.ReconnectDelay < 0 {
		return errors.New("normalizing client config: reconnect delay must be >= 0")
	}
	return nil
}

func (cfg Config) normalizedTunnel() (tunnel.Config, error) {
	tunnelCfg := cfg.Tunnel
	if tunnelCfg.Logger == nil {
		tunnelCfg.Logger = cfg.Logger
	}
	normalized, err := tunnelCfg.Normalized()
	if err != nil {
		return tunnel.Config{}, fmt.Errorf("normalizing tunnel config: %w", err)
	}
	return normalized, nil
}

func (cfg Config) normalizedIMS() (IMSConfig, error) {
	imsCfg := cfg.IMS
	if imsCfg.IMEI == "" {
		imsCfg.IMEI = cfg.IMEI
	}
	// Over ePDG/SWu we default to TCP for SIP, matching the pre-refactor
	// behavior and avoiding large initial REGISTER requests over UDP.
	if strings.TrimSpace(imsCfg.Transport) == "" && strings.TrimSpace(cfg.EPDG) != "" {
		imsCfg.Transport = "tcp"
	}
	normalized, err := imsCfg.Normalized()
	if err != nil {
		return IMSConfig{}, fmt.Errorf("normalizing ims config: %w", err)
	}
	return normalized, nil
}

func (cfg IMSConfig) Normalized() (IMSConfig, error) {
	cfg.Transport = strings.ToLower(strings.TrimSpace(cfg.Transport))
	cfg.PublicIdentity = strings.TrimSpace(cfg.PublicIdentity)
	cfg.HomeDomain = strings.TrimSpace(cfg.HomeDomain)
	cfg.Region = strings.TrimSpace(cfg.Region)
	cfg.USSDLanguage = strings.TrimSpace(cfg.USSDLanguage)
	cfg.UserAgent = strings.TrimSpace(cfg.UserAgent)
	cfg.AccessNetworkInfo = strings.TrimSpace(cfg.AccessNetworkInfo)
	cfg.WLANNodeID = strings.TrimSpace(cfg.WLANNodeID)
	cfg.ServiceCenter = strings.TrimSpace(cfg.ServiceCenter)
	cfg.IMEI = strings.TrimSpace(cfg.IMEI)

	if cfg.Transport == "" {
		cfg.Transport = "udp"
	}
	switch cfg.Transport {
	case "udp", "tcp":
	default:
		return IMSConfig{}, fmt.Errorf("normalizing ims config: unsupported transport %q", cfg.Transport)
	}
	if cfg.Region == "" {
		cfg.Region = "US"
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = defaultUserAgent()
	}
	if cfg.RegisterExpires < 0 {
		return IMSConfig{}, errors.New("normalizing ims config: register expires must be >= 0")
	}
	if cfg.RegisterExpires == 0 {
		cfg.RegisterExpires = 10 * time.Minute
	}
	return cfg, nil
}

func defaultEPDGAddress(card Card) (string, error) {
	if card == nil {
		return "", errors.New("normalizing client config: card is nil")
	}

	mcc := strings.TrimSpace(card.MCC())
	if len(mcc) != 3 {
		return "", fmt.Errorf("normalizing client config: mcc %q must be 3 digits", mcc)
	}

	mnc := strings.TrimSpace(card.MNC())
	switch len(mnc) {
	case 2:
		mnc = "0" + mnc
	case 3:
	default:
		return "", fmt.Errorf("normalizing client config: mnc %q must be 2 or 3 digits", mnc)
	}

	return fmt.Sprintf("epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org", mnc, mcc), nil
}
