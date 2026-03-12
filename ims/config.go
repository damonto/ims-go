package ims

import (
	"fmt"
	"log/slog"
	"strings"
	"time"
)

func (cfg Config) Normalized() (Config, error) {
	cfg.ProxyAddr = strings.TrimSpace(cfg.ProxyAddr)
	cfg.Transport = strings.ToLower(strings.TrimSpace(cfg.Transport))
	cfg.PublicIdentity = strings.TrimSpace(cfg.PublicIdentity)
	cfg.HomeDomain = strings.TrimSpace(cfg.HomeDomain)
	cfg.Country = strings.TrimSpace(cfg.Country)
	cfg.USSDLanguage = strings.TrimSpace(cfg.USSDLanguage)
	cfg.UserAgent = strings.TrimSpace(cfg.UserAgent)
	cfg.AccessNetworkInfo = strings.TrimSpace(cfg.AccessNetworkInfo)
	cfg.WLANNodeID = strings.TrimSpace(cfg.WLANNodeID)
	cfg.SMSC = strings.TrimSpace(cfg.SMSC)
	cfg.IMEI = strings.TrimSpace(cfg.IMEI)
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	if cfg.Transport == "" {
		cfg.Transport = "udp"
	}
	switch cfg.Transport {
	case "udp", "tcp":
	default:
		return Config{}, fmt.Errorf("normalizing IMS config: unsupported transport %q", cfg.Transport)
	}
	if cfg.Country == "" {
		cfg.Country = "IE"
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "IMSClient/1.0 Linux"
	}
	if cfg.RegisterExpires < 0 {
		return Config{}, fmt.Errorf("normalizing IMS config: register expires must be >= 0")
	}
	if cfg.RegisterExpires == 0 {
		cfg.RegisterExpires = 10 * time.Minute
	}
	return cfg, nil
}
