package imsclient

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/damonto/ims-client/ims"
	"github.com/damonto/ims-client/swu"
)

func (cfg Config) normalized() (Config, error) {
	cfg = cfg.trimmed()

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}

	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
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
	cfg.EPDGAddress = strings.TrimSpace(cfg.EPDGAddress)
	cfg.PCSCFAddress = strings.TrimSpace(cfg.PCSCFAddress)
	cfg.UserAgent = strings.TrimSpace(cfg.UserAgent)
	return cfg
}

func (cfg Config) validate() error {
	if cfg.RegisterExpires < 0 {
		return fmt.Errorf("normalizing client config: register expires must be >= 0")
	}
	return nil
}

func (cfg Config) normalizedTunnel() (swu.Config, error) {
	tunnelCfg := cfg.Tunnel
	if tunnelCfg.Logger == nil {
		tunnelCfg.Logger = cfg.Logger
	}
	normalized, err := tunnelCfg.Normalized()
	if err != nil {
		return swu.Config{}, fmt.Errorf("normalizing tunnel config: %w", err)
	}
	return normalized, nil
}

func (cfg Config) normalizedIMS() (ims.Config, error) {
	imsCfg := cfg.IMS
	if imsCfg.Logger == nil {
		imsCfg.Logger = cfg.Logger
	}
	if imsCfg.ProxyAddr == "" {
		imsCfg.ProxyAddr = cfg.PCSCFAddress
	}
	if imsCfg.UserAgent == "" {
		imsCfg.UserAgent = cfg.UserAgent
	}
	if imsCfg.IMEI == "" {
		imsCfg.IMEI = cfg.IMEI
	}
	if imsCfg.RegisterExpires == 0 {
		imsCfg.RegisterExpires = cfg.RegisterExpires
	}
	normalized, err := imsCfg.Normalized()
	if err != nil {
		return ims.Config{}, fmt.Errorf("normalizing ims config: %w", err)
	}
	return normalized, nil
}
