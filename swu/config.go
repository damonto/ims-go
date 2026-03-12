package swu

import (
	"fmt"
	"log/slog"
	"strings"
)

func (cfg Config) Normalized() (Config, error) {
	cfg.LocalAddr = strings.TrimSpace(cfg.LocalAddr)
	cfg.RemoteAddr = strings.TrimSpace(cfg.RemoteAddr)
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	if err := validatePortRange("initial port", cfg.InitialPort); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if cfg.NATTPort == 0 {
		cfg.NATTPort = 4500
	}
	if cfg.LocalSIPPort == 0 {
		cfg.LocalSIPPort = 5062
	}
	if cfg.SIPPort == 0 {
		cfg.SIPPort = 5060
	}
	if err := validatePortRange("natt port", cfg.NATTPort); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if err := validatePortRange("local sip port", cfg.LocalSIPPort); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if err := validatePortRange("sip port", cfg.SIPPort); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	return cfg, nil
}

func validatePortRange(name string, port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("%s must be between 0 and 65535", name)
	}
	return nil
}
