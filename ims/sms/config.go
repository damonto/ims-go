package sms

import (
	"errors"
	"strings"
	"time"
)

func DefaultSubmitReportTimeout() time.Duration {
	return defaultSubmitReportTimeout
}

func DefaultDeliveryReportTimeout() time.Duration {
	return defaultTR2Timeout
}

func normalizeConfig(cfg Config) (Config, error) {
	cfg.ServiceCenter = strings.TrimSpace(cfg.ServiceCenter)
	if cfg.SubmitReportTimeout < 0 {
		return Config{}, errors.New("creating SMS endpoint: submit report timeout must be >= 0")
	}
	if cfg.DeliveryReportTimeout < 0 {
		return Config{}, errors.New("creating SMS endpoint: delivery report timeout must be >= 0")
	}
	if cfg.SubmitReportTimeout == 0 {
		cfg.SubmitReportTimeout = defaultSubmitReportTimeout
	}
	if cfg.DeliveryReportTimeout == 0 {
		cfg.DeliveryReportTimeout = DefaultDeliveryReportTimeout()
	}
	if cfg.SubmitReportTimeout <= 35*time.Second || cfg.SubmitReportTimeout >= 45*time.Second {
		return Config{}, errors.New("creating SMS endpoint: submit report timeout must be > 35s and < 45s")
	}
	if cfg.DeliveryReportTimeout <= 12*time.Second || cfg.DeliveryReportTimeout >= 20*time.Second {
		return Config{}, errors.New("creating SMS endpoint: delivery report timeout must be > 12s and < 20s")
	}
	return cfg, nil
}
