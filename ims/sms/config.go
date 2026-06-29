package sms

import (
	"errors"
	"strings"
	"time"
)

func init() {
	setSubmitReportTimeout(defaultSubmitReportTimeout)
}

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
		cfg.SubmitReportTimeout = currentSubmitReportTimeout()
	}
	if cfg.DeliveryReportTimeout == 0 {
		cfg.DeliveryReportTimeout = DefaultDeliveryReportTimeout()
	}
	return cfg, nil
}

func currentSubmitReportTimeout() time.Duration {
	return time.Duration(submitReportTimeoutNanos.Load())
}

func setSubmitReportTimeout(timeout time.Duration) {
	submitReportTimeoutNanos.Store(int64(timeout))
}
