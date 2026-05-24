package tunnel

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

var (
	defaultDHGroups          = []uint16{transformDH2048MODP}
	defaultEncryptionKeyLens = []uint16{128, 256}
	defaultIKEIntegrity      = []uint16{transformINTEGHMACSHA256}
	defaultIKEPRF            = []uint16{transformPRFHMACSHA1, transformPRFHMACSHA256}
	defaultChildIntegrity    = []uint16{transformINTEGHMACSHA256}
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
	if len(cfg.DHGroups) == 0 {
		cfg.DHGroups = append([]uint16(nil), defaultDHGroups...)
	} else {
		cfg.DHGroups = append([]uint16(nil), cfg.DHGroups...)
	}
	for _, group := range cfg.DHGroups {
		if err := validateDHGroup(group); err != nil {
			return Config{}, fmt.Errorf("normalizing swu config: %w", err)
		}
	}
	if len(cfg.IKEEncryptionKeyLens) == 0 {
		cfg.IKEEncryptionKeyLens = append([]uint16(nil), defaultEncryptionKeyLens...)
	} else {
		cfg.IKEEncryptionKeyLens = append([]uint16(nil), cfg.IKEEncryptionKeyLens...)
	}
	if err := validateEncryptionKeyLens("ike encryption key lengths", cfg.IKEEncryptionKeyLens); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if len(cfg.IKEIntegrity) == 0 {
		cfg.IKEIntegrity = append([]uint16(nil), defaultIKEIntegrity...)
	} else {
		cfg.IKEIntegrity = append([]uint16(nil), cfg.IKEIntegrity...)
	}
	if err := validateIntegrityTransforms("ike integrity transforms", cfg.IKEIntegrity); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if len(cfg.IKEPRF) == 0 {
		cfg.IKEPRF = append([]uint16(nil), defaultIKEPRF...)
	} else {
		cfg.IKEPRF = append([]uint16(nil), cfg.IKEPRF...)
	}
	if err := validatePRFTransforms("ike prf transforms", cfg.IKEPRF); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if len(cfg.ChildEncryptionKeyLens) == 0 {
		cfg.ChildEncryptionKeyLens = append([]uint16(nil), defaultEncryptionKeyLens...)
	} else {
		cfg.ChildEncryptionKeyLens = append([]uint16(nil), cfg.ChildEncryptionKeyLens...)
	}
	if err := validateEncryptionKeyLens("child encryption key lengths", cfg.ChildEncryptionKeyLens); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if len(cfg.ChildIntegrity) == 0 {
		cfg.ChildIntegrity = append([]uint16(nil), defaultChildIntegrity...)
	} else {
		cfg.ChildIntegrity = append([]uint16(nil), cfg.ChildIntegrity...)
	}
	if err := validateIntegrityTransforms("child integrity transforms", cfg.ChildIntegrity); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if cfg.PCSCFIPv4ConfigAttribute == 0 {
		cfg.PCSCFIPv4ConfigAttribute = configAttrPCSCFIPv4Address
	}
	if cfg.PCSCFIPv6ConfigAttribute == 0 {
		cfg.PCSCFIPv6ConfigAttribute = configAttrPCSCFIPv6Address
	}
	if cfg.NATKeepaliveInterval == 0 {
		cfg.NATKeepaliveInterval = 20 * time.Second
	}
	if cfg.NATKeepaliveInterval < 0 {
		return Config{}, errors.New("normalizing swu config: natt keepalive interval must be >= 0")
	}
	if len(cfg.IKERetransmitDelays) == 0 {
		cfg.IKERetransmitDelays = append([]time.Duration(nil), defaultIKERetransmitDelays...)
	} else {
		cfg.IKERetransmitDelays = append([]time.Duration(nil), cfg.IKERetransmitDelays...)
	}
	if err := validateRetransmitDelays("ike retransmit delays", cfg.IKERetransmitDelays); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
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

func validateDHGroup(group uint16) error {
	switch group {
	case transformDH1024MODP, transformDH2048MODP:
		return nil
	default:
		return fmt.Errorf("dh group %d is unsupported", group)
	}
}

func validateEncryptionKeyLens(name string, values []uint16) error {
	if len(values) == 0 {
		return fmt.Errorf("%s must not be empty", name)
	}
	for _, value := range values {
		switch value {
		case 128, 192, 256:
		default:
			return fmt.Errorf("%s value %d is unsupported", name, value)
		}
	}
	return nil
}

func validateIntegrityTransforms(name string, values []uint16) error {
	if len(values) == 0 {
		return fmt.Errorf("%s must not be empty", name)
	}
	for _, value := range values {
		switch value {
		case transformINTEGHMACMD596, transformINTEGHMACSHA196, transformINTEGHMACSHA256:
		default:
			return fmt.Errorf("%s value %d is unsupported", name, value)
		}
	}
	return nil
}

func validatePRFTransforms(name string, values []uint16) error {
	if len(values) == 0 {
		return fmt.Errorf("%s must not be empty", name)
	}
	for _, value := range values {
		switch value {
		case transformPRFHMACMD5, transformPRFHMACSHA1, transformPRFHMACSHA256:
		default:
			return fmt.Errorf("%s value %d is unsupported", name, value)
		}
	}
	return nil
}

func validateRetransmitDelays(name string, delays []time.Duration) error {
	if len(delays) == 0 || len(delays) > 10 {
		return fmt.Errorf("%s must contain 1 to 10 entries", name)
	}
	for _, delay := range delays {
		if delay < 500*time.Millisecond || delay > 30*time.Minute {
			return fmt.Errorf("%s entry %s must be between 500ms and 30m", name, delay)
		}
	}
	return nil
}
