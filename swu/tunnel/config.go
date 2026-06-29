package tunnel

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/damonto/vowifi-go/swu/handshake"
)

type Config struct {
	LocalAddr                        string
	RemoteAddr                       string
	APN                              string
	PDNType                          PDNType
	AKAPrimeNetworkName              string
	AllowAKAPrimeNetworkNameMismatch bool
	PacketConn                       net.PacketConn
	InitialPort                      int
	NATTPort                         int
	LocalSIPPort                     int
	SIPPort                          int
	DHGroups                         []uint16
	IKEEncryptionKeyLens             []uint16
	IKEIntegrity                     []uint16
	IKEPRF                           []uint16
	ChildEncryptionKeyLens           []uint16
	ChildIntegrity                   []uint16
	PCSCFIPv4ConfigAttribute         uint16
	PCSCFIPv6ConfigAttribute         uint16
	DisablePCSCFRestoration          bool
	PDUSessionID                     byte
	EnableIPMSIndication             bool
	NATKeepaliveInterval             time.Duration
	LivenessTimeout                  time.Duration
	IKERetransmitDelays              []time.Duration
	IKESALifetime                    time.Duration
	IKESARekeyMargin                 time.Duration
	IKESAByteLifetime                uint64
	IKESAByteRekeyMargin             uint64
	ChildSALifetime                  time.Duration
	ChildSARekeyMargin               time.Duration
	ChildSAByteLifetime              uint64
	ChildSAByteRekeyMargin           uint64
	AddKEToChildSARekey              bool
	Logger                           *slog.Logger
}

type IPAddress = handshake.IPAddress
type IPPrefix = handshake.IPPrefix
type PDNType = handshake.PDNType

const (
	PDNTypeUnspecified = handshake.PDNTypeUnspecified
	PDNTypeIPv4        = handshake.PDNTypeIPv4
	PDNTypeIPv6        = handshake.PDNTypeIPv6
	PDNTypeIPv4v6      = handshake.PDNTypeIPv4v6
)

var (
	defaultDHGroups          = []uint16{transformDH2048MODP}
	defaultEncryptionKeyLens = []uint16{transformKeyLenAES128, transformKeyLenAES256}
	defaultIKEIntegrity      = []uint16{transformINTEGHMACSHA256}
	defaultIKEPRF            = []uint16{transformPRFHMACSHA1, transformPRFHMACSHA256}
	defaultChildIntegrity    = []uint16{transformINTEGHMACSHA256}
)

const (
	DefaultAPN                   = "ims"
	defaultAKAPrimeNetworkName   = "WLAN"
	defaultIKEPort               = 500
	defaultNATTPort              = 4500
	defaultLocalSIPPort          = 5062
	defaultSIPPort               = 5060
	defaultNATKeepaliveInterval  = 20 * time.Second
	defaultLivenessTimeout       = 120 * time.Second
	defaultIKESARekeySoftTimer   = 7200 * time.Second
	defaultIKESARekeyHardTimer   = 14400 * time.Second
	defaultChildSARekeySoftTimer = 3600 * time.Second
	defaultChildSARekeyHardTimer = 7200 * time.Second
)

const (
	transformKeyLenAES128 uint16 = 128
	transformKeyLenAES192 uint16 = 192
	transformKeyLenAES256 uint16 = 256
)

func (cfg Config) Normalized() (Config, error) {
	cfg.LocalAddr = strings.TrimSpace(cfg.LocalAddr)
	cfg.RemoteAddr = strings.TrimSpace(cfg.RemoteAddr)
	cfg.APN = strings.TrimSpace(cfg.APN)
	cfg.AKAPrimeNetworkName = strings.TrimSpace(cfg.AKAPrimeNetworkName)
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.APN == "" {
		cfg.APN = DefaultAPN
	}
	if cfg.AKAPrimeNetworkName == "" {
		cfg.AKAPrimeNetworkName = defaultAKAPrimeNetworkName
	}
	if !validPDNType(cfg.PDNType) {
		return Config{}, fmt.Errorf("normalizing swu config: invalid pdn type %d", cfg.PDNType)
	}

	if err := validatePortRange("initial port", cfg.InitialPort); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if cfg.NATTPort == 0 {
		cfg.NATTPort = defaultNATTPort
	}
	if cfg.LocalSIPPort == 0 {
		cfg.LocalSIPPort = defaultLocalSIPPort
	}
	if cfg.SIPPort == 0 {
		cfg.SIPPort = defaultSIPPort
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
		cfg.NATKeepaliveInterval = defaultNATKeepaliveInterval
	}
	if cfg.NATKeepaliveInterval < 0 {
		return Config{}, errors.New("normalizing swu config: natt keepalive interval must be >= 0")
	}
	if cfg.LivenessTimeout < 0 {
		return Config{}, errors.New("normalizing swu config: liveness timeout must be >= 0")
	}
	if cfg.LivenessTimeout == 0 {
		cfg.LivenessTimeout = defaultLivenessTimeout
	}
	if len(cfg.IKERetransmitDelays) == 0 {
		cfg.IKERetransmitDelays = append([]time.Duration(nil), defaultIKERetransmitDelays...)
	} else {
		cfg.IKERetransmitDelays = append([]time.Duration(nil), cfg.IKERetransmitDelays...)
	}
	if err := validateRetransmitDelays("ike retransmit delays", cfg.IKERetransmitDelays); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if err := normalizeSALifetime("ike sa", &cfg.IKESALifetime, &cfg.IKESARekeyMargin, defaultIKESARekeyHardTimer, defaultIKESARekeyHardTimer-defaultIKESARekeySoftTimer); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if err := normalizeSAByteLifetime("ike sa", &cfg.IKESAByteLifetime, &cfg.IKESAByteRekeyMargin); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if err := normalizeSALifetime("child sa", &cfg.ChildSALifetime, &cfg.ChildSARekeyMargin, defaultChildSARekeyHardTimer, defaultChildSARekeyHardTimer-defaultChildSARekeySoftTimer); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if err := normalizeSAByteLifetime("child sa", &cfg.ChildSAByteLifetime, &cfg.ChildSAByteRekeyMargin); err != nil {
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

func handshakeConfig(cfg Config) handshake.Config {
	return handshake.Config{
		LocalAddr:                cfg.LocalAddr,
		RemoteAddr:               cfg.RemoteAddr,
		APN:                      cfg.APN,
		PDNType:                  cfg.PDNType,
		InitialPort:              cfg.InitialPort,
		NATTPort:                 cfg.NATTPort,
		LocalSIPPort:             cfg.LocalSIPPort,
		SIPPort:                  cfg.SIPPort,
		DHGroups:                 append([]uint16(nil), cfg.DHGroups...),
		IKEEncryptionKeyLens:     append([]uint16(nil), cfg.IKEEncryptionKeyLens...),
		IKEIntegrity:             append([]uint16(nil), cfg.IKEIntegrity...),
		IKEPRF:                   append([]uint16(nil), cfg.IKEPRF...),
		ChildEncryptionKeyLens:   append([]uint16(nil), cfg.ChildEncryptionKeyLens...),
		ChildIntegrity:           append([]uint16(nil), cfg.ChildIntegrity...),
		PCSCFIPv4ConfigAttribute: cfg.PCSCFIPv4ConfigAttribute,
		PCSCFIPv6ConfigAttribute: cfg.PCSCFIPv6ConfigAttribute,
		PCSCFRestoration:         !cfg.DisablePCSCFRestoration,
		PDUSessionID:             cfg.PDUSessionID,
		IPMSIndication:           cfg.EnableIPMSIndication,
		NATKeepaliveInterval:     cfg.NATKeepaliveInterval,
		LivenessTimeout:          cfg.LivenessTimeout,
		IKERetransmitDelays:      append([]time.Duration(nil), cfg.IKERetransmitDelays...),
	}
}

func validPDNType(pdnType PDNType) bool {
	switch pdnType {
	case PDNTypeUnspecified, PDNTypeIPv4, PDNTypeIPv6, PDNTypeIPv4v6:
		return true
	default:
		return false
	}
}

func normalizeSALifetime(name string, lifetime, rekeyMargin *time.Duration, defaultLifetime, defaultRekeyMargin time.Duration) error {
	if *lifetime < 0 {
		return fmt.Errorf("%s lifetime must be >= 0", name)
	}
	if *rekeyMargin < 0 {
		return fmt.Errorf("%s rekey margin must be >= 0", name)
	}
	if *lifetime == 0 {
		if *rekeyMargin != 0 {
			return fmt.Errorf("%s rekey margin requires %s lifetime", name, name)
		}
		*lifetime = defaultLifetime
		*rekeyMargin = defaultRekeyMargin
		return nil
	}
	if *rekeyMargin == 0 {
		*rekeyMargin = defaultSARekeyMargin(*lifetime)
	}
	if *rekeyMargin >= *lifetime {
		return fmt.Errorf("%s rekey margin must be shorter than %s lifetime", name, name)
	}
	return nil
}

func normalizeSAByteLifetime(name string, lifetime, rekeyMargin *uint64) error {
	if *lifetime == 0 && *rekeyMargin != 0 {
		return fmt.Errorf("%s byte rekey margin requires %s byte lifetime", name, name)
	}
	if *lifetime > 0 && *rekeyMargin == 0 {
		*rekeyMargin = defaultSAByteRekeyMargin(*lifetime)
	}
	if *lifetime > 0 && *rekeyMargin >= *lifetime {
		return fmt.Errorf("%s byte rekey margin must be shorter than %s byte lifetime", name, name)
	}
	return nil
}

func defaultSARekeyMargin(lifetime time.Duration) time.Duration {
	margin := lifetime / 10
	if margin > 5*time.Minute {
		return 5 * time.Minute
	}
	if margin <= 0 {
		return lifetime / 2
	}
	return margin
}

func defaultSAByteRekeyMargin(lifetime uint64) uint64 {
	margin := lifetime / 10
	if margin == 0 {
		return 1
	}
	return margin
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
		case transformKeyLenAES128, transformKeyLenAES192, transformKeyLenAES256:
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
	if len(delays) == 0 || len(delays) > 12 {
		return fmt.Errorf("%s must contain 1 to 12 entries", name)
	}
	for i, delay := range delays {
		if delay < 500*time.Millisecond || delay > 30*time.Minute {
			return fmt.Errorf("%s entry %s must be between 500ms and 30m", name, delay)
		}
		if i == 0 {
			continue
		}
		minDelay := delays[i-1] * 2
		if delay < minDelay {
			return fmt.Errorf("%s entry %s must be at least double previous entry %s", name, delay, delays[i-1])
		}
	}
	return nil
}
