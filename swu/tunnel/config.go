package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/damonto/ims-go/swu/handshake"
)

type Config struct {
	LocalAddr  string
	RemoteAddr string
	// ListenPacket creates the outer IKE/NAT-T socket. PacketConn takes
	// precedence when supplied and remains available for tests and callers
	// that own a socket themselves.
	ListenPacket func(context.Context, string, string) (net.PacketConn, error)
	APN          string
	// RequestDefaultAPN omits IDr so the ePDG selects the default APN.
	// APN must be empty when this option is enabled.
	RequestDefaultAPN                bool
	PDNType                          handshake.PDNType
	AKAPrimeNetworkName              string
	AllowAKAPrimeNetworkNameMismatch bool
	PacketConn                       net.PacketConn
	InitialPort                      int
	NATTPort                         int
	SIPPort                          int
	DHGroups                         []uint16
	IKEEncryption                    []uint16
	IKEEncryptionKeyLens             []uint16
	IKEEncryptionAESCTRKeyLens       []uint16
	IKEIntegrity                     []uint16
	IKEPRF                           []uint16
	ChildEncryption                  []uint16
	ChildEncryptionKeyLens           []uint16
	ChildEncryptionAESCTRKeyLens     []uint16
	ChildIntegrity                   []uint16
	ChildSAMultipleProposals         bool
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

const (
	PDNTypeUnspecified = handshake.PDNTypeUnspecified
	PDNTypeIPv4        = handshake.PDNTypeIPv4
	PDNTypeIPv6        = handshake.PDNTypeIPv6
	PDNTypeIPv4v6      = handshake.PDNTypeIPv4v6
)

var (
	defaultDHGroups          = []uint16{transformDH2048MODP}
	defaultEncryption        = []uint16{transformENCRAESCBC}
	defaultEncryptionKeyLens = []uint16{transformKeyLenAES128, transformKeyLenAES256}
	defaultIKEIntegrity      = []uint16{transformINTEGHMACSHA256}
	defaultIKEPRF            = []uint16{transformPRFHMACSHA1, transformPRFHMACSHA256}
	defaultChildIntegrity    = []uint16{transformINTEGHMACSHA256}
)

const (
	DefaultIKEPort               = 500
	DefaultAPN                   = "ims"
	defaultAKAPrimeNetworkName   = "WLAN"
	defaultIKEPort               = DefaultIKEPort
	defaultNATTPort              = 4500
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

func (c Config) Normalized() (Config, error) {
	c.LocalAddr = strings.TrimSpace(c.LocalAddr)
	c.RemoteAddr = strings.TrimSpace(c.RemoteAddr)
	c.APN = strings.TrimSpace(c.APN)
	c.AKAPrimeNetworkName = strings.TrimSpace(c.AKAPrimeNetworkName)
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.RequestDefaultAPN && c.APN != "" {
		return Config{}, errors.New("normalizing swu config: apn must be empty when requesting the default apn")
	}
	if !c.RequestDefaultAPN && c.APN == "" {
		c.APN = DefaultAPN
	}
	if c.AKAPrimeNetworkName == "" {
		c.AKAPrimeNetworkName = defaultAKAPrimeNetworkName
	}
	if !validPDNType(c.PDNType) {
		return Config{}, fmt.Errorf("normalizing swu config: invalid pdn type %d", c.PDNType)
	}

	if err := validatePortRange("initial port", c.InitialPort); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if c.NATTPort == 0 {
		c.NATTPort = defaultNATTPort
	}
	if c.SIPPort == 0 {
		c.SIPPort = defaultSIPPort
	}
	if len(c.DHGroups) == 0 {
		c.DHGroups = append([]uint16(nil), defaultDHGroups...)
	} else {
		c.DHGroups = append([]uint16(nil), c.DHGroups...)
	}
	for _, group := range c.DHGroups {
		if err := validateDHGroup(group); err != nil {
			return Config{}, fmt.Errorf("normalizing swu config: %w", err)
		}
	}
	if len(c.IKEEncryption) == 0 {
		c.IKEEncryption = append([]uint16(nil), defaultEncryption...)
	} else {
		c.IKEEncryption = append([]uint16(nil), c.IKEEncryption...)
	}
	if err := validateEncryptionTransforms("ike encryption transforms", c.IKEEncryption); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if len(c.IKEEncryptionKeyLens) == 0 {
		c.IKEEncryptionKeyLens = append([]uint16(nil), defaultEncryptionKeyLens...)
	} else {
		c.IKEEncryptionKeyLens = append([]uint16(nil), c.IKEEncryptionKeyLens...)
	}
	if err := validateEncryptionKeyLens("ike encryption key lengths", c.IKEEncryptionKeyLens); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if len(c.IKEEncryptionAESCTRKeyLens) == 0 {
		c.IKEEncryptionAESCTRKeyLens = append([]uint16(nil), defaultEncryptionKeyLens...)
	} else {
		c.IKEEncryptionAESCTRKeyLens = append([]uint16(nil), c.IKEEncryptionAESCTRKeyLens...)
	}
	if err := validateEncryptionKeyLens("ike AES-CTR key lengths", c.IKEEncryptionAESCTRKeyLens); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if len(c.IKEIntegrity) == 0 {
		c.IKEIntegrity = append([]uint16(nil), defaultIKEIntegrity...)
	} else {
		c.IKEIntegrity = append([]uint16(nil), c.IKEIntegrity...)
	}
	if err := validateIntegrityTransforms("ike integrity transforms", c.IKEIntegrity); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if len(c.IKEPRF) == 0 {
		c.IKEPRF = append([]uint16(nil), defaultIKEPRF...)
	} else {
		c.IKEPRF = append([]uint16(nil), c.IKEPRF...)
	}
	if err := validatePRFTransforms("ike prf transforms", c.IKEPRF); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if len(c.ChildEncryption) == 0 {
		c.ChildEncryption = append([]uint16(nil), defaultEncryption...)
	} else {
		c.ChildEncryption = append([]uint16(nil), c.ChildEncryption...)
	}
	if err := validateEncryptionTransforms("child encryption transforms", c.ChildEncryption); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if len(c.ChildEncryptionKeyLens) == 0 {
		c.ChildEncryptionKeyLens = append([]uint16(nil), defaultEncryptionKeyLens...)
	} else {
		c.ChildEncryptionKeyLens = append([]uint16(nil), c.ChildEncryptionKeyLens...)
	}
	if err := validateEncryptionKeyLens("child encryption key lengths", c.ChildEncryptionKeyLens); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if len(c.ChildEncryptionAESCTRKeyLens) == 0 {
		c.ChildEncryptionAESCTRKeyLens = append([]uint16(nil), defaultEncryptionKeyLens...)
	} else {
		c.ChildEncryptionAESCTRKeyLens = append([]uint16(nil), c.ChildEncryptionAESCTRKeyLens...)
	}
	if err := validateEncryptionKeyLens("child AES-CTR key lengths", c.ChildEncryptionAESCTRKeyLens); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if len(c.ChildIntegrity) == 0 {
		c.ChildIntegrity = append([]uint16(nil), defaultChildIntegrity...)
	} else {
		c.ChildIntegrity = append([]uint16(nil), c.ChildIntegrity...)
	}
	if err := validateIntegrityTransforms("child integrity transforms", c.ChildIntegrity); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if c.PCSCFIPv4ConfigAttribute == 0 {
		c.PCSCFIPv4ConfigAttribute = configAttrPCSCFIPv4Address
	}
	if c.PCSCFIPv6ConfigAttribute == 0 {
		c.PCSCFIPv6ConfigAttribute = configAttrPCSCFIPv6Address
	}
	if c.NATKeepaliveInterval == 0 {
		c.NATKeepaliveInterval = defaultNATKeepaliveInterval
	}
	if c.NATKeepaliveInterval < 0 {
		return Config{}, errors.New("normalizing swu config: natt keepalive interval must be >= 0")
	}
	if c.LivenessTimeout < 0 {
		return Config{}, errors.New("normalizing swu config: liveness timeout must be >= 0")
	}
	if c.LivenessTimeout == 0 {
		c.LivenessTimeout = defaultLivenessTimeout
	}
	if len(c.IKERetransmitDelays) == 0 {
		c.IKERetransmitDelays = append([]time.Duration(nil), defaultIKERetransmitDelays...)
	} else {
		c.IKERetransmitDelays = append([]time.Duration(nil), c.IKERetransmitDelays...)
	}
	if err := validateRetransmitDelays("ike retransmit delays", c.IKERetransmitDelays); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if err := normalizeSALifetime("ike sa", &c.IKESALifetime, &c.IKESARekeyMargin, defaultIKESARekeyHardTimer, defaultIKESARekeyHardTimer-defaultIKESARekeySoftTimer); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if err := normalizeSAByteLifetime("ike sa", &c.IKESAByteLifetime, &c.IKESAByteRekeyMargin); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if err := normalizeSALifetime("child sa", &c.ChildSALifetime, &c.ChildSARekeyMargin, defaultChildSARekeyHardTimer, defaultChildSARekeyHardTimer-defaultChildSARekeySoftTimer); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if err := normalizeSAByteLifetime("child sa", &c.ChildSAByteLifetime, &c.ChildSAByteRekeyMargin); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if err := validatePortRange("natt port", c.NATTPort); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	if err := validatePortRange("sip port", c.SIPPort); err != nil {
		return Config{}, fmt.Errorf("normalizing swu config: %w", err)
	}
	return c, nil
}

func handshakeConfig(c Config) handshake.Config {
	return handshake.Config{
		LocalAddr:                    c.LocalAddr,
		RemoteAddr:                   c.RemoteAddr,
		APN:                          c.APN,
		RequestDefaultAPN:            c.RequestDefaultAPN,
		PDNType:                      c.PDNType,
		InitialPort:                  c.InitialPort,
		NATTPort:                     c.NATTPort,
		DHGroups:                     append([]uint16(nil), c.DHGroups...),
		IKEEncryption:                append([]uint16(nil), c.IKEEncryption...),
		IKEEncryptionKeyLens:         append([]uint16(nil), c.IKEEncryptionKeyLens...),
		IKEEncryptionAESCTRKeyLens:   append([]uint16(nil), c.IKEEncryptionAESCTRKeyLens...),
		IKEIntegrity:                 append([]uint16(nil), c.IKEIntegrity...),
		IKEPRF:                       append([]uint16(nil), c.IKEPRF...),
		ChildEncryption:              append([]uint16(nil), c.ChildEncryption...),
		ChildEncryptionKeyLens:       append([]uint16(nil), c.ChildEncryptionKeyLens...),
		ChildEncryptionAESCTRKeyLens: append([]uint16(nil), c.ChildEncryptionAESCTRKeyLens...),
		ChildIntegrity:               append([]uint16(nil), c.ChildIntegrity...),
		ChildSAMultipleProposals:     c.ChildSAMultipleProposals,
		PCSCFIPv4ConfigAttribute:     c.PCSCFIPv4ConfigAttribute,
		PCSCFIPv6ConfigAttribute:     c.PCSCFIPv6ConfigAttribute,
		PCSCFRestoration:             !c.DisablePCSCFRestoration,
		PDUSessionID:                 c.PDUSessionID,
		IPMSIndication:               c.EnableIPMSIndication,
		NATKeepaliveInterval:         c.NATKeepaliveInterval,
		LivenessTimeout:              c.LivenessTimeout,
		IKERetransmitDelays:          append([]time.Duration(nil), c.IKERetransmitDelays...),
	}
}

func validPDNType(pdnType handshake.PDNType) bool {
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
	case transformDH1024MODP, transformDH1536MODP, transformDH2048MODP, transformDH3072MODP, transformDH4096MODP:
		return nil
	default:
		return fmt.Errorf("dh group %d is unsupported", group)
	}
}

func validateEncryptionTransforms(name string, values []uint16) error {
	if len(values) == 0 {
		return fmt.Errorf("%s must not be empty", name)
	}
	for _, value := range values {
		if !supportedEncryptionTransform(value) {
			return fmt.Errorf("%s value %d is unsupported", name, value)
		}
	}
	return nil
}

func supportedEncryptionTransform(transform uint16) bool {
	return transform == transformENCRAESCBC || transform == transformENCRAESCTR
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
		case transformINTEGHMACMD596, transformINTEGHMACSHA196, transformINTEGAESXCBC96, transformINTEGHMACSHA256, transformINTEGHMACSHA384, transformINTEGHMACSHA512:
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
		case transformPRFHMACMD5, transformPRFHMACSHA1, transformPRFAES128XCBC, transformPRFHMACSHA256, transformPRFHMACSHA384, transformPRFHMACSHA512:
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
