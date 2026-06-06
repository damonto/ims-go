package vowifi

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/damonto/vowifi-go/ims/pidf"
	"github.com/damonto/vowifi-go/ims/security"
	imssms "github.com/damonto/vowifi-go/ims/sms"
	imsussd "github.com/damonto/vowifi-go/ims/ussd"
	"github.com/damonto/vowifi-go/swu/tunnel"
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
	if cfg.ReconnectMaxDelay == 0 {
		cfg.ReconnectMaxDelay = max(defaultReconnectMaxDelay, cfg.ReconnectDelay)
	}
	if cfg.ReconnectDelay > cfg.ReconnectMaxDelay {
		return Config{}, errors.New("normalizing client config: reconnect max delay must be >= reconnect delay")
	}

	cfg.Terminal = cfg.Terminal.trimmed()
	if cfg.Terminal.ID == "" {
		return Config{}, errors.New("normalizing client config: terminal id is empty")
	}
	cfg.smsRequestStatusReport = true
	profile, ok, err := loadWFCProfile(card)
	if err != nil {
		return Config{}, err
	}
	if ok {
		cfg = cfg.withWFCProfile(profile, card)
	}
	if cfg.EPDG == "" {
		epdg, err := defaultEPDGAddress(card)
		if err != nil {
			return Config{}, err
		}
		cfg.EPDG = epdg
	}

	imsCfg, err := cfg.normalizedIMS()
	if err != nil {
		return Config{}, err
	}
	cfg.IMS = imsCfg

	tunnelCfg, err := cfg.normalizedTunnel()
	if err != nil {
		return Config{}, err
	}
	cfg.Tunnel = tunnelCfg

	return cfg, nil
}

func (cfg Config) trimmed() Config {
	cfg.EPDG = strings.TrimSpace(cfg.EPDG)
	cfg.Terminal = cfg.Terminal.trimmed()
	return cfg
}

func (cfg Config) validate() error {
	if cfg.ReconnectDelay < 0 {
		return errors.New("normalizing client config: reconnect delay must be >= 0")
	}
	if cfg.ReconnectMaxDelay < 0 {
		return errors.New("normalizing client config: reconnect max delay must be >= 0")
	}
	return nil
}

func (cfg Config) normalizedTunnel() (tunnel.Config, error) {
	tunnelCfg := cfg.Tunnel
	if tunnelCfg.Logger == nil {
		tunnelCfg.Logger = cfg.Logger
	}
	if tunnelCfg.SIPPort == 0 && cfg.IMS.SIPServerPort != 0 {
		tunnelCfg.SIPPort = cfg.IMS.SIPServerPort
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
		imsCfg.IMEI = cfg.Terminal.trimmed().ID
	}
	// Over ePDG/SWu we default to TCP for SIP, matching the pre-refactor
	// behavior and avoiding large initial REGISTER requests over UDP.
	if strings.TrimSpace(imsCfg.Transport) == "" && strings.TrimSpace(cfg.EPDG) != "" {
		imsCfg.Transport = "tcp"
	}
	if strings.TrimSpace(imsCfg.AccessNetworkInfo) == "" && strings.TrimSpace(imsCfg.WLANNodeID) == "" && strings.TrimSpace(cfg.EPDG) != "" {
		imsCfg.AccessNetworkInfo = "IEEE-802.11"
	}
	normalized, err := imsCfg.Normalized()
	if err != nil {
		return IMSConfig{}, fmt.Errorf("normalizing ims config: %w", err)
	}
	return normalized, nil
}

func (cfg IMSConfig) Normalized() (IMSConfig, error) {
	cfg.Transport = strings.ToLower(strings.TrimSpace(cfg.Transport))
	cfg.PrivateIdentity = strings.TrimSpace(cfg.PrivateIdentity)
	cfg.PublicIdentity = strings.TrimSpace(cfg.PublicIdentity)
	cfg.HomeDomain = strings.TrimSpace(cfg.HomeDomain)
	cfg.PhoneContextDomain = strings.TrimSpace(cfg.PhoneContextDomain)
	cfg.USSDLanguage = strings.TrimSpace(cfg.USSDLanguage)
	cfg.USSDDomain = strings.ToLower(strings.TrimSpace(cfg.USSDDomain))
	cfg.UserAgent = strings.TrimSpace(cfg.UserAgent)
	cfg.AccessNetworkInfo = strings.TrimSpace(cfg.AccessNetworkInfo)
	cfg.WLANNodeID = strings.TrimSpace(cfg.WLANNodeID)
	cfg.ServiceCenter = strings.TrimSpace(cfg.ServiceCenter)
	cfg.IMEI = strings.TrimSpace(cfg.IMEI)
	cfg.AuthAlgorithm = strings.TrimSpace(cfg.AuthAlgorithm)
	cfg.GeolocationPIDFRegister = pidf.NormalizeTypes(cfg.GeolocationPIDFRegister)
	cfg.GeolocationCountry = strings.ToUpper(strings.TrimSpace(cfg.GeolocationCountry))
	cfg.Voice.GeolocationCountry = strings.ToUpper(strings.TrimSpace(cfg.Voice.GeolocationCountry))
	if cfg.GeolocationCountry == "" {
		cfg.GeolocationCountry = cfg.Voice.GeolocationCountry
	}
	if cfg.Voice.GeolocationCountry == "" {
		cfg.Voice.GeolocationCountry = cfg.GeolocationCountry
	}
	if cfg.UseTelURIForPIDFXML {
		cfg.Voice.UseTelURIForPIDFXML = true
	}
	if geolocationPIDFConfigured(cfg) && cfg.GeolocationCountry == "" {
		cfg.GeolocationCountry = "US"
		cfg.Voice.GeolocationCountry = "US"
	}
	if cfg.GeolocationCountry != "" && len(cfg.GeolocationCountry) != 2 {
		return IMSConfig{}, errors.New("normalizing ims config: geolocation country must be two letters")
	}
	timers, err := cfg.SIPTimers.Normalized()
	if err != nil {
		return IMSConfig{}, fmt.Errorf("normalizing ims config: %w", err)
	}
	cfg.SIPTimers = timers
	cfg.TCPDataACKTimeouts = append([]time.Duration(nil), cfg.TCPDataACKTimeouts...)
	for _, timeout := range cfg.TCPDataACKTimeouts {
		if timeout <= 0 {
			return IMSConfig{}, errors.New("normalizing ims config: tcp data ack timeout must be > 0")
		}
	}

	if cfg.Transport == "" {
		cfg.Transport = "udp"
	}
	switch cfg.Transport {
	case "udp", "tcp":
	default:
		return IMSConfig{}, fmt.Errorf("normalizing ims config: unsupported transport %q", cfg.Transport)
	}
	if cfg.RegisterExpires < 0 {
		return IMSConfig{}, errors.New("normalizing ims config: register expires must be >= 0")
	}
	if cfg.RegisterExpires == 0 {
		cfg.RegisterExpires = 600000 * time.Second
	}
	if cfg.USSDDomain == "" {
		cfg.USSDDomain = string(imsussd.DomainIMS)
	}
	switch imsussd.Domain(cfg.USSDDomain) {
	case imsussd.DomainIMS, imsussd.DomainCS, imsussd.DomainDisabled:
	default:
		return IMSConfig{}, fmt.Errorf("normalizing ims config: unsupported ussd domain %q", cfg.USSDDomain)
	}
	if cfg.AuthAlgorithm == "" {
		cfg.AuthAlgorithm = security.AlgorithmAKAv1MD5
	} else {
		algorithm, ok := security.NormalizeAKAAlgorithm(cfg.AuthAlgorithm)
		if !ok {
			return IMSConfig{}, fmt.Errorf("normalizing ims config: unsupported AKA algorithm %q", cfg.AuthAlgorithm)
		}
		if algorithm == security.AlgorithmAKAv2MD5 {
			return IMSConfig{}, errors.New("normalizing ims config: AKAv2-MD5 is not a valid IMS REGISTER bootstrap algorithm")
		}
		cfg.AuthAlgorithm = algorithm
	}
	if cfg.RegistrationRetryBase < 0 {
		return IMSConfig{}, errors.New("normalizing ims config: registration retry base must be >= 0")
	}
	if cfg.RegistrationRetryMax < 0 {
		return IMSConfig{}, errors.New("normalizing ims config: registration retry max must be >= 0")
	}
	if cfg.RegistrationRetryBase == 0 {
		cfg.RegistrationRetryBase = defaultIMSRegistrationRetryBase
	}
	if cfg.RegistrationRetryMax == 0 {
		cfg.RegistrationRetryMax = max(defaultIMSRegistrationRetryMax, cfg.RegistrationRetryBase)
	}
	if cfg.RegistrationRetryBase > cfg.RegistrationRetryMax {
		return IMSConfig{}, errors.New("normalizing ims config: registration retry max must be >= registration retry base")
	}
	if cfg.SIPServerPort < 0 || cfg.SIPServerPort > 65535 {
		return IMSConfig{}, errors.New("normalizing ims config: sip server port must be between 0 and 65535")
	}
	if cfg.SMSDeliveryReportTimeout < 0 {
		return IMSConfig{}, errors.New("normalizing ims config: sms delivery report timeout must be >= 0")
	}
	if cfg.SMSDeliveryReportTimeout == 0 {
		cfg.SMSDeliveryReportTimeout = imssms.DefaultDeliveryReportTimeout()
	}
	voiceCfg, err := cfg.Voice.Normalized()
	if err != nil {
		return IMSConfig{}, fmt.Errorf("normalizing ims config: %w", err)
	}
	cfg.Voice = voiceCfg
	return cfg, nil
}

func geolocationPIDFConfigured(cfg IMSConfig) bool {
	return len(cfg.GeolocationPIDFRegister) > 0 ||
		len(cfg.Voice.GeolocationPIDFInvite) > 0 ||
		len(cfg.Voice.PIDFShortCodes) > 0
}

func defaultEPDGAddress(card Card) (string, error) {
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
