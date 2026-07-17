package ims

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/damonto/ims-go/ims/pidf"
	"github.com/damonto/ims-go/ims/security"
	imssession "github.com/damonto/ims-go/ims/session"
	imssms "github.com/damonto/ims-go/ims/sms"
	imsussd "github.com/damonto/ims-go/ims/ussd"
	imsvoice "github.com/damonto/ims-go/ims/voice"
	"github.com/damonto/ims-go/lte"
	"github.com/damonto/ims-go/swu/tunnel"
)

type Config struct {
	Logger            *slog.Logger
	ReconnectDelay    time.Duration
	ReconnectMaxDelay time.Duration
	Terminal          TerminalInfo
	Access            AccessConfig
	IMS               IMSConfig

	smsRequestStatusReport bool
}

type TerminalInfo struct {
	ID              string
	Vendor          string
	Model           string
	SoftwareVersion string
	Build           string
	Type            string
	HardwareSKU     string
}

func (terminal TerminalInfo) trimmed() TerminalInfo {
	terminal.ID = strings.TrimSpace(terminal.ID)
	terminal.Vendor = strings.TrimSpace(terminal.Vendor)
	terminal.Model = strings.TrimSpace(terminal.Model)
	terminal.SoftwareVersion = strings.TrimSpace(terminal.SoftwareVersion)
	terminal.Build = strings.TrimSpace(terminal.Build)
	terminal.Type = strings.TrimSpace(terminal.Type)
	terminal.HardwareSKU = strings.TrimSpace(terminal.HardwareSKU)
	return terminal
}

type IMSConfig struct {
	Transport                string
	PrivateIdentity          string
	PublicIdentity           string
	HomeDomain               string
	PhoneContextDomain       string
	USSDLanguage             string
	USSDDomain               string
	UserAgent                string
	AccessNetworkInfo        string
	WLANNodeID               string
	RegisterExpires          time.Duration
	AuthAlgorithm            string
	RegistrationRetryBase    time.Duration
	RegistrationRetryMax     time.Duration
	ServiceCenter            string
	IMEI                     string
	GeolocationPIDFRegister  []int
	GeolocationCountry       string
	UseTelURIForPIDFXML      bool
	SIPServerPort            int
	SIPTimers                imssession.TransactionTimers
	SMSDeliveryReportTimeout time.Duration
	Voice                    imsvoice.Config
}

func cloneConfig(cfg *Config) Config {
	if cfg == nil {
		return Config{}
	}
	cloned := *cfg
	cloned.Access = cfg.Access.clone()
	return cloned
}

func (cfg AccessConfig) clone() AccessConfig {
	if cfg.VoWiFi != nil {
		wifi := *cfg.VoWiFi
		cfg.VoWiFi = &wifi
	}
	if cfg.VoLTE != nil {
		volte := *cfg.VoLTE
		cfg.VoLTE = &volte
	}
	return cfg
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
	accessCfg, err := cfg.Access.normalized()
	if err != nil {
		return Config{}, err
	}
	cfg.Access = accessCfg

	profile, ok, err := loadIMSProfile(card)
	if err != nil {
		return Config{}, err
	}
	if ok {
		cfg = cfg.withIMSProfile(profile, card)
		cfg.Logger.Debug("IMS carrier profile selected", "mcc", profile.MCC, "mnc", profile.MNC, "gid1", profile.GID1)
	}

	if cfg.usesVoWiFi() {
		if cfg.Access.VoWiFi.EPDG == "" {
			epdg, err := defaultEPDGAddress(card)
			if err != nil {
				return Config{}, err
			}
			cfg.Access.VoWiFi.EPDG = epdg
		}
	}

	imsCfg, err := cfg.normalizedIMS()
	if err != nil {
		return Config{}, err
	}
	cfg.IMS = imsCfg

	if cfg.usesVoWiFi() {
		tunnelCfg, err := cfg.normalizedTunnel()
		if err != nil {
			return Config{}, err
		}
		cfg.Access.VoWiFi.Tunnel = tunnelCfg
	}

	return cfg, nil
}

func (cfg Config) trimmed() Config {
	cfg.Terminal = cfg.Terminal.trimmed()
	if cfg.Access.VoWiFi != nil {
		wifi := *cfg.Access.VoWiFi
		wifi.EPDG = strings.TrimSpace(wifi.EPDG)
		cfg.Access.VoWiFi = &wifi
	}
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
	tunnelCfg := cfg.Access.VoWiFi.Tunnel
	if tunnelCfg.Logger == nil {
		tunnelCfg.Logger = cfg.Logger
	}
	if tunnelCfg.SIPPort == 0 && cfg.IMS.SIPServerPort != 0 {
		tunnelCfg.SIPPort = cfg.IMS.SIPServerPort
	}
	tunnelCfg, err := tunnelCfg.Normalized()
	if err != nil {
		return tunnel.Config{}, fmt.Errorf("normalizing tunnel config: %w", err)
	}
	return tunnelCfg, nil
}

func (cfg Config) normalizedIMS() (IMSConfig, error) {
	imsCfg := cfg.IMS
	if imsCfg.IMEI == "" {
		imsCfg.IMEI = cfg.Terminal.trimmed().ID
	}
	var epdg string
	if cfg.usesVoWiFi() {
		epdg = strings.TrimSpace(cfg.Access.VoWiFi.EPDG)
	}
	// Over ePDG/SWu we default to TCP for SIP, matching the pre-refactor
	// behavior and avoiding large initial REGISTER requests over UDP.
	if strings.TrimSpace(imsCfg.Transport) == "" && epdg != "" {
		imsCfg.Transport = "tcp"
	}
	if strings.TrimSpace(imsCfg.AccessNetworkInfo) == "" && cfg.usesVoLTE() {
		imsCfg.AccessNetworkInfo = cfg.Access.VoLTE.AccessNetworkInfo
	}
	if strings.TrimSpace(imsCfg.AccessNetworkInfo) == "" && strings.TrimSpace(imsCfg.WLANNodeID) == "" && epdg != "" {
		imsCfg.AccessNetworkInfo = "IEEE-802.11"
	}
	imsCfg, err := imsCfg.Normalized()
	if err != nil {
		return IMSConfig{}, fmt.Errorf("normalizing ims config: %w", err)
	}
	if cfg.usesVoLTE() && imsCfg.AccessNetworkInfo == "" {
		return IMSConfig{}, errors.New("normalizing ims config: access network info is required for VoLTE")
	}
	if cfg.usesVoLTE() {
		imsCfg.AccessNetworkInfo, err = lte.NormalizeAccessNetworkInfo(imsCfg.AccessNetworkInfo)
		if err != nil {
			return IMSConfig{}, fmt.Errorf("normalizing ims config: %w", err)
		}
	}
	return imsCfg, nil
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

func renderIMSUserAgent(template string, cfg Config, profile imsProfile) string {
	terminal := cfg.Terminal.trimmed()
	replacer := strings.NewReplacer(
		"#MANUFACTURE#", terminal.Vendor,
		"#MANUFACTURER#", terminal.Vendor,
		"#MODEL#", terminal.Model,
		"#AV#", terminal.SoftwareVersion,
		"#BUILD#", terminal.Build,
		"#TYPE#", terminal.Type,
		"#MCCMNC#", strings.TrimSpace(profile.MCC)+strings.TrimSpace(profile.MNC),
		"#IMEISV#", imeisvFromIMEI(terminal.ID),
		"#OPERATOR#", strings.TrimSpace(profile.WFCSPN),
		"#HWSKU#", terminal.HardwareSKU,
	)
	return replacer.Replace(template)
}

func imeisvFromIMEI(imei string) string {
	imei = strings.TrimSpace(imei)
	if len(imei) >= 16 {
		return imei[:16]
	}
	if len(imei) >= 14 {
		return imei[:14] + "00"
	}
	return imei
}
