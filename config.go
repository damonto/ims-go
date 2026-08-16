package ims

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/damonto/ims-go/ims/pidf"
	"github.com/damonto/ims-go/ims/registration"
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
	IMS               ServiceConfig

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

func (ti TerminalInfo) trimmed() TerminalInfo {
	ti.ID = strings.TrimSpace(ti.ID)
	ti.Vendor = strings.TrimSpace(ti.Vendor)
	ti.Model = strings.TrimSpace(ti.Model)
	ti.SoftwareVersion = strings.TrimSpace(ti.SoftwareVersion)
	ti.Build = strings.TrimSpace(ti.Build)
	ti.Type = strings.TrimSpace(ti.Type)
	ti.HardwareSKU = strings.TrimSpace(ti.HardwareSKU)
	return ti
}

type ServiceConfig struct {
	Transport             string
	PrivateIdentity       string
	PublicIdentity        string
	HomeDomain            string
	PhoneContextDomain    string
	USSDLanguage          string
	USSDDomain            string
	UserAgent             string
	AccessNetworkInfo     string
	WLANNodeID            string
	RegisterExpires       time.Duration
	AuthAlgorithm         string
	RegistrationRetryBase time.Duration
	RegistrationRetryMax  time.Duration
	// RegistrationGroup enables RFC 5626 multiple registration. Share the
	// same group between Clients that use the same USIM and IMS identity.
	RegistrationGroup *registration.Group
	// RegistrationID is the stable reg-id for this access flow.
	RegistrationID uint32
	// RegistrationPreference is both the local queue priority and Contact q
	// value in thousandths. Valid values are 1 through 1000.
	RegistrationPreference    int
	IPSecIntegrityAlgorithms  []string
	IPSecEncryptionAlgorithms []string
	IPSecModes                []string
	ServiceCenter             string
	IMEI                      string
	GeolocationPIDFRegister   []int
	GeolocationCountry        string
	UseTelURIForPIDFXML       bool
	SIPServerPort             int
	SIPTimers                 imssession.TransactionTimers
	SMSDeliveryReportTimeout  time.Duration
	Voice                     imsvoice.Config
}

func cloneConfig(c *Config) Config {
	if c == nil {
		return Config{}
	}
	cloned := *c
	cloned.Access = c.Access.clone()
	return cloned
}

func (c AccessConfig) clone() AccessConfig {
	if c.VoWiFi != nil {
		wifi := *c.VoWiFi
		c.VoWiFi = &wifi
	}
	if c.VoLTE != nil {
		volte := *c.VoLTE
		c.VoLTE = &volte
	}
	return c
}

func (c Config) normalized(card Card) (Config, error) {
	c = c.trimmed()

	if err := c.validate(); err != nil {
		return Config{}, err
	}

	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.ReconnectDelay == 0 {
		c.ReconnectDelay = defaultReconnectDelay
	}
	if c.ReconnectMaxDelay == 0 {
		c.ReconnectMaxDelay = max(defaultReconnectMaxDelay, c.ReconnectDelay)
	}
	if c.ReconnectDelay > c.ReconnectMaxDelay {
		return Config{}, errors.New("normalizing client config: reconnect max delay must be >= reconnect delay")
	}

	c.Terminal = c.Terminal.trimmed()
	if c.Terminal.ID == "" {
		return Config{}, errors.New("normalizing client config: terminal id is empty")
	}
	c.smsRequestStatusReport = true
	accessCfg, err := c.Access.normalized()
	if err != nil {
		return Config{}, err
	}
	c.Access = accessCfg

	profile, ok, err := loadIMSProfile(card)
	if err != nil {
		return Config{}, err
	}
	if ok {
		c = c.withIMSProfile(profile, card)
		c.Logger.Debug(
			"IMS carrier profile selected",
			"mcc", profile.MCC,
			"mnc", profile.MNC,
			"imsi_prefix", profile.IMSIPrefix,
			"iccid_prefix", profile.ICCIDPrefix,
			"spn", profile.SPN,
			"gid1", profile.GID1,
			"gid2", profile.GID2,
			"epdg", profile.EPDG,
		)
	}

	if c.usesVoWiFi() {
		if c.Access.VoWiFi.EPDG == "" {
			epdg, err := defaultEPDGAddress(card)
			if err != nil {
				return Config{}, err
			}
			c.Access.VoWiFi.EPDG = epdg
		}
	}

	imsCfg, err := c.normalizedIMS()
	if err != nil {
		return Config{}, err
	}
	c.IMS = imsCfg

	if c.usesVoWiFi() {
		tunnelCfg, err := c.normalizedTunnel()
		if err != nil {
			return Config{}, err
		}
		c.Access.VoWiFi.Tunnel = tunnelCfg
	}

	return c, nil
}

func (c Config) trimmed() Config {
	c.Terminal = c.Terminal.trimmed()
	if c.Access.VoWiFi != nil {
		wifi := *c.Access.VoWiFi
		wifi.EPDG = strings.TrimSpace(wifi.EPDG)
		c.Access.VoWiFi = &wifi
	}
	return c
}

func (c Config) validate() error {
	if c.ReconnectDelay < 0 {
		return errors.New("normalizing client config: reconnect delay must be >= 0")
	}
	if c.ReconnectMaxDelay < 0 {
		return errors.New("normalizing client config: reconnect max delay must be >= 0")
	}
	return nil
}

func (c Config) normalizedTunnel() (tunnel.Config, error) {
	tunnelCfg := c.Access.VoWiFi.Tunnel
	if c.Access.VoWiFi.Underlay != nil && tunnelCfg.PacketConn == nil && tunnelCfg.ListenPacket == nil {
		tunnelCfg.ListenPacket = c.Access.VoWiFi.Underlay.ListenPacket
	}
	if tunnelCfg.Logger == nil {
		tunnelCfg.Logger = c.Logger
	}
	if tunnelCfg.SIPPort == 0 && c.IMS.SIPServerPort != 0 {
		tunnelCfg.SIPPort = c.IMS.SIPServerPort
	}
	tunnelCfg, err := tunnelCfg.Normalized()
	if err != nil {
		return tunnel.Config{}, fmt.Errorf("normalizing tunnel config: %w", err)
	}
	return tunnelCfg, nil
}

func (c Config) normalizedIMS() (ServiceConfig, error) {
	imsCfg := c.IMS
	if imsCfg.IMEI == "" {
		imsCfg.IMEI = c.Terminal.trimmed().ID
	}
	var epdg string
	if c.usesVoWiFi() {
		epdg = strings.TrimSpace(c.Access.VoWiFi.EPDG)
	}
	// Over ePDG/SWu we default to TCP for SIP, matching the pre-refactor
	// behavior and avoiding large initial REGISTER requests over UDP.
	if strings.TrimSpace(imsCfg.Transport) == "" && epdg != "" {
		imsCfg.Transport = "tcp"
	}
	if strings.TrimSpace(imsCfg.AccessNetworkInfo) == "" && c.usesVoLTE() {
		imsCfg.AccessNetworkInfo = c.Access.VoLTE.AccessNetworkInfo
	}
	if strings.TrimSpace(imsCfg.AccessNetworkInfo) == "" && strings.TrimSpace(imsCfg.WLANNodeID) == "" && epdg != "" {
		imsCfg.AccessNetworkInfo = "IEEE-802.11"
	}
	if imsCfg.RegistrationGroup != nil {
		switch {
		case c.usesVoWiFi():
			if imsCfg.RegistrationID == 0 {
				imsCfg.RegistrationID = defaultVoWiFiRegistrationID
			}
			if imsCfg.RegistrationPreference == 0 {
				imsCfg.RegistrationPreference = defaultVoWiFiRegistrationPreference
			}
		case c.usesVoLTE():
			if imsCfg.RegistrationID == 0 {
				imsCfg.RegistrationID = defaultVoLTERegistrationID
			}
			if imsCfg.RegistrationPreference == 0 {
				imsCfg.RegistrationPreference = defaultVoLTERegistrationPreference
			}
		}
	}
	imsCfg, err := imsCfg.Normalized()
	if err != nil {
		return ServiceConfig{}, err
	}
	if c.usesVoLTE() && imsCfg.AccessNetworkInfo == "" {
		return ServiceConfig{}, errors.New("normalizing ims config: access network info is required for VoLTE")
	}
	if c.usesVoLTE() {
		imsCfg.AccessNetworkInfo, err = lte.NormalizeAccessNetworkInfo(imsCfg.AccessNetworkInfo)
		if err != nil {
			return ServiceConfig{}, fmt.Errorf("normalizing ims config: %w", err)
		}
	}
	return imsCfg, nil
}

func (c ServiceConfig) Normalized() (ServiceConfig, error) {
	c.Transport = strings.ToLower(strings.TrimSpace(c.Transport))
	c.PrivateIdentity = strings.TrimSpace(c.PrivateIdentity)
	c.PublicIdentity = strings.TrimSpace(c.PublicIdentity)
	c.HomeDomain = strings.TrimSpace(c.HomeDomain)
	c.PhoneContextDomain = strings.TrimSpace(c.PhoneContextDomain)
	c.USSDLanguage = strings.TrimSpace(c.USSDLanguage)
	c.USSDDomain = strings.ToLower(strings.TrimSpace(c.USSDDomain))
	c.UserAgent = strings.TrimSpace(c.UserAgent)
	c.AccessNetworkInfo = strings.TrimSpace(c.AccessNetworkInfo)
	c.WLANNodeID = strings.TrimSpace(c.WLANNodeID)
	c.ServiceCenter = strings.TrimSpace(c.ServiceCenter)
	c.IMEI = strings.TrimSpace(c.IMEI)
	c.AuthAlgorithm = strings.TrimSpace(c.AuthAlgorithm)
	var err error
	c.IPSecIntegrityAlgorithms, err = security.NormalizeIPSecIntegrityAlgorithms(c.IPSecIntegrityAlgorithms)
	if err != nil {
		return ServiceConfig{}, fmt.Errorf("normalizing ims config: %w", err)
	}
	c.IPSecEncryptionAlgorithms, err = security.NormalizeIPSecEncryptionAlgorithms(c.IPSecEncryptionAlgorithms)
	if err != nil {
		return ServiceConfig{}, fmt.Errorf("normalizing ims config: %w", err)
	}
	c.IPSecModes, err = security.NormalizeIPSecModes(c.IPSecModes)
	if err != nil {
		return ServiceConfig{}, fmt.Errorf("normalizing ims config: %w", err)
	}
	c.GeolocationPIDFRegister = pidf.NormalizeTypes(c.GeolocationPIDFRegister)
	c.GeolocationCountry = strings.ToUpper(strings.TrimSpace(c.GeolocationCountry))
	c.Voice.GeolocationCountry = strings.ToUpper(strings.TrimSpace(c.Voice.GeolocationCountry))
	if c.GeolocationCountry == "" {
		c.GeolocationCountry = c.Voice.GeolocationCountry
	}
	if c.Voice.GeolocationCountry == "" {
		c.Voice.GeolocationCountry = c.GeolocationCountry
	}
	if c.UseTelURIForPIDFXML {
		c.Voice.UseTelURIForPIDFXML = true
	}
	if geolocationPIDFConfigured(c) && c.GeolocationCountry == "" {
		c.GeolocationCountry = "US"
		c.Voice.GeolocationCountry = "US"
	}
	if c.GeolocationCountry != "" && len(c.GeolocationCountry) != 2 {
		return ServiceConfig{}, errors.New("normalizing ims config: geolocation country must be two letters")
	}
	timers, err := c.SIPTimers.Normalized()
	if err != nil {
		return ServiceConfig{}, fmt.Errorf("normalizing ims config: %w", err)
	}
	c.SIPTimers = timers
	if c.Transport == "" {
		c.Transport = "udp"
	}
	switch c.Transport {
	case "udp", "tcp":
	default:
		return ServiceConfig{}, fmt.Errorf("normalizing ims config: unsupported transport %q", c.Transport)
	}
	if c.RegisterExpires < 0 {
		return ServiceConfig{}, errors.New("normalizing ims config: register expires must be >= 0")
	}
	if c.RegisterExpires == 0 {
		c.RegisterExpires = 600000 * time.Second
	}
	if c.USSDDomain == "" {
		c.USSDDomain = string(imsussd.DomainIMS)
	}
	switch imsussd.Domain(c.USSDDomain) {
	case imsussd.DomainIMS, imsussd.DomainCS, imsussd.DomainDisabled:
	default:
		return ServiceConfig{}, fmt.Errorf("normalizing ims config: unsupported ussd domain %q", c.USSDDomain)
	}
	if c.AuthAlgorithm == "" {
		c.AuthAlgorithm = security.AlgorithmAKAv1MD5
	} else {
		algorithm, ok := security.NormalizeAKAAlgorithm(c.AuthAlgorithm)
		if !ok {
			return ServiceConfig{}, fmt.Errorf("normalizing ims config: unsupported AKA algorithm %q", c.AuthAlgorithm)
		}
		if algorithm == security.AlgorithmAKAv2MD5 {
			return ServiceConfig{}, errors.New("normalizing ims config: AKAv2-MD5 is not a valid IMS REGISTER bootstrap algorithm")
		}
		c.AuthAlgorithm = algorithm
	}
	if c.RegistrationRetryBase < 0 {
		return ServiceConfig{}, errors.New("normalizing ims config: registration retry base must be >= 0")
	}
	if c.RegistrationRetryMax < 0 {
		return ServiceConfig{}, errors.New("normalizing ims config: registration retry max must be >= 0")
	}
	if c.RegistrationRetryBase == 0 {
		c.RegistrationRetryBase = defaultIMSRegistrationRetryBase
	}
	if c.RegistrationRetryMax == 0 {
		c.RegistrationRetryMax = max(defaultIMSRegistrationRetryMax, c.RegistrationRetryBase)
	}
	if c.RegistrationRetryBase > c.RegistrationRetryMax {
		return ServiceConfig{}, errors.New("normalizing ims config: registration retry max must be >= registration retry base")
	}
	if c.RegistrationGroup == nil {
		if c.RegistrationID != 0 || c.RegistrationPreference != 0 {
			return ServiceConfig{}, errors.New("normalizing ims config: registration group is required for multiple registration settings")
		}
	} else {
		if c.RegistrationID == 0 {
			return ServiceConfig{}, errors.New("normalizing ims config: registration id must be greater than zero")
		}
		if c.RegistrationPreference < 1 || c.RegistrationPreference > 1000 {
			return ServiceConfig{}, errors.New("normalizing ims config: registration preference must be between 1 and 1000")
		}
		if c.IMEI == "" {
			return ServiceConfig{}, errors.New("normalizing ims config: imei is required for multiple registration")
		}
	}
	if c.SIPServerPort < 0 || c.SIPServerPort > 65535 {
		return ServiceConfig{}, errors.New("normalizing ims config: sip server port must be between 0 and 65535")
	}
	if c.SMSDeliveryReportTimeout < 0 {
		return ServiceConfig{}, errors.New("normalizing ims config: sms delivery report timeout must be >= 0")
	}
	if c.SMSDeliveryReportTimeout == 0 {
		c.SMSDeliveryReportTimeout = imssms.DefaultDeliveryReportTimeout()
	}
	voiceCfg, err := c.Voice.Normalized()
	if err != nil {
		return ServiceConfig{}, fmt.Errorf("normalizing ims config: %w", err)
	}
	c.Voice = voiceCfg
	return c, nil
}

func geolocationPIDFConfigured(c ServiceConfig) bool {
	return len(c.GeolocationPIDFRegister) > 0 ||
		len(c.Voice.GeolocationPIDFInvite) > 0 ||
		len(c.Voice.PIDFShortCodes) > 0
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

func renderIMSUserAgent(template string, c Config, profile imsProfile) string {
	terminal := c.Terminal.trimmed()
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
