package vowifi

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	imsvoice "github.com/damonto/vowifi-go/ims/voice"
)

//go:embed wfc_config.json
var embeddedWFCConfig []byte

type wfcProfile struct {
	MCC                        string           `json:"mcc"`
	MNC                        string           `json:"mnc"`
	GID1                       string           `json:"gid1"`
	EPDG                       string           `json:"epdg"`
	EPDGAddresses              []string         `json:"epdgAddresses"`
	InitialPort                int              `json:"initialPort"`
	NATTPort                   int              `json:"nattPort"`
	LocalSIPPort               int              `json:"localSIPPort"`
	SIPPort                    int              `json:"sipPort"`
	DHGroups                   []uint16         `json:"dhGroups"`
	IKEEncryptionKeyLens       []uint16         `json:"ikeEncryptionKeyLens"`
	IKEIntegrity               []uint16         `json:"ikeIntegrity"`
	IKEPRF                     []uint16         `json:"ikePRF"`
	ChildEncryptionKeyLens     []uint16         `json:"childEncryptionKeyLens"`
	ChildIntegrity             []uint16         `json:"childIntegrity"`
	PCSCFIPv4ConfigAttribute   uint16           `json:"pcscfIPv4ConfigAttribute"`
	PCSCFIPv6ConfigAttribute   uint16           `json:"pcscfIPv6ConfigAttribute"`
	NATKeepaliveInterval       *wfcDuration     `json:"natKeepaliveInterval"`
	AndroidDPDSeconds          *int             `json:"iwlan.dpd_timer_sec_int"`
	AndroidNATKeepaliveSeconds *int             `json:"iwlan.natt_keep_alive_timer_sec_int"`
	IKERetransmitDelays        []wfcDuration    `json:"ikeRetransmitDelays"`
	AndroidIKERetransmitMS     []int            `json:"iwlan.retransmit_timer_sec_int_array"`
	IKESARekeySoftTime         *wfcDuration     `json:"ikeSARekeySoftTime"`
	IKESARekeyHardTime         *wfcDuration     `json:"ikeSARekeyHardTime"`
	IKESARekeyTime             *wfcDuration     `json:"ikeSARekeyTime"`
	AndroidIKESARekeySoftSecs  *int             `json:"iwlan.ike_rekey_soft_timer_sec_int"`
	AndroidIKESARekeyHardSecs  *int             `json:"iwlan.ike_rekey_hard_timer_in_sec"`
	ChildSARekeySoftTime       *wfcDuration     `json:"childSARekeySoftTime"`
	ChildSARekeyHardTime       *wfcDuration     `json:"childSARekeyHardTime"`
	ChildSARekeyTime           *wfcDuration     `json:"childSARekeyTime"`
	AndroidChildSARekeySoftSec *int             `json:"iwlan.child_sa_rekey_soft_timer_sec_int"`
	AndroidChildSARekeyHardSec *int             `json:"iwlan.child_sa_rekey_hard_timer_sec_int"`
	AddKEToChildSARekey        *bool            `json:"addKEToChildSARekey"`
	AndroidAddKEToChildRekey   *bool            `json:"iwlan.add_ke_to_child_session_rekey_bool"`
	IMSTransport               string           `json:"imsTransport"`
	IMSHomeDomain              string           `json:"imsHomeDomain"`
	IMSPrivateIdentity         string           `json:"imsPrivateIdentity"`
	IMSPublicIdentity          string           `json:"imsPublicIdentity"`
	IMSPhoneContextDomain      string           `json:"imsPhoneContextDomain"`
	IMSAccessNetworkInfo       string           `json:"imsAccessNetworkInfo"`
	IMSUserAgent               string           `json:"imsUserAgent"`
	IMSRegisterExpires         *wfcDuration     `json:"imsRegisterExpires"`
	IMSRegistrationRetryBase   *wfcDuration     `json:"imsRegistrationRetryBase"`
	IMSRegistrationRetryMax    *wfcDuration     `json:"imsRegistrationRetryMax"`
	AndroidIMSRetryBaseMS      *int             `json:"ims.registration_retry_base_timer_millis_int"`
	AndroidIMSRetryMaxMS       *int             `json:"ims.registration_retry_max_timer_millis_int"`
	IMSGeolocationPIDFInvite   []int            `json:"imsGeolocationPIDFInSIPInviteSupport"`
	IMSGeolocationPIDFRegister []int            `json:"imsGeolocationPIDFInSIPRegisterSupport"`
	IMSUseTelURIForPIDFXML     *bool            `json:"imsUseTelURIForPIDFXML"`
	IMSSIPServerPort           int              `json:"imsSIPServerPort"`
	IMSSIPTimerT1              *wfcDuration     `json:"imsSIPTimerT1"`
	IMSSIPTimerT2              *wfcDuration     `json:"imsSIPTimerT2"`
	IMSSIPTimerT4              *wfcDuration     `json:"imsSIPTimerT4"`
	IMSSIPTimerB               *wfcDuration     `json:"imsSIPTimerB"`
	IMSSIPTimerD               *wfcDuration     `json:"imsSIPTimerD"`
	IMSSIPTimerF               *wfcDuration     `json:"imsSIPTimerF"`
	IMSSIPTimerH               *wfcDuration     `json:"imsSIPTimerH"`
	IMSSIPTimerJ               *wfcDuration     `json:"imsSIPTimerJ"`
	EnableSMSDeliveryReports   *bool            `json:"enableSMSDeliveryReports"`
	IMSVoice                   *wfcVoiceProfile `json:"imsVoice"`
	WFCSPN                     string           `json:"wfcSPN"`
}

type wfcVoiceProfile struct {
	RTPProfile                    string                                  `json:"rtpProfile"`
	PTime                         *wfcDuration                            `json:"ptime"`
	MaxPTime                      *wfcDuration                            `json:"maxptime"`
	GeolocationCountry            string                                  `json:"geolocationCountry"`
	PIDFShortCodes                []string                                `json:"pidfShortCodes"`
	QoSPreconditionsSupported     *bool                                   `json:"qosPreconditionsSupported"`
	ReliableProvisionalSupported  *bool                                   `json:"reliableProvisionalSupported"`
	SessionTimer                  *bool                                   `json:"sessionTimer"`
	SessionExpires                *wfcDuration                            `json:"sessionExpires"`
	MinimumSessionExpires         *wfcDuration                            `json:"minimumSessionExpires"`
	SessionRefresher              string                                  `json:"sessionRefresher"`
	MOCallRequestTimeout          *wfcDuration                            `json:"moCallRequestTimeout"`
	RingbackTimer                 *wfcDuration                            `json:"ringbackTimer"`
	RingingTimer                  *wfcDuration                            `json:"ringingTimer"`
	AudioASBandwidthKbps          int                                     `json:"audioASBandwidthKbps"`
	RTPInactivityTimeout          *wfcDuration                            `json:"rtpInactivityTimeout"`
	RTCPInactivityTimeout         *wfcDuration                            `json:"rtcpInactivityTimeout"`
	AudioInactivityCallEndReasons []imsvoice.AudioInactivityCallEndReason `json:"audioInactivityCallEndReasons"`
	RTCPSendInterval              *wfcDuration                            `json:"rtcpSendInterval"`
	LocalRTPPortMin               int                                     `json:"localRTPPortMin"`
	LocalRTPPortMax               int                                     `json:"localRTPPortMax"`
	Codecs                        []wfcVoiceCodecProfile                  `json:"codecs"`
	EVSPayloadDescriptions        map[string]wfcEVSPayloadDescription     `json:"evsPayloadDescriptions"`
}

type wfcVoiceCodecProfile struct {
	Name         imsvoice.AudioCodec `json:"name"`
	PayloadTypes []int               `json:"payloadTypes"`
	ClockRate    int                 `json:"clockRate"`
	Channels     int                 `json:"channels"`
	ModeSet      string              `json:"modeSet"`
	Bitrate      string              `json:"bitrate"`
	Bandwidth    string              `json:"bandwidth"`
	OctetAlign   bool                `json:"octetAlign"`
}

type wfcEVSPayloadDescription struct {
	Bitrate             string `json:"bitrate"`
	Bandwidth           string `json:"bandwidth"`
	ChannelAwareReceive *int   `json:"channelAwareReceive"`
}

type wfcDuration struct {
	time.Duration
}

func (d *wfcDuration) UnmarshalJSON(data []byte) error {
	value := strings.TrimSpace(string(data))
	if value == "null" {
		return nil
	}

	var text string
	if strings.HasPrefix(value, `"`) {
		if err := json.Unmarshal(data, &text); err != nil {
			return fmt.Errorf("parsing duration string: %w", err)
		}
	} else {
		text = value + "s"
	}

	duration, err := time.ParseDuration(text)
	if err != nil {
		return fmt.Errorf("parsing duration %q: %w", text, err)
	}
	d.Duration = duration
	return nil
}

func loadWFCProfile(card Card) (wfcProfile, bool, error) {
	return parseWFCProfile(embeddedWFCConfig, card)
}

func parseWFCProfile(raw []byte, card Card) (wfcProfile, bool, error) {
	var profiles []wfcProfile
	if err := json.Unmarshal(raw, &profiles); err != nil {
		return wfcProfile{}, false, fmt.Errorf("loading wfc config: decode json: %w", err)
	}

	mcc := strings.TrimSpace(card.MCC())
	mnc := strings.TrimSpace(card.MNC())
	mncLength := cardMNCLength(card)
	gid1 := cardGID1(card)
	for _, profile := range profiles {
		if profile.GID1 == "" {
			continue
		}
		if samePLMNDigits(profile.MCC, profile.MNC, mcc, mnc, mncLength) && sameGID1(profile.GID1, gid1) {
			return profile, true, nil
		}
	}
	for _, profile := range profiles {
		if profile.GID1 != "" {
			continue
		}
		if samePLMNDigits(profile.MCC, profile.MNC, mcc, mnc, mncLength) {
			return profile, true, nil
		}
	}
	return wfcProfile{}, false, nil
}

type mncLengthCard interface {
	MNCLength() int
}

func cardMNCLength(card Card) int {
	lengthCard, ok := card.(mncLengthCard)
	if !ok {
		return 0
	}
	return lengthCard.MNCLength()
}

type gid1Card interface {
	GID1() string
}

func cardGID1(card Card) string {
	gid1Card, ok := card.(gid1Card)
	if !ok {
		return ""
	}
	return normalizeGID1(gid1Card.GID1())
}

func samePLMNDigits(profileMCC, profileMNC, cardMCC, cardMNC string, cardMNCLength int) bool {
	profileMCC = strings.TrimSpace(profileMCC)
	cardMCC = strings.TrimSpace(cardMCC)
	if profileMCC != cardMCC {
		return false
	}

	profileMNC = strings.TrimSpace(profileMNC)
	cardMNC = strings.TrimSpace(cardMNC)
	if profileMNC == cardMNC {
		return true
	}
	if cardMNCLength != 2 || len(profileMNC) != 2 || len(cardMNC) != 3 {
		return false
	}
	return cardMNC[0] == '0' && profileMNC == cardMNC[1:]
}

func sameGID1(profileGID1, cardGID1 string) bool {
	profileGID1 = normalizeGID1(profileGID1)
	if profileGID1 == "" || cardGID1 == "" {
		return false
	}
	return strings.HasPrefix(cardGID1, profileGID1)
}

func normalizeGID1(gid1 string) string {
	gid1 = strings.TrimSpace(gid1)
	gid1 = strings.TrimPrefix(gid1, "0x")
	gid1 = strings.TrimPrefix(gid1, "0X")
	return strings.ToUpper(gid1)
}

func (cfg Config) withWFCProfile(profile wfcProfile, card Card) Config {
	if cfg.EPDG == "" {
		cfg.EPDG = firstNonEmpty(profile.EPDG, profile.EPDGAddresses...)
	}

	if cfg.Tunnel.InitialPort == 0 {
		cfg.Tunnel.InitialPort = profile.InitialPort
	}
	if cfg.Tunnel.NATTPort == 0 {
		cfg.Tunnel.NATTPort = profile.NATTPort
	}
	if cfg.Tunnel.LocalSIPPort == 0 {
		cfg.Tunnel.LocalSIPPort = profile.LocalSIPPort
	}
	if cfg.Tunnel.SIPPort == 0 {
		cfg.Tunnel.SIPPort = firstNonZero(profile.SIPPort, profile.IMSSIPServerPort)
	}
	if len(cfg.Tunnel.DHGroups) == 0 {
		cfg.Tunnel.DHGroups = cloneUint16s(profile.DHGroups)
	}
	if len(cfg.Tunnel.IKEEncryptionKeyLens) == 0 {
		cfg.Tunnel.IKEEncryptionKeyLens = cloneUint16s(profile.IKEEncryptionKeyLens)
	}
	if len(cfg.Tunnel.IKEIntegrity) == 0 {
		cfg.Tunnel.IKEIntegrity = cloneUint16s(profile.IKEIntegrity)
	}
	if len(cfg.Tunnel.IKEPRF) == 0 {
		cfg.Tunnel.IKEPRF = cloneUint16s(profile.IKEPRF)
	}
	if len(cfg.Tunnel.ChildEncryptionKeyLens) == 0 {
		cfg.Tunnel.ChildEncryptionKeyLens = cloneUint16s(profile.ChildEncryptionKeyLens)
	}
	if len(cfg.Tunnel.ChildIntegrity) == 0 {
		cfg.Tunnel.ChildIntegrity = cloneUint16s(profile.ChildIntegrity)
	}
	if cfg.Tunnel.PCSCFIPv4ConfigAttribute == 0 {
		cfg.Tunnel.PCSCFIPv4ConfigAttribute = profile.PCSCFIPv4ConfigAttribute
	}
	if cfg.Tunnel.PCSCFIPv6ConfigAttribute == 0 {
		cfg.Tunnel.PCSCFIPv6ConfigAttribute = profile.PCSCFIPv6ConfigAttribute
	}
	if cfg.Tunnel.NATKeepaliveInterval == 0 {
		cfg.Tunnel.NATKeepaliveInterval = wfcProfileDuration(profile.NATKeepaliveInterval, profile.AndroidNATKeepaliveSeconds)
	}
	if cfg.Tunnel.LivenessTimeout == 0 {
		cfg.Tunnel.LivenessTimeout = wfcSecondsDuration(profile.AndroidDPDSeconds)
	}
	if len(cfg.Tunnel.IKERetransmitDelays) == 0 {
		cfg.Tunnel.IKERetransmitDelays = wfcIKEReTransmitDelays(profile)
	}
	if cfg.Tunnel.IKESALifetime == 0 {
		cfg.Tunnel.IKESALifetime, cfg.Tunnel.IKESARekeyMargin = saLifetimeFromWFCRekeyTimers(
			profile.IKESARekeySoftTime,
			profile.IKESARekeyHardTime,
			profile.IKESARekeyTime,
			profile.AndroidIKESARekeySoftSecs,
			profile.AndroidIKESARekeyHardSecs,
		)
	}
	if cfg.Tunnel.ChildSALifetime == 0 {
		cfg.Tunnel.ChildSALifetime, cfg.Tunnel.ChildSARekeyMargin = saLifetimeFromWFCRekeyTimers(
			profile.ChildSARekeySoftTime,
			profile.ChildSARekeyHardTime,
			profile.ChildSARekeyTime,
			profile.AndroidChildSARekeySoftSec,
			profile.AndroidChildSARekeyHardSec,
		)
	}
	if !cfg.Tunnel.AddKEToChildSARekey {
		if addKE, ok := wfcAddKEToChildSARekey(profile); ok {
			cfg.Tunnel.AddKEToChildSARekey = addKE
		}
	}

	if strings.TrimSpace(cfg.IMS.Transport) == "" {
		cfg.IMS.Transport = profile.IMSTransport
	}
	if strings.TrimSpace(cfg.IMS.HomeDomain) == "" {
		cfg.IMS.HomeDomain = profile.IMSHomeDomain
	}
	if strings.TrimSpace(cfg.IMS.PrivateIdentity) == "" {
		cfg.IMS.PrivateIdentity = renderWFCIdentity(profile.IMSPrivateIdentity, cfg, card)
	}
	if strings.TrimSpace(cfg.IMS.PublicIdentity) == "" {
		cfg.IMS.PublicIdentity = renderWFCIdentity(profile.IMSPublicIdentity, cfg, card)
	}
	if strings.TrimSpace(cfg.IMS.PhoneContextDomain) == "" {
		cfg.IMS.PhoneContextDomain = profile.IMSPhoneContextDomain
	}
	if strings.TrimSpace(cfg.IMS.AccessNetworkInfo) == "" {
		cfg.IMS.AccessNetworkInfo = profile.IMSAccessNetworkInfo
	}
	if strings.TrimSpace(cfg.IMS.UserAgent) == "" {
		cfg.IMS.UserAgent = renderWFCUserAgent(profile.IMSUserAgent, cfg, profile)
	}
	if cfg.IMS.RegisterExpires == 0 && profile.IMSRegisterExpires != nil {
		cfg.IMS.RegisterExpires = profile.IMSRegisterExpires.Duration
	}
	if cfg.IMS.RegistrationRetryBase == 0 {
		cfg.IMS.RegistrationRetryBase = wfcProfileMillisDuration(profile.IMSRegistrationRetryBase, profile.AndroidIMSRetryBaseMS)
	}
	if cfg.IMS.RegistrationRetryMax == 0 {
		cfg.IMS.RegistrationRetryMax = wfcProfileMillisDuration(profile.IMSRegistrationRetryMax, profile.AndroidIMSRetryMaxMS)
	}
	if len(cfg.IMS.Voice.GeolocationPIDFInvite) == 0 {
		cfg.IMS.Voice.GeolocationPIDFInvite = cloneInts(profile.IMSGeolocationPIDFInvite)
	}
	if len(cfg.IMS.GeolocationPIDFRegister) == 0 {
		cfg.IMS.GeolocationPIDFRegister = cloneInts(profile.IMSGeolocationPIDFRegister)
	}
	if !cfg.IMS.UseTelURIForPIDFXML && profile.IMSUseTelURIForPIDFXML != nil {
		cfg.IMS.UseTelURIForPIDFXML = *profile.IMSUseTelURIForPIDFXML
	}
	if cfg.IMS.SIPServerPort == 0 {
		cfg.IMS.SIPServerPort = firstNonZero(profile.IMSSIPServerPort, profile.SIPPort)
	}
	if cfg.IMS.SIPTimers.T1 == 0 && profile.IMSSIPTimerT1 != nil {
		cfg.IMS.SIPTimers.T1 = profile.IMSSIPTimerT1.Duration
	}
	if cfg.IMS.SIPTimers.T2 == 0 && profile.IMSSIPTimerT2 != nil {
		cfg.IMS.SIPTimers.T2 = profile.IMSSIPTimerT2.Duration
	}
	if cfg.IMS.SIPTimers.T4 == 0 && profile.IMSSIPTimerT4 != nil {
		cfg.IMS.SIPTimers.T4 = profile.IMSSIPTimerT4.Duration
	}
	if cfg.IMS.SIPTimers.TB == 0 && profile.IMSSIPTimerB != nil {
		cfg.IMS.SIPTimers.TB = profile.IMSSIPTimerB.Duration
	}
	if cfg.IMS.SIPTimers.TD == 0 && profile.IMSSIPTimerD != nil {
		cfg.IMS.SIPTimers.TD = profile.IMSSIPTimerD.Duration
	}
	if cfg.IMS.SIPTimers.TF == 0 && profile.IMSSIPTimerF != nil {
		cfg.IMS.SIPTimers.TF = profile.IMSSIPTimerF.Duration
	}
	if cfg.IMS.SIPTimers.TH == 0 && profile.IMSSIPTimerH != nil {
		cfg.IMS.SIPTimers.TH = profile.IMSSIPTimerH.Duration
	}
	if cfg.IMS.SIPTimers.TJ == 0 && profile.IMSSIPTimerJ != nil {
		cfg.IMS.SIPTimers.TJ = profile.IMSSIPTimerJ.Duration
	}
	cfg.smsRequestStatusReport = wfcSMSDeliveryReports(profile)
	cfg = cfg.withWFCVoiceProfile(profile.IMSVoice)
	return cfg
}

func wfcSMSDeliveryReports(profile wfcProfile) bool {
	if profile.EnableSMSDeliveryReports == nil {
		return true
	}
	return *profile.EnableSMSDeliveryReports
}

func (cfg Config) withWFCVoiceProfile(profile *wfcVoiceProfile) Config {
	if profile == nil {
		return cfg
	}
	if strings.TrimSpace(cfg.IMS.Voice.RTPProfile) == "" {
		cfg.IMS.Voice.RTPProfile = profile.RTPProfile
	}
	if cfg.IMS.Voice.PTime == 0 && profile.PTime != nil {
		cfg.IMS.Voice.PTime = profile.PTime.Duration
	}
	if cfg.IMS.Voice.MaxPTime == 0 && profile.MaxPTime != nil {
		cfg.IMS.Voice.MaxPTime = profile.MaxPTime.Duration
	}
	if strings.TrimSpace(cfg.IMS.Voice.GeolocationCountry) == "" {
		cfg.IMS.Voice.GeolocationCountry = profile.GeolocationCountry
	}
	if len(cfg.IMS.Voice.PIDFShortCodes) == 0 {
		cfg.IMS.Voice.PIDFShortCodes = cloneStrings(profile.PIDFShortCodes)
	}
	if !cfg.IMS.Voice.ReliableProvisional && profile.ReliableProvisionalSupported != nil {
		cfg.IMS.Voice.ReliableProvisional = *profile.ReliableProvisionalSupported
	}
	if !cfg.IMS.Voice.SessionTimer && profile.SessionTimer != nil {
		cfg.IMS.Voice.SessionTimer = *profile.SessionTimer
	}
	if cfg.IMS.Voice.SessionExpires == 0 && profile.SessionExpires != nil {
		cfg.IMS.Voice.SessionExpires = profile.SessionExpires.Duration
	}
	if cfg.IMS.Voice.MinSessionExpires == 0 && profile.MinimumSessionExpires != nil {
		cfg.IMS.Voice.MinSessionExpires = profile.MinimumSessionExpires.Duration
	}
	if strings.TrimSpace(cfg.IMS.Voice.SessionRefresher) == "" {
		cfg.IMS.Voice.SessionRefresher = profile.SessionRefresher
	}
	if cfg.IMS.Voice.MOCallRequestTimeout == 0 && profile.MOCallRequestTimeout != nil {
		cfg.IMS.Voice.MOCallRequestTimeout = profile.MOCallRequestTimeout.Duration
	}
	if cfg.IMS.Voice.RingbackTimeout == 0 && profile.RingbackTimer != nil {
		cfg.IMS.Voice.RingbackTimeout = profile.RingbackTimer.Duration
	}
	if cfg.IMS.Voice.RingingTimeout == 0 && profile.RingingTimer != nil {
		cfg.IMS.Voice.RingingTimeout = profile.RingingTimer.Duration
	}
	if cfg.IMS.Voice.AudioASBandwidthKbps == 0 {
		cfg.IMS.Voice.AudioASBandwidthKbps = profile.AudioASBandwidthKbps
	}
	if cfg.IMS.Voice.RTPInactivityTimeout == 0 && profile.RTPInactivityTimeout != nil {
		cfg.IMS.Voice.RTPInactivityTimeout = profile.RTPInactivityTimeout.Duration
	}
	if cfg.IMS.Voice.RTCPInactivityTimeout == 0 && profile.RTCPInactivityTimeout != nil {
		cfg.IMS.Voice.RTCPInactivityTimeout = profile.RTCPInactivityTimeout.Duration
	}
	if cfg.IMS.Voice.AudioInactivityCallEndReasons == nil && profile.AudioInactivityCallEndReasons != nil {
		cfg.IMS.Voice.AudioInactivityCallEndReasons = append([]imsvoice.AudioInactivityCallEndReason(nil), profile.AudioInactivityCallEndReasons...)
	}
	if cfg.IMS.Voice.RTCPSendInterval == 0 && profile.RTCPSendInterval != nil {
		cfg.IMS.Voice.RTCPSendInterval = profile.RTCPSendInterval.Duration
	}
	if cfg.IMS.Voice.LocalRTPPortMin == 0 {
		cfg.IMS.Voice.LocalRTPPortMin = profile.LocalRTPPortMin
	}
	if cfg.IMS.Voice.LocalRTPPortMax == 0 {
		cfg.IMS.Voice.LocalRTPPortMax = profile.LocalRTPPortMax
	}
	if len(cfg.IMS.Voice.Codecs) == 0 {
		cfg.IMS.Voice.Codecs = wfcVoiceCodecs(profile)
	}
	return cfg
}

func wfcVoiceCodecs(profile *wfcVoiceProfile) []imsvoice.AudioCodecConfig {
	if profile == nil || len(profile.Codecs) == 0 {
		return nil
	}
	out := make([]imsvoice.AudioCodecConfig, 0, len(profile.Codecs))
	for _, codec := range profile.Codecs {
		voiceCodec := imsvoice.AudioCodecConfig{
			Name:         codec.Name,
			PayloadTypes: append([]int(nil), codec.PayloadTypes...),
			ClockRate:    codec.ClockRate,
			Channels:     codec.Channels,
			OctetAlign:   codec.OctetAlign,
			ModeSet:      codec.ModeSet,
			Bitrate:      codec.Bitrate,
			Bandwidth:    codec.Bandwidth,
		}
		if strings.EqualFold(string(codec.Name), string(imsvoice.CodecEVS)) {
			applyWFCVoiceEVSDescription(&voiceCodec, profile.EVSPayloadDescriptions)
		}
		out = append(out, voiceCodec)
	}
	return out
}

func applyWFCVoiceEVSDescription(codec *imsvoice.AudioCodecConfig, descriptions map[string]wfcEVSPayloadDescription) {
	if len(codec.PayloadTypes) == 0 || len(descriptions) == 0 {
		return
	}
	desc, ok := descriptions[fmt.Sprint(codec.PayloadTypes[0])]
	if !ok {
		return
	}
	if codec.Bitrate == "" {
		codec.Bitrate = strings.TrimSpace(desc.Bitrate)
	}
	if codec.Bandwidth == "" {
		codec.Bandwidth = strings.TrimSpace(desc.Bandwidth)
	}
	if desc.ChannelAwareReceive != nil && validEVSChannelAwareReceive(*desc.ChannelAwareReceive) {
		value := *desc.ChannelAwareReceive
		codec.ChAwRecv = &value
	}
}

func validEVSChannelAwareReceive(value int) bool {
	switch value {
	case -1, 0, 2, 3, 5, 7:
		return true
	default:
		return false
	}
}

func renderWFCIdentity(template string, cfg Config, card Card) string {
	template = strings.TrimSpace(template)
	if template == "" {
		return ""
	}
	replacer := strings.NewReplacer(
		"#IMSI#", strings.TrimSpace(card.IMSI()),
		"#MCC#", strings.TrimSpace(card.MCC()),
		"#MNC#", strings.TrimSpace(card.MNC()),
		"#HOME_DOMAIN#", strings.TrimSpace(cfg.IMS.HomeDomain),
	)
	return replacer.Replace(template)
}

func firstNonEmpty(first string, rest ...string) string {
	if value := strings.TrimSpace(first); value != "" {
		return value
	}
	for _, value := range rest {
		if value := strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func firstNonZero(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func cloneUint16s(values []uint16) []uint16 {
	if len(values) == 0 {
		return nil
	}
	return append([]uint16(nil), values...)
}

func cloneInts(values []int) []int {
	if len(values) == 0 {
		return nil
	}
	return append([]int(nil), values...)
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func wfcDurations(values []wfcDuration) []time.Duration {
	if len(values) == 0 {
		return nil
	}
	durations := make([]time.Duration, 0, len(values))
	for _, value := range values {
		durations = append(durations, value.Duration)
	}
	return durations
}

func wfcIKEReTransmitDelays(profile wfcProfile) []time.Duration {
	if len(profile.IKERetransmitDelays) != 0 {
		return wfcDurations(profile.IKERetransmitDelays)
	}
	if len(profile.AndroidIKERetransmitMS) == 0 {
		return nil
	}
	delays := make([]time.Duration, 0, len(profile.AndroidIKERetransmitMS))
	for _, ms := range profile.AndroidIKERetransmitMS {
		delays = append(delays, time.Duration(ms)*time.Millisecond)
	}
	return delays
}

func saLifetimeFromWFCRekeyTimers(soft, hard, legacySoft *wfcDuration, androidSoft, androidHard *int) (time.Duration, time.Duration) {
	softTime := firstPositiveDuration(
		wfcDurationValue(soft),
		wfcDurationValue(legacySoft),
		wfcSecondsDuration(androidSoft),
	)
	if softTime <= 0 {
		return 0, 0
	}
	hardTime := firstPositiveDuration(wfcDurationValue(hard), wfcSecondsDuration(androidHard))
	if hardTime <= softTime {
		hardTime = softTime + swuSARekeyMargin(softTime)
	}
	return hardTime, hardTime - softTime
}

func wfcProfileDuration(normalized *wfcDuration, androidSeconds *int) time.Duration {
	return firstPositiveDuration(wfcDurationValue(normalized), wfcSecondsDuration(androidSeconds))
}

func wfcProfileMillisDuration(normalized *wfcDuration, androidMillis *int) time.Duration {
	return firstPositiveDuration(wfcDurationValue(normalized), wfcMillisDuration(androidMillis))
}

func wfcDurationValue(value *wfcDuration) time.Duration {
	if value == nil {
		return 0
	}
	return value.Duration
}

func wfcSecondsDuration(seconds *int) time.Duration {
	if seconds == nil || *seconds <= 0 {
		return 0
	}
	return time.Duration(*seconds) * time.Second
}

func wfcMillisDuration(millis *int) time.Duration {
	if millis == nil || *millis <= 0 {
		return 0
	}
	return time.Duration(*millis) * time.Millisecond
}

func firstPositiveDuration(values ...time.Duration) time.Duration {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func wfcAddKEToChildSARekey(profile wfcProfile) (bool, bool) {
	if profile.AddKEToChildSARekey != nil {
		return *profile.AddKEToChildSARekey, true
	}
	if profile.AndroidAddKEToChildRekey != nil {
		return *profile.AndroidAddKEToChildRekey, true
	}
	return false, false
}

func swuSARekeyMargin(rekeyTime time.Duration) time.Duration {
	margin := rekeyTime / 10
	if margin > 5*time.Minute {
		return 5 * time.Minute
	}
	if margin <= 0 {
		return rekeyTime / 2
	}
	return margin
}
