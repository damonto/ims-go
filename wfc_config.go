package ims

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	imsvoice "github.com/damonto/ims-go/ims/voice"
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
	LivenessTimeout            *wfcDuration     `json:"livenessTimeout"`
	IKESALifetime              *wfcDuration     `json:"ikeSALifetime"`
	IKERetransmitDelays        []wfcDuration    `json:"ikeRetransmitDelays"`
	IKESARekeySoftTime         *wfcDuration     `json:"ikeSARekeySoftTime"`
	IKESARekeyHardTime         *wfcDuration     `json:"ikeSARekeyHardTime"`
	IKESARekeyTime             *wfcDuration     `json:"ikeSARekeyTime"`
	ChildSALifetime            *wfcDuration     `json:"childSALifetime"`
	ChildSARekeySoftTime       *wfcDuration     `json:"childSARekeySoftTime"`
	ChildSARekeyHardTime       *wfcDuration     `json:"childSARekeyHardTime"`
	ChildSARekeyTime           *wfcDuration     `json:"childSARekeyTime"`
	AddKEToChildSARekey        *bool            `json:"addKEToChildSARekey"`
	IMSTransport               string           `json:"imsTransport"`
	IMSHomeDomain              string           `json:"imsHomeDomain"`
	IMSPublicIdentity          string           `json:"imsPublicIdentity"`
	IMSPhoneContextDomain      string           `json:"imsPhoneContextDomain"`
	IMSAccessNetworkInfo       string           `json:"imsAccessNetworkInfo"`
	IMSUserAgent               string           `json:"imsUserAgent"`
	IMSRegisterExpires         *wfcDuration     `json:"imsRegisterExpires"`
	IMSRegistrationRetryBase   *wfcDuration     `json:"imsRegistrationRetryBase"`
	IMSRegistrationRetryMax    *wfcDuration     `json:"imsRegistrationRetryMax"`
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
	if cfg.Access.VoWiFi == nil {
		cfg.Access.VoWiFi = &VoWiFiConfig{}
	}
	wifi := cfg.Access.VoWiFi
	if wifi.EPDG == "" {
		wifi.EPDG = firstNonEmpty(profile.EPDG, profile.EPDGAddresses...)
	}

	if wifi.Tunnel.InitialPort == 0 {
		wifi.Tunnel.InitialPort = profile.InitialPort
	}
	if wifi.Tunnel.NATTPort == 0 {
		wifi.Tunnel.NATTPort = profile.NATTPort
	}
	if wifi.Tunnel.LocalSIPPort == 0 {
		wifi.Tunnel.LocalSIPPort = profile.LocalSIPPort
	}
	if wifi.Tunnel.SIPPort == 0 {
		wifi.Tunnel.SIPPort = firstNonZero(profile.SIPPort, profile.IMSSIPServerPort)
	}
	if len(wifi.Tunnel.DHGroups) == 0 {
		wifi.Tunnel.DHGroups = cloneUint16s(profile.DHGroups)
	}
	if len(wifi.Tunnel.IKEEncryptionKeyLens) == 0 {
		wifi.Tunnel.IKEEncryptionKeyLens = cloneUint16s(profile.IKEEncryptionKeyLens)
	}
	if len(wifi.Tunnel.IKEIntegrity) == 0 {
		wifi.Tunnel.IKEIntegrity = cloneUint16s(profile.IKEIntegrity)
	}
	if len(wifi.Tunnel.IKEPRF) == 0 {
		wifi.Tunnel.IKEPRF = cloneUint16s(profile.IKEPRF)
	}
	if len(wifi.Tunnel.ChildEncryptionKeyLens) == 0 {
		wifi.Tunnel.ChildEncryptionKeyLens = cloneUint16s(profile.ChildEncryptionKeyLens)
	}
	if len(wifi.Tunnel.ChildIntegrity) == 0 {
		wifi.Tunnel.ChildIntegrity = cloneUint16s(profile.ChildIntegrity)
	}
	if wifi.Tunnel.PCSCFIPv4ConfigAttribute == 0 {
		wifi.Tunnel.PCSCFIPv4ConfigAttribute = profile.PCSCFIPv4ConfigAttribute
	}
	if wifi.Tunnel.PCSCFIPv6ConfigAttribute == 0 {
		wifi.Tunnel.PCSCFIPv6ConfigAttribute = profile.PCSCFIPv6ConfigAttribute
	}
	if wifi.Tunnel.NATKeepaliveInterval == 0 {
		wifi.Tunnel.NATKeepaliveInterval = wfcDurationValue(profile.NATKeepaliveInterval)
	}
	if wifi.Tunnel.LivenessTimeout == 0 && profile.LivenessTimeout != nil {
		wifi.Tunnel.LivenessTimeout = profile.LivenessTimeout.Duration
	}
	if len(wifi.Tunnel.IKERetransmitDelays) == 0 {
		wifi.Tunnel.IKERetransmitDelays = wfcIKEReTransmitDelays(profile)
	}
	if wifi.Tunnel.IKESALifetime == 0 {
		wifi.Tunnel.IKESALifetime, wifi.Tunnel.IKESARekeyMargin = saLifetimeFromWFCProfile(
			profile.IKESALifetime,
			profile.IKESARekeySoftTime,
			profile.IKESARekeyHardTime,
			profile.IKESARekeyTime,
		)
	}
	if wifi.Tunnel.ChildSALifetime == 0 {
		wifi.Tunnel.ChildSALifetime, wifi.Tunnel.ChildSARekeyMargin = saLifetimeFromWFCProfile(
			profile.ChildSALifetime,
			profile.ChildSARekeySoftTime,
			profile.ChildSARekeyHardTime,
			profile.ChildSARekeyTime,
		)
	}
	if !wifi.Tunnel.AddKEToChildSARekey {
		if addKE, ok := wfcAddKEToChildSARekey(profile); ok {
			wifi.Tunnel.AddKEToChildSARekey = addKE
		}
	}

	if strings.TrimSpace(cfg.IMS.Transport) == "" {
		cfg.IMS.Transport = profile.IMSTransport
	}
	if strings.TrimSpace(cfg.IMS.HomeDomain) == "" {
		cfg.IMS.HomeDomain = profile.IMSHomeDomain
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
		cfg.IMS.RegistrationRetryBase = wfcDurationValue(profile.IMSRegistrationRetryBase)
	}
	if cfg.IMS.RegistrationRetryMax == 0 {
		cfg.IMS.RegistrationRetryMax = wfcDurationValue(profile.IMSRegistrationRetryMax)
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
	if cfg.IMS.Voice.RTPInactivityTimeout == nil && profile.RTPInactivityTimeout != nil {
		cfg.IMS.Voice.RTPInactivityTimeout = imsvoice.Duration(profile.RTPInactivityTimeout.Duration)
	}
	if cfg.IMS.Voice.RTCPInactivityTimeout == nil && profile.RTCPInactivityTimeout != nil {
		cfg.IMS.Voice.RTCPInactivityTimeout = imsvoice.Duration(profile.RTCPInactivityTimeout.Duration)
	}
	if cfg.IMS.Voice.AudioInactivityCallEndReasons == nil && profile.AudioInactivityCallEndReasons != nil {
		cfg.IMS.Voice.AudioInactivityCallEndReasons = append([]imsvoice.AudioInactivityCallEndReason(nil), profile.AudioInactivityCallEndReasons...)
	}
	if cfg.IMS.Voice.RTCPSendInterval == nil && profile.RTCPSendInterval != nil {
		cfg.IMS.Voice.RTCPSendInterval = imsvoice.Duration(profile.RTCPSendInterval.Duration)
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
	return nil
}

func saLifetimeFromWFCProfile(lifetime, soft, hard, legacySoft *wfcDuration) (time.Duration, time.Duration) {
	hardTime := wfcDurationValue(lifetime)
	if hardTime > 0 {
		softTime := wfcRekeySoftTime(hardTime, legacySoft)
		if softTime <= 0 {
			return hardTime, swuSARekeyMargin(hardTime)
		}
		return hardTime, hardTime - softTime
	}

	legacyTime := wfcDurationValue(legacySoft)
	if legacyTime > 0 {
		hardTime = legacyTime + swuSARekeyMargin(legacyTime)
		return hardTime, hardTime - legacyTime
	}

	hardTime = wfcDurationValue(hard)
	softTime := wfcRekeySoftTime(hardTime, soft)
	if hardTime <= 0 {
		if softTime <= 0 {
			return 0, 0
		}
		hardTime = softTime + swuSARekeyMargin(softTime)
	}
	if softTime <= 0 {
		return hardTime, swuSARekeyMargin(hardTime)
	}
	return hardTime, hardTime - softTime
}

func wfcRekeySoftTime(hardTime time.Duration, values ...*wfcDuration) time.Duration {
	for _, value := range values {
		rekeyTime := wfcDurationValue(value)
		if rekeyTime <= 0 {
			continue
		}
		if hardTime > 0 && rekeyTime >= hardTime {
			continue
		}
		return rekeyTime
	}
	return 0
}

func wfcDurationValue(value *wfcDuration) time.Duration {
	if value == nil {
		return 0
	}
	return value.Duration
}

func wfcAddKEToChildSARekey(profile wfcProfile) (bool, bool) {
	if profile.AddKEToChildSARekey != nil {
		return *profile.AddKEToChildSARekey, true
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
