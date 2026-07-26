package ims

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	imsvoice "github.com/damonto/ims-go/ims/voice"
)

//go:embed ims.json
var embeddedIMSConfig []byte

type imsProfile struct {
	MCC                          string                    `json:"mcc"`
	MNC                          string                    `json:"mnc"`
	IMSIPrefix                   string                    `json:"imsiPrefix"`
	ICCIDPrefix                  string                    `json:"iccidPrefix"`
	SPN                          string                    `json:"spn"`
	GID1                         string                    `json:"gid1"`
	GID2                         string                    `json:"gid2"`
	EPDG                         string                    `json:"epdg"`
	EPDGAddresses                []string                  `json:"epdgAddresses"`
	InitialPort                  int                       `json:"initialPort"`
	NATTPort                     int                       `json:"nattPort"`
	SIPPort                      int                       `json:"sipPort"`
	DHGroups                     []uint16                  `json:"dhGroups"`
	IKEEncryption                []uint16                  `json:"ikeEncryption"`
	IKEEncryptionKeyLens         []uint16                  `json:"ikeEncryptionKeyLens"`
	IKEEncryptionAESCTRKeyLens   []uint16                  `json:"ikeEncryptionAESCTRKeyLens"`
	IKEIntegrity                 []uint16                  `json:"ikeIntegrity"`
	IKEPRF                       []uint16                  `json:"ikePRF"`
	ChildEncryption              []uint16                  `json:"childEncryption"`
	ChildEncryptionKeyLens       []uint16                  `json:"childEncryptionKeyLens"`
	ChildEncryptionAESCTRKeyLens []uint16                  `json:"childEncryptionAESCTRKeyLens"`
	ChildIntegrity               []uint16                  `json:"childIntegrity"`
	PCSCFIPv4ConfigAttribute     uint16                    `json:"pcscfIPv4ConfigAttribute"`
	PCSCFIPv6ConfigAttribute     uint16                    `json:"pcscfIPv6ConfigAttribute"`
	NATKeepaliveInterval         imsProfileDuration        `json:"natKeepaliveInterval"`
	LivenessTimeout              imsProfileDuration        `json:"livenessTimeout"`
	IKESALifetime                imsProfileDuration        `json:"ikeSALifetime"`
	IKERetransmitDelays          []imsProfileDuration      `json:"ikeRetransmitDelays"`
	IKESARekeySoftTime           imsProfileDuration        `json:"ikeSARekeySoftTime"`
	IKESARekeyHardTime           imsProfileDuration        `json:"ikeSARekeyHardTime"`
	IKESARekeyTime               imsProfileDuration        `json:"ikeSARekeyTime"`
	ChildSALifetime              imsProfileDuration        `json:"childSALifetime"`
	ChildSARekeySoftTime         imsProfileDuration        `json:"childSARekeySoftTime"`
	ChildSARekeyHardTime         imsProfileDuration        `json:"childSARekeyHardTime"`
	ChildSARekeyTime             imsProfileDuration        `json:"childSARekeyTime"`
	AddKEToChildSARekey          bool                      `json:"addKEToChildSARekey"`
	IMSTransport                 string                    `json:"imsTransport"`
	IMSHomeDomain                string                    `json:"imsHomeDomain"`
	IMSPublicIdentity            string                    `json:"imsPublicIdentity"`
	IMSPhoneContextDomain        string                    `json:"imsPhoneContextDomain"`
	IMSAccessNetworkInfo         string                    `json:"imsAccessNetworkInfo"`
	IMSUserAgent                 string                    `json:"imsUserAgent"`
	IMSRegisterExpires           imsProfileDuration        `json:"imsRegisterExpires"`
	IMSRegistrationRetryBase     imsProfileDuration        `json:"imsRegistrationRetryBase"`
	IMSRegistrationRetryMax      imsProfileDuration        `json:"imsRegistrationRetryMax"`
	IMSIPSecIntegrityAlgorithms  []string                  `json:"imsIPSecIntegrityAlgorithms"`
	IMSIPSecEncryptionAlgorithms []string                  `json:"imsIPSecEncryptionAlgorithms"`
	IMSIPSecModes                []string                  `json:"imsIPSecModes"`
	IMSGeolocationPIDFInvite     []int                     `json:"imsGeolocationPIDFInSIPInviteSupport"`
	IMSGeolocationPIDFRegister   []int                     `json:"imsGeolocationPIDFInSIPRegisterSupport"`
	IMSUseTelURIForPIDFXML       bool                      `json:"imsUseTelURIForPIDFXML"`
	IMSRequestURIFormat          imsvoice.RequestURIFormat `json:"imsRequestURIFormat"`
	IMSSIPServerPort             int                       `json:"imsSIPServerPort"`
	IMSSIPTimerT1                imsProfileDuration        `json:"imsSIPTimerT1"`
	IMSSIPTimerT2                imsProfileDuration        `json:"imsSIPTimerT2"`
	IMSSIPTimerT4                imsProfileDuration        `json:"imsSIPTimerT4"`
	IMSSIPTimerB                 imsProfileDuration        `json:"imsSIPTimerB"`
	IMSSIPTimerD                 imsProfileDuration        `json:"imsSIPTimerD"`
	IMSSIPTimerF                 imsProfileDuration        `json:"imsSIPTimerF"`
	IMSSIPTimerH                 imsProfileDuration        `json:"imsSIPTimerH"`
	IMSSIPTimerJ                 imsProfileDuration        `json:"imsSIPTimerJ"`
	EnableSMSDeliveryReports     bool                      `json:"enableSMSDeliveryReports"`
	IMSVoice                     imsVoiceProfile           `json:"imsVoice"`
	WFCSPN                       string                    `json:"wfcSPN"`
}

type imsVoiceProfile struct {
	RTPProfile                    string                                  `json:"rtpProfile"`
	PTime                         imsProfileDuration                      `json:"ptime"`
	MaxPTime                      imsProfileDuration                      `json:"maxptime"`
	GeolocationCountry            string                                  `json:"geolocationCountry"`
	PIDFShortCodes                []string                                `json:"pidfShortCodes"`
	QoSPreconditionsSupported     bool                                    `json:"qosPreconditionsSupported"`
	ReliableProvisionalSupported  bool                                    `json:"reliableProvisionalSupported"`
	SessionTimer                  bool                                    `json:"sessionTimer"`
	SessionExpires                imsProfileDuration                      `json:"sessionExpires"`
	MinimumSessionExpires         imsProfileDuration                      `json:"minimumSessionExpires"`
	SessionRefresher              string                                  `json:"sessionRefresher"`
	MOCallRequestTimeout          imsProfileDuration                      `json:"moCallRequestTimeout"`
	RingbackTimer                 imsProfileDuration                      `json:"ringbackTimer"`
	RingingTimer                  imsProfileDuration                      `json:"ringingTimer"`
	AudioASBandwidthKbps          int                                     `json:"audioASBandwidthKbps"`
	RTPInactivityTimeout          imsProfileDuration                      `json:"rtpInactivityTimeout"`
	RTCPInactivityTimeout         imsProfileDuration                      `json:"rtcpInactivityTimeout"`
	AudioInactivityCallEndReasons []imsvoice.AudioInactivityCallEndReason `json:"audioInactivityCallEndReasons"`
	LocalRTPPortMin               int                                     `json:"localRTPPortMin"`
	LocalRTPPortMax               int                                     `json:"localRTPPortMax"`
	Codecs                        []imsVoiceCodecProfile                  `json:"codecs"`
	EVSPayloadDescriptions        map[string]imsEVSPayloadDescription     `json:"evsPayloadDescriptions"`
}

type imsVoiceCodecProfile struct {
	Name         imsvoice.AudioCodec `json:"name"`
	PayloadTypes []int               `json:"payloadTypes"`
	ClockRate    int                 `json:"clockRate"`
	Channels     int                 `json:"channels"`
	ModeSet      string              `json:"modeSet"`
	Bitrate      string              `json:"bitrate"`
	Bandwidth    string              `json:"bandwidth"`
	OctetAlign   bool                `json:"octetAlign"`
}

type imsEVSPayloadDescription struct {
	Bitrate             string `json:"bitrate"`
	Bandwidth           string `json:"bandwidth"`
	ChannelAwareReceive int    `json:"channelAwareReceive"`
}

type imsProfileDuration struct {
	time.Duration
}

func (d *imsProfileDuration) UnmarshalJSON(data []byte) error {
	value := strings.TrimSpace(string(data))
	if value == "null" {
		return fmt.Errorf("profile duration cannot be null")
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

func loadIMSProfile(card Card) (imsProfile, bool, error) {
	profile, ok, err := parseIMSProfile(embeddedIMSConfig, card)
	if err != nil || !ok {
		return profile, ok, err
	}
	if len(profile.IMSIPSecIntegrityAlgorithms) == 0 {
		return imsProfile{}, false, fmt.Errorf("ims carrier profile %s-%s has no IPsec integrity algorithms", profile.MCC, profile.MNC)
	}
	if len(profile.IMSIPSecEncryptionAlgorithms) == 0 {
		return imsProfile{}, false, fmt.Errorf("ims carrier profile %s-%s has no IPsec encryption algorithms", profile.MCC, profile.MNC)
	}
	if len(profile.IMSIPSecModes) == 0 {
		return imsProfile{}, false, fmt.Errorf("ims carrier profile %s-%s has no IPsec modes", profile.MCC, profile.MNC)
	}
	return profile, true, nil
}

func parseIMSProfile(raw []byte, card Card) (imsProfile, bool, error) {
	var profiles []imsProfile
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profiles); err != nil {
		return imsProfile{}, false, fmt.Errorf("decode json: %w", err)
	}

	mcc := strings.TrimSpace(card.MCC())
	mnc := strings.TrimSpace(card.MNC())
	mncLength := card.MNCLength()
	imsi := normalizeDigits(card.IMSI())
	iccid := normalizeDigits(card.ICCID())
	spn := strings.TrimSpace(card.SPN())
	gid1 := normalizeGID(card.GID1())
	gid2 := normalizeGID(card.GID2())
	bestIndex := -1
	bestScore := imsProfileMatchScore{}
	for index, profile := range profiles {
		if !samePLMNDigits(profile.MCC, profile.MNC, mcc, mnc, mncLength) {
			continue
		}
		imsiPrefix := strings.TrimSpace(profile.IMSIPrefix)
		if imsiPrefix != "" && !matchesIMSIPrefix(imsi, imsiPrefix) {
			continue
		}
		iccidPrefix := normalizeDigits(profile.ICCIDPrefix)
		if iccidPrefix != "" && !strings.HasPrefix(iccid, iccidPrefix) {
			continue
		}
		profileSPN := strings.TrimSpace(profile.SPN)
		if profileSPN != "" && !strings.EqualFold(spn, profileSPN) {
			continue
		}
		if profile.GID1 != "" && !sameGID(profile.GID1, gid1) {
			continue
		}
		if profile.GID2 != "" && !sameGID(profile.GID2, gid2) {
			continue
		}

		score := newIMSProfileMatchScore(profile)
		if bestIndex < 0 || score.betterThan(bestScore) {
			bestIndex = index
			bestScore = score
		}
	}
	if bestIndex >= 0 {
		return profiles[bestIndex], true, nil
	}
	return imsProfile{}, false, nil
}

type imsProfileMatchScore struct {
	conditions  int
	specificity int
	length      int
}

func newIMSProfileMatchScore(profile imsProfile) imsProfileMatchScore {
	imsiPrefix := strings.TrimSpace(profile.IMSIPrefix)
	selectors := []string{
		normalizeDigits(profile.ICCIDPrefix),
		strings.TrimSpace(profile.SPN),
		normalizeGID(profile.GID1),
		normalizeGID(profile.GID2),
	}
	score := imsProfileMatchScore{}
	if imsiPrefix != "" {
		score.conditions++
		score.length += len(imsiPrefix)
		score.specificity += len(imsiPrefix) - strings.Count(strings.ToLower(imsiPrefix), "x")
	}
	for _, selector := range selectors {
		if selector == "" {
			continue
		}
		score.conditions++
		score.length += len(selector)
		score.specificity += len(selector)
	}
	return score
}

func (score imsProfileMatchScore) betterThan(other imsProfileMatchScore) bool {
	if score.conditions != other.conditions {
		return score.conditions > other.conditions
	}
	if score.specificity != other.specificity {
		return score.specificity > other.specificity
	}
	return score.length > other.length
}

func matchesIMSIPrefix(imsi, pattern string) bool {
	if len(pattern) > len(imsi) {
		return false
	}
	for index := range len(pattern) {
		if pattern[index] == 'x' || pattern[index] == 'X' {
			if imsi[index] < '0' || imsi[index] > '9' {
				return false
			}
			continue
		}
		if pattern[index] != imsi[index] {
			return false
		}
	}
	return true
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

func sameGID(profileGID, cardGID string) bool {
	profileGID = normalizeGID(profileGID)
	cardGID = normalizeGID(cardGID)
	if profileGID == "" || cardGID == "" {
		return false
	}
	return strings.HasPrefix(cardGID, profileGID)
}

func normalizeGID(gid string) string {
	gid = strings.TrimSpace(gid)
	gid = strings.TrimPrefix(gid, "0x")
	gid = strings.TrimPrefix(gid, "0X")
	return strings.ToUpper(gid)
}

func normalizeDigits(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, value)
}

func (cfg Config) withIMSProfile(profile imsProfile, card Card) Config {
	if cfg.usesVoWiFi() {
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
		if wifi.Tunnel.SIPPort == 0 {
			wifi.Tunnel.SIPPort = firstNonZero(profile.SIPPort, profile.IMSSIPServerPort)
		}
		if len(wifi.Tunnel.DHGroups) == 0 {
			wifi.Tunnel.DHGroups = cloneUint16s(profile.DHGroups)
		}
		if len(wifi.Tunnel.IKEEncryption) == 0 {
			wifi.Tunnel.IKEEncryption = cloneUint16s(profile.IKEEncryption)
		}
		if len(wifi.Tunnel.IKEEncryptionKeyLens) == 0 {
			wifi.Tunnel.IKEEncryptionKeyLens = cloneUint16s(profile.IKEEncryptionKeyLens)
		}
		if len(wifi.Tunnel.IKEEncryptionAESCTRKeyLens) == 0 {
			wifi.Tunnel.IKEEncryptionAESCTRKeyLens = cloneUint16s(profile.IKEEncryptionAESCTRKeyLens)
		}
		if len(wifi.Tunnel.IKEIntegrity) == 0 {
			wifi.Tunnel.IKEIntegrity = cloneUint16s(profile.IKEIntegrity)
		}
		if len(wifi.Tunnel.IKEPRF) == 0 {
			wifi.Tunnel.IKEPRF = cloneUint16s(profile.IKEPRF)
		}
		if len(wifi.Tunnel.ChildEncryption) == 0 {
			wifi.Tunnel.ChildEncryption = cloneUint16s(profile.ChildEncryption)
		}
		if len(wifi.Tunnel.ChildEncryptionKeyLens) == 0 {
			wifi.Tunnel.ChildEncryptionKeyLens = cloneUint16s(profile.ChildEncryptionKeyLens)
		}
		if len(wifi.Tunnel.ChildEncryptionAESCTRKeyLens) == 0 {
			wifi.Tunnel.ChildEncryptionAESCTRKeyLens = cloneUint16s(profile.ChildEncryptionAESCTRKeyLens)
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
			wifi.Tunnel.NATKeepaliveInterval = imsProfileDurationValue(profile.NATKeepaliveInterval)
		}
		if wifi.Tunnel.LivenessTimeout == 0 {
			wifi.Tunnel.LivenessTimeout = profile.LivenessTimeout.Duration
		}
		if len(wifi.Tunnel.IKERetransmitDelays) == 0 {
			wifi.Tunnel.IKERetransmitDelays = imsProfileIKEReTransmitDelays(profile)
		}
		if wifi.Tunnel.IKESALifetime == 0 {
			wifi.Tunnel.IKESALifetime, wifi.Tunnel.IKESARekeyMargin = saLifetimeFromIMSProfile(
				profile.IKESALifetime,
				profile.IKESARekeySoftTime,
				profile.IKESARekeyHardTime,
				profile.IKESARekeyTime,
			)
		}
		if wifi.Tunnel.ChildSALifetime == 0 {
			wifi.Tunnel.ChildSALifetime, wifi.Tunnel.ChildSARekeyMargin = saLifetimeFromIMSProfile(
				profile.ChildSALifetime,
				profile.ChildSARekeySoftTime,
				profile.ChildSARekeyHardTime,
				profile.ChildSARekeyTime,
			)
		}
		if !wifi.Tunnel.AddKEToChildSARekey {
			wifi.Tunnel.AddKEToChildSARekey = profile.AddKEToChildSARekey
		}
	}

	if strings.TrimSpace(cfg.IMS.Transport) == "" {
		cfg.IMS.Transport = profile.IMSTransport
	}
	if strings.TrimSpace(cfg.IMS.HomeDomain) == "" {
		cfg.IMS.HomeDomain = profile.IMSHomeDomain
	}
	if strings.TrimSpace(cfg.IMS.PublicIdentity) == "" {
		cfg.IMS.PublicIdentity = renderIMSIdentity(profile.IMSPublicIdentity, cfg, card)
	}
	if strings.TrimSpace(cfg.IMS.PhoneContextDomain) == "" {
		cfg.IMS.PhoneContextDomain = profile.IMSPhoneContextDomain
	}
	if cfg.usesVoWiFi() && strings.TrimSpace(cfg.IMS.AccessNetworkInfo) == "" {
		cfg.IMS.AccessNetworkInfo = profile.IMSAccessNetworkInfo
	}
	if strings.TrimSpace(cfg.IMS.UserAgent) == "" {
		cfg.IMS.UserAgent = renderIMSUserAgent(profile.IMSUserAgent, cfg, profile)
	}
	if cfg.IMS.RegisterExpires == 0 {
		cfg.IMS.RegisterExpires = profile.IMSRegisterExpires.Duration
	}
	if cfg.IMS.RegistrationRetryBase == 0 {
		cfg.IMS.RegistrationRetryBase = imsProfileDurationValue(profile.IMSRegistrationRetryBase)
	}
	if cfg.IMS.RegistrationRetryMax == 0 {
		cfg.IMS.RegistrationRetryMax = imsProfileDurationValue(profile.IMSRegistrationRetryMax)
	}
	if len(cfg.IMS.IPSecIntegrityAlgorithms) == 0 {
		cfg.IMS.IPSecIntegrityAlgorithms = cloneStrings(profile.IMSIPSecIntegrityAlgorithms)
	}
	if len(cfg.IMS.IPSecEncryptionAlgorithms) == 0 {
		cfg.IMS.IPSecEncryptionAlgorithms = cloneStrings(profile.IMSIPSecEncryptionAlgorithms)
	}
	cfg.IMS.IPSecModes = cloneStrings(profile.IMSIPSecModes)
	if len(cfg.IMS.Voice.GeolocationPIDFInvite) == 0 {
		cfg.IMS.Voice.GeolocationPIDFInvite = cloneInts(profile.IMSGeolocationPIDFInvite)
	}
	if len(cfg.IMS.GeolocationPIDFRegister) == 0 {
		cfg.IMS.GeolocationPIDFRegister = cloneInts(profile.IMSGeolocationPIDFRegister)
	}
	if !cfg.IMS.UseTelURIForPIDFXML {
		cfg.IMS.UseTelURIForPIDFXML = profile.IMSUseTelURIForPIDFXML
	}
	if cfg.IMS.Voice.RequestURIFormat == "" {
		cfg.IMS.Voice.RequestURIFormat = profile.IMSRequestURIFormat
	}
	if cfg.IMS.SIPServerPort == 0 {
		cfg.IMS.SIPServerPort = firstNonZero(profile.IMSSIPServerPort, profile.SIPPort)
	}
	if cfg.IMS.SIPTimers.T1 == 0 {
		cfg.IMS.SIPTimers.T1 = profile.IMSSIPTimerT1.Duration
	}
	if cfg.IMS.SIPTimers.T2 == 0 {
		cfg.IMS.SIPTimers.T2 = profile.IMSSIPTimerT2.Duration
	}
	if cfg.IMS.SIPTimers.T4 == 0 {
		cfg.IMS.SIPTimers.T4 = profile.IMSSIPTimerT4.Duration
	}
	if cfg.IMS.SIPTimers.TB == 0 {
		cfg.IMS.SIPTimers.TB = profile.IMSSIPTimerB.Duration
	}
	if cfg.IMS.SIPTimers.TD == 0 {
		cfg.IMS.SIPTimers.TD = profile.IMSSIPTimerD.Duration
	}
	if cfg.IMS.SIPTimers.TF == 0 {
		cfg.IMS.SIPTimers.TF = profile.IMSSIPTimerF.Duration
	}
	if cfg.IMS.SIPTimers.TH == 0 {
		cfg.IMS.SIPTimers.TH = profile.IMSSIPTimerH.Duration
	}
	if cfg.IMS.SIPTimers.TJ == 0 {
		cfg.IMS.SIPTimers.TJ = profile.IMSSIPTimerJ.Duration
	}
	cfg.smsRequestStatusReport = profile.EnableSMSDeliveryReports
	cfg = cfg.withIMSVoiceProfile(profile.IMSVoice)
	return cfg
}

func (cfg Config) withIMSVoiceProfile(profile imsVoiceProfile) Config {
	if strings.TrimSpace(cfg.IMS.Voice.RTPProfile) == "" {
		cfg.IMS.Voice.RTPProfile = profile.RTPProfile
	}
	if cfg.IMS.Voice.PTime == 0 {
		cfg.IMS.Voice.PTime = profile.PTime.Duration
	}
	if cfg.IMS.Voice.MaxPTime == 0 {
		cfg.IMS.Voice.MaxPTime = profile.MaxPTime.Duration
	}
	if strings.TrimSpace(cfg.IMS.Voice.GeolocationCountry) == "" {
		cfg.IMS.Voice.GeolocationCountry = profile.GeolocationCountry
	}
	if len(cfg.IMS.Voice.PIDFShortCodes) == 0 {
		cfg.IMS.Voice.PIDFShortCodes = cloneStrings(profile.PIDFShortCodes)
	}
	cfg.IMS.Voice.Preconditions = profile.QoSPreconditionsSupported
	cfg.IMS.Voice.ReliableProvisional = profile.ReliableProvisionalSupported
	cfg.IMS.Voice.SessionTimer = profile.SessionTimer
	if cfg.IMS.Voice.SessionExpires == 0 {
		cfg.IMS.Voice.SessionExpires = profile.SessionExpires.Duration
	}
	if cfg.IMS.Voice.MinSessionExpires == 0 {
		cfg.IMS.Voice.MinSessionExpires = profile.MinimumSessionExpires.Duration
	}
	if strings.TrimSpace(cfg.IMS.Voice.SessionRefresher) == "" {
		cfg.IMS.Voice.SessionRefresher = profile.SessionRefresher
	}
	if cfg.IMS.Voice.MOCallRequestTimeout == 0 {
		cfg.IMS.Voice.MOCallRequestTimeout = profile.MOCallRequestTimeout.Duration
	}
	if cfg.IMS.Voice.RingbackTimeout == 0 {
		cfg.IMS.Voice.RingbackTimeout = profile.RingbackTimer.Duration
	}
	if cfg.IMS.Voice.RingingTimeout == 0 {
		cfg.IMS.Voice.RingingTimeout = profile.RingingTimer.Duration
	}
	if cfg.IMS.Voice.AudioASBandwidthKbps == 0 {
		cfg.IMS.Voice.AudioASBandwidthKbps = profile.AudioASBandwidthKbps
	}
	if cfg.IMS.Voice.RTPInactivityTimeout == nil {
		cfg.IMS.Voice.RTPInactivityTimeout = imsvoice.Duration(profile.RTPInactivityTimeout.Duration)
	}
	if cfg.IMS.Voice.RTCPInactivityTimeout == nil {
		cfg.IMS.Voice.RTCPInactivityTimeout = imsvoice.Duration(profile.RTCPInactivityTimeout.Duration)
	}
	if cfg.IMS.Voice.AudioInactivityCallEndReasons == nil && profile.AudioInactivityCallEndReasons != nil {
		cfg.IMS.Voice.AudioInactivityCallEndReasons = append([]imsvoice.AudioInactivityCallEndReason(nil), profile.AudioInactivityCallEndReasons...)
	}
	if cfg.IMS.Voice.LocalRTPPortMin == 0 {
		cfg.IMS.Voice.LocalRTPPortMin = profile.LocalRTPPortMin
	}
	if cfg.IMS.Voice.LocalRTPPortMax == 0 {
		cfg.IMS.Voice.LocalRTPPortMax = profile.LocalRTPPortMax
	}
	if len(cfg.IMS.Voice.Codecs) == 0 {
		cfg.IMS.Voice.Codecs = imsProfileVoiceCodecs(profile)
	}
	return cfg
}

func imsProfileVoiceCodecs(profile imsVoiceProfile) []imsvoice.AudioCodecConfig {
	if len(profile.Codecs) == 0 {
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
			applyIMSVoiceEVSDescription(&voiceCodec, profile.EVSPayloadDescriptions)
		}
		out = append(out, voiceCodec)
	}
	return out
}

func applyIMSVoiceEVSDescription(codec *imsvoice.AudioCodecConfig, descriptions map[string]imsEVSPayloadDescription) {
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
	if validEVSChannelAwareReceive(desc.ChannelAwareReceive) {
		value := desc.ChannelAwareReceive
		codec.ChAwRecv = &value
	}
}

func validEVSChannelAwareReceive(value int) bool {
	switch value {
	case 2, 3, 5, 7:
		return true
	default:
		return false
	}
}

func renderIMSIdentity(template string, cfg Config, card Card) string {
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

func imsProfileDurations(values []imsProfileDuration) []time.Duration {
	if len(values) == 0 {
		return nil
	}
	durations := make([]time.Duration, 0, len(values))
	for _, value := range values {
		durations = append(durations, value.Duration)
	}
	return durations
}

func imsProfileIKEReTransmitDelays(profile imsProfile) []time.Duration {
	if len(profile.IKERetransmitDelays) != 0 {
		return imsProfileDurations(profile.IKERetransmitDelays)
	}
	return nil
}

func saLifetimeFromIMSProfile(lifetime, soft, hard, legacySoft imsProfileDuration) (time.Duration, time.Duration) {
	hardTime := imsProfileDurationValue(hard)
	softTime := imsProfileDurationValue(soft)
	if hardTime > 0 || softTime > 0 {
		softTime = imsProfileRekeySoftTime(hardTime, soft)
		if hardTime <= 0 {
			hardTime = softTime + swuSARekeyMargin(softTime)
		}
		if softTime <= 0 {
			return hardTime, swuSARekeyMargin(hardTime)
		}
		return hardTime, hardTime - softTime
	}

	hardTime = imsProfileDurationValue(lifetime)
	softTime = imsProfileRekeySoftTime(hardTime, legacySoft)
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

func imsProfileRekeySoftTime(hardTime time.Duration, values ...imsProfileDuration) time.Duration {
	for _, value := range values {
		rekeyTime := imsProfileDurationValue(value)
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

func imsProfileDurationValue(value imsProfileDuration) time.Duration {
	return value.Duration
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
