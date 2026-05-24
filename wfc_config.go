package imsclient

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

//go:embed wfc_config.json
var embeddedWFCConfig []byte

type wfcProfile struct {
	MCC                    string        `json:"mcc"`
	MNC                    string        `json:"mnc"`
	EPDG                   string        `json:"epdg"`
	EPDGAddresses          []string      `json:"epdgAddresses"`
	InitialPort            int           `json:"initialPort"`
	NATTPort               int           `json:"nattPort"`
	LocalSIPPort           int           `json:"localSIPPort"`
	SIPPort                int           `json:"sipPort"`
	DHGroups               []uint16      `json:"dhGroups"`
	IKEEncryptionKeyLens   []uint16      `json:"ikeEncryptionKeyLens"`
	IKEIntegrity           []uint16      `json:"ikeIntegrity"`
	IKEPRF                 []uint16      `json:"ikePRF"`
	ChildEncryptionKeyLens []uint16      `json:"childEncryptionKeyLens"`
	ChildIntegrity         []uint16      `json:"childIntegrity"`
	NATKeepaliveInterval   *wfcDuration  `json:"natKeepaliveInterval"`
	IKERetransmitDelays    []wfcDuration `json:"ikeRetransmitDelays"`
	IMSTransport           string        `json:"imsTransport"`
	IMSHomeDomain          string        `json:"imsHomeDomain"`
	IMSPhoneContextDomain  string        `json:"imsPhoneContextDomain"`
	IMSAccessNetworkInfo   string        `json:"imsAccessNetworkInfo"`
	IMSUserAgent           string        `json:"imsUserAgent"`
	IMSRegisterExpires     *wfcDuration  `json:"imsRegisterExpires"`
	IMSSIPServerPort       int           `json:"imsSIPServerPort"`
	IMSSIPTimerT1          *wfcDuration  `json:"imsSIPTimerT1"`
	IMSSIPTimerT2          *wfcDuration  `json:"imsSIPTimerT2"`
	IMSSIPTimerT4          *wfcDuration  `json:"imsSIPTimerT4"`
	IMSSIPTimerB           *wfcDuration  `json:"imsSIPTimerB"`
	IMSSIPTimerD           *wfcDuration  `json:"imsSIPTimerD"`
	IMSSIPTimerF           *wfcDuration  `json:"imsSIPTimerF"`
	IMSSIPTimerH           *wfcDuration  `json:"imsSIPTimerH"`
	IMSSIPTimerJ           *wfcDuration  `json:"imsSIPTimerJ"`
	WFCSPN                 string        `json:"wfcSPN"`
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
	if card == nil {
		return wfcProfile{}, false, errors.New("loading wfc config: card is nil")
	}

	var profiles map[string]wfcProfile
	if err := json.Unmarshal(raw, &profiles); err != nil {
		return wfcProfile{}, false, fmt.Errorf("loading wfc config: decode json: %w", err)
	}

	mcc := strings.TrimSpace(card.MCC())
	mnc := strings.TrimSpace(card.MNC())
	if profile, ok := profiles[mcc+mnc]; ok {
		return profile, true, nil
	}
	for _, profile := range profiles {
		if strings.TrimSpace(profile.MCC) == mcc && strings.TrimSpace(profile.MNC) == mnc {
			return profile, true, nil
		}
	}
	return wfcProfile{}, false, nil
}

func (cfg Config) withWFCProfile(profile wfcProfile) Config {
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
	if cfg.Tunnel.NATKeepaliveInterval == 0 && profile.NATKeepaliveInterval != nil {
		cfg.Tunnel.NATKeepaliveInterval = profile.NATKeepaliveInterval.Duration
	}
	if len(cfg.Tunnel.IKERetransmitDelays) == 0 {
		cfg.Tunnel.IKERetransmitDelays = wfcDurations(profile.IKERetransmitDelays)
	}

	if strings.TrimSpace(cfg.IMS.Transport) == "" {
		cfg.IMS.Transport = profile.IMSTransport
	}
	if strings.TrimSpace(cfg.IMS.HomeDomain) == "" {
		cfg.IMS.HomeDomain = profile.IMSHomeDomain
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
	return cfg
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
