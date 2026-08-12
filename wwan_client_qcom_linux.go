//go:build linux

package ims

import (
	"context"
	"errors"
	"fmt"

	"github.com/damonto/wwan-go/qcom"
	"github.com/damonto/wwan-go/sim"
)

type QCOMClient struct {
	*sim.QCOM
	client *qcom.Client
	config QCOMClientConfig
}

// QCOMClientConfig configures QCOM-specific IMS PDN access.
// LegacyMuxDataPort is used as a fallback when modern mux binding is unsupported.
type QCOMClientConfig struct {
	MuxDataPort       *qcom.WDSMuxDataPort
	LegacyMuxDataPort qcom.WDSSIOPort
	Network           PDNNetwork
}

// NewQCOMClient adapts a wwan-go QCOM client for SIM access and VoLTE IMS PDN setup.
// The returned client owns the supplied client and closes it from Close.
func NewQCOMClient(client *qcom.Client, cfg QCOMClientConfig) (*QCOMClient, error) {
	wwan, err := sim.NewQCOM(client)
	if err != nil {
		return nil, err
	}
	cfg.MuxDataPort = cloneQCOMMuxDataPort(cfg.MuxDataPort)
	return &QCOMClient{QCOM: wwan, client: client, config: cfg}, nil
}

func (c *QCOMClient) OpenIMSPDN(ctx context.Context, cfg imsPDNConfig) (imsPDNSession, error) {
	pdnConfigs, err := qcomIMSPDNConfigs(cfg, c.config)
	if err != nil {
		return nil, err
	}
	var session *qcom.IMSPDNSession
	for i, pdnCfg := range pdnConfigs {
		session, err = c.client.OpenIMSPDN(ctx, pdnCfg)
		if err == nil {
			adapted := qcomIMSPDNSession{session}
			return configurePDNNetwork(ctx, adapted, c.config.Network, qcomPDNNetworkInfo(session.Info()))
		}
		if i == 0 && len(pdnConfigs) > 1 && errors.Is(err, qcom.QMIErrorNotSupported) {
			continue
		}
		return nil, err
	}
	return nil, err
}

func qcomPDNNetworkInfo(info qcom.IMSPDNInfo) PDNNetworkInfo {
	return PDNNetworkInfo{
		LocalIPv4:   info.LocalIPv4,
		LocalIPv6:   info.LocalIPv6,
		IPv4Gateway: info.IPv4Gateway,
		IPv6Gateway: info.IPv6Gateway,
		PCSCFIPs:    info.PCSCFIPs,
	}
}

func qcomIMSPDNConfigs(cfg imsPDNConfig, clientCfg QCOMClientConfig) ([]qcom.IMSPDNConfig, error) {
	ipPreference, err := qcomIPPreference(cfg.PDNType)
	if err != nil {
		return nil, err
	}
	pdnCfg := qcom.IMSPDNConfig{
		APN:          cfg.APN,
		IPPreference: ipPreference,
		ProfileIndex: cfg.ProfileIndex,
		MuxDataPort:  cloneQCOMMuxDataPort(clientCfg.MuxDataPort),
	}
	if clientCfg.MuxDataPort == nil {
		pdnCfg.LegacyMuxDataPort = clientCfg.LegacyMuxDataPort
		return []qcom.IMSPDNConfig{pdnCfg}, nil
	}
	configs := []qcom.IMSPDNConfig{pdnCfg}
	if clientCfg.LegacyMuxDataPort != 0 {
		pdnCfg.MuxDataPort = nil
		pdnCfg.LegacyMuxDataPort = clientCfg.LegacyMuxDataPort
		configs = append(configs, pdnCfg)
	}
	return configs, nil
}

func cloneQCOMMuxDataPort(port *qcom.WDSMuxDataPort) *qcom.WDSMuxDataPort {
	if port == nil {
		return nil
	}
	clone := *port
	if port.Endpoint != nil {
		endpoint := *port.Endpoint
		clone.Endpoint = &endpoint
	}
	return &clone
}

type qcomIMSPDNSession struct {
	*qcom.IMSPDNSession
}

func (s qcomIMSPDNSession) Info() imsPDNInfo {
	info := s.IMSPDNSession.Info()
	return imsPDNInfo{
		LocalIPv4:       info.LocalIPv4,
		LocalIPv6:       info.LocalIPv6,
		PCSCFIPs:        info.PCSCFIPs,
		VoPSKnown:       info.VoPSKnown,
		VoPSSupported:   info.VoPSSupported,
		PacketDataReady: info.PacketDataReady,
	}
}

func qcomIPPreference(pdnType string) (qcom.WDSIPPreference, error) {
	switch pdnType {
	case "ipv4":
		return qcom.WDSIPPreferenceIPv4, nil
	case "ipv6":
		return qcom.WDSIPPreferenceIPv6, nil
	case "ipv4v6":
		return qcom.WDSIPPreferenceDefault, nil
	default:
		return 0, fmt.Errorf("opening QCOM IMS PDN: unsupported PDN type %q", pdnType)
	}
}
