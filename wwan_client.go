package ims

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/damonto/wwan-go/mbim"
	"github.com/damonto/wwan-go/qcom"
	"github.com/damonto/wwan-go/sim"
)

// IMSPDNNetworkInfo contains the host-side network state negotiated for an IMS PDN.
type IMSPDNNetworkInfo struct {
	SessionID uint32
	LocalIPv4 net.IP
	LocalIPv6 net.IP
	PCSCFIPs  []net.IP
}

// IMSPDNNetwork applies and removes host-side interface addresses and P-CSCF routes.
type IMSPDNNetwork interface {
	Replace(context.Context, IMSPDNNetworkInfo) error
	Close() error
}

type QCOMClient struct {
	*sim.QCOM
	client            *qcom.Client
	muxDataPort       *qcom.WDSMuxDataPort
	legacyMuxDataPort qcom.WDSSIOPort
	network           IMSPDNNetwork
}

// QCOMClientConfig configures QCOM-specific IMS PDN access.
// LegacyMuxDataPort is used as a fallback when modern mux binding is unsupported.
type QCOMClientConfig struct {
	MuxDataPort       *qcom.WDSMuxDataPort
	LegacyMuxDataPort qcom.WDSSIOPort
	Network           IMSPDNNetwork
}

// NewQCOMClient adapts a wwan-go QCOM client for SIM access and VoLTE IMS PDN setup.
// The returned client owns the supplied client and closes it from Close.
func NewQCOMClient(client *qcom.Client, cfg QCOMClientConfig) (*QCOMClient, error) {
	wwan, err := sim.NewQCOM(client)
	if err != nil {
		return nil, err
	}
	return &QCOMClient{
		QCOM:              wwan,
		client:            client,
		muxDataPort:       cloneQCOMMuxDataPort(cfg.MuxDataPort),
		legacyMuxDataPort: cfg.LegacyMuxDataPort,
		network:           cfg.Network,
	}, nil
}

func (c *QCOMClient) OpenIMSPDN(ctx context.Context, cfg imsPDNConfig) (imsPDNSession, error) {
	pdnConfigs, err := qcomIMSPDNConfigs(cfg, c.muxDataPort, c.legacyMuxDataPort)
	if err != nil {
		return nil, err
	}
	var session *qcom.IMSPDNSession
	for i, pdnCfg := range pdnConfigs {
		session, err = c.client.OpenIMSPDN(ctx, pdnCfg)
		if err == nil {
			adapted := qcomIMSPDNSession{session}
			info := session.Info()
			return configureIMSPDNNetwork(ctx, adapted, c.network, IMSPDNNetworkInfo{
				LocalIPv4: info.LocalIPv4,
				LocalIPv6: info.LocalIPv6,
				PCSCFIPs:  info.PCSCFIPs,
			})
		}
		if i == 0 && len(pdnConfigs) > 1 && errors.Is(err, qcom.QMIErrorNotSupported) {
			continue
		}
		return nil, err
	}
	return nil, err
}

func qcomIMSPDNConfigs(cfg imsPDNConfig, muxDataPort *qcom.WDSMuxDataPort, legacyMuxDataPort qcom.WDSSIOPort) ([]qcom.IMSPDNConfig, error) {
	ipPreference, err := qcomIPPreference(cfg.PDNType)
	if err != nil {
		return nil, err
	}
	pdnCfg := qcom.IMSPDNConfig{
		APN:          cfg.APN,
		IPPreference: ipPreference,
		ProfileIndex: cfg.ProfileIndex,
		MuxDataPort:  cloneQCOMMuxDataPort(muxDataPort),
	}
	if muxDataPort == nil {
		pdnCfg.LegacyMuxDataPort = legacyMuxDataPort
		return []qcom.IMSPDNConfig{pdnCfg}, nil
	}
	configs := []qcom.IMSPDNConfig{pdnCfg}
	if legacyMuxDataPort != 0 {
		pdnCfg.MuxDataPort = nil
		pdnCfg.LegacyMuxDataPort = legacyMuxDataPort
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
		return qcom.WDSIPPreferenceUnspecified, nil
	default:
		return 0, fmt.Errorf("opening QCOM IMS PDN: unsupported PDN type %q", pdnType)
	}
}

type MBIMClient struct {
	*sim.MBIM
	client  *mbim.Client
	network IMSPDNNetwork
}

// MBIMClientConfig configures MBIM-specific IMS PDN access.
type MBIMClientConfig struct {
	Network IMSPDNNetwork
}

// NewMBIMClient adapts a wwan-go MBIM client for SIM access and VoLTE IMS PDN setup.
// The returned client owns the supplied client and closes it from Close.
func NewMBIMClient(client *mbim.Client, cfg MBIMClientConfig) (*MBIMClient, error) {
	reader, err := sim.NewMBIM(client)
	if err != nil {
		return nil, err
	}
	return &MBIMClient{MBIM: reader, client: client, network: cfg.Network}, nil
}

func (c *MBIMClient) OpenIMSPDN(ctx context.Context, cfg imsPDNConfig) (imsPDNSession, error) {
	if cfg.ProfileIndex != 0 {
		return nil, errors.New("opening MBIM IMS PDN: profile index is unsupported")
	}
	ipType, err := mbimIPType(cfg.PDNType)
	if err != nil {
		return nil, err
	}
	session, err := c.client.OpenIMSPDN(ctx, mbim.IMSPDNConfig{
		APN:    cfg.APN,
		IPType: ipType,
	})
	if err != nil {
		return nil, err
	}
	adapted := mbimIMSPDNSession{session}
	info := session.Info()
	return configureIMSPDNNetwork(ctx, adapted, c.network, IMSPDNNetworkInfo{
		SessionID: info.SessionID,
		LocalIPv4: info.LocalIPv4,
		LocalIPv6: info.LocalIPv6,
		PCSCFIPs:  info.PCSCFIPs,
	})
}

type networkedIMSPDNSession struct {
	imsPDNSession
	network   IMSPDNNetwork
	closeOnce sync.Once
	closeErr  error
}

func configureIMSPDNNetwork(ctx context.Context, session imsPDNSession, network IMSPDNNetwork, info IMSPDNNetworkInfo) (imsPDNSession, error) {
	if network == nil {
		return session, nil
	}
	if err := network.Replace(ctx, info); err != nil {
		return nil, errors.Join(err, network.Close(), session.Close())
	}
	return &networkedIMSPDNSession{imsPDNSession: session, network: network}, nil
}

func (s *networkedIMSPDNSession) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = errors.Join(s.network.Close(), s.imsPDNSession.Close())
	})
	return s.closeErr
}

type mbimIMSPDNSession struct {
	*mbim.IMSPDNSession
}

func (s mbimIMSPDNSession) Info() imsPDNInfo {
	info := s.IMSPDNSession.Info()
	return imsPDNInfo{
		LocalIPv4:       info.LocalIPv4,
		LocalIPv6:       info.LocalIPv6,
		PCSCFIPs:        info.PCSCFIPs,
		VoPSSupported:   info.VoPSSupported,
		PacketDataReady: info.PacketDataReady,
	}
}

func mbimIPType(pdnType string) (mbim.ContextIPType, error) {
	switch pdnType {
	case "ipv4":
		return mbim.ContextIPTypeIPv4, nil
	case "ipv6":
		return mbim.ContextIPTypeIPv6, nil
	case "ipv4v6":
		return mbim.ContextIPTypeIPv4v6, nil
	default:
		return 0, fmt.Errorf("opening MBIM IMS PDN: unsupported PDN type %q", pdnType)
	}
}
