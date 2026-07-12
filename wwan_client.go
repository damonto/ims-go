package ims

import (
	"context"
	"errors"
	"fmt"

	"github.com/damonto/wwan-go/mbim"
	"github.com/damonto/wwan-go/qcom"
	"github.com/damonto/wwan-go/sim"
)

type QCOMClient struct {
	*sim.QCOM
	client *qcom.Client
}

// NewQCOMClient adapts a wwan-go QCOM client for SIM access and VoLTE IMS PDN setup.
// The returned client owns the supplied client and closes it from Close.
func NewQCOMClient(client *qcom.Client) (*QCOMClient, error) {
	reader, err := sim.NewQCOM(client)
	if err != nil {
		return nil, err
	}
	return &QCOMClient{QCOM: reader, client: client}, nil
}

func (c *QCOMClient) OpenIMSPDN(ctx context.Context, cfg imsPDNConfig) (imsPDNSession, error) {
	ipPreference, err := qcomIPPreference(cfg.PDNType)
	if err != nil {
		return nil, err
	}
	session, err := c.client.OpenIMSPDN(ctx, qcom.IMSPDNConfig{
		APN:          cfg.APN,
		IPPreference: ipPreference,
		ProfileIndex: cfg.ProfileIndex,
	})
	if err != nil {
		return nil, err
	}
	return qcomIMSPDNSession{session}, nil
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
	client *mbim.Client
}

// NewMBIMClient adapts a wwan-go MBIM client for SIM access and VoLTE IMS PDN setup.
// The returned client owns the supplied client and closes it from Close.
func NewMBIMClient(client *mbim.Client) (*MBIMClient, error) {
	reader, err := sim.NewMBIM(client)
	if err != nil {
		return nil, err
	}
	return &MBIMClient{MBIM: reader, client: client}, nil
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
	return mbimIMSPDNSession{session}, nil
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
