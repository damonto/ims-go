package vowifi

import (
	"context"
	"fmt"
	"strings"

	swutunnel "github.com/damonto/vowifi-go/swu/tunnel"
	"github.com/damonto/vowifi-go/wfcsetup"
)

func (c *Client) checkWFCSetup(ctx context.Context, cfg *Config, card Card) error {
	terminal := cfg.Terminal.trimmed()
	result, err := wfcsetup.Check(ctx, wfcsetup.Request{
		Card: card,
		Device: wfcsetup.Device{
			IMEI:            terminal.ID,
			Vendor:          terminal.Vendor,
			Model:           terminal.Model,
			SoftwareVersion: terminal.SoftwareVersion,
		},
		Purpose: wfcsetup.PurposeActivation,
		Logger:  cfg.Logger,
	})
	if err != nil {
		return err
	}
	applyWFCSetupMSISDN(cfg, result.MSISDN)
	if result.Entitled {
		return nil
	}
	return wfcSetupResultError(result)
}

func wfcSetupResultError(result wfcsetup.Result) error {
	if result.Entitled {
		return nil
	}
	err := wfcsetup.ErrDenied
	switch result.Action {
	case wfcsetup.ActionOpenWebsheet:
		err = wfcsetup.ErrUserActionRequired
	case wfcsetup.ActionWait:
		err = wfcsetup.ErrPending
	}
	return &wfcsetup.Error{Err: err, Result: result}
}

func applyWFCSetupMSISDN(cfg *Config, msisdn string) {
	if strings.TrimSpace(cfg.IMS.PublicIdentity) != "" {
		return
	}
	msisdn = wfcSetupPublicMSISDN(msisdn)
	if msisdn == "" || cfg.IMS.HomeDomain == "" {
		return
	}
	cfg.IMS.PublicIdentity = "sip:" + msisdn + "@" + cfg.IMS.HomeDomain
}

func wfcSetupPublicMSISDN(msisdn string) string {
	msisdn = strings.TrimSpace(msisdn)
	if msisdn == "" {
		return ""
	}
	if strings.HasPrefix(msisdn, "+") {
		return msisdn
	}
	switch {
	case len(msisdn) == 10:
		return "+1" + msisdn
	case len(msisdn) == 11 && strings.HasPrefix(msisdn, "1"):
		return "+" + msisdn
	default:
		return msisdn
	}
}

func (c *Client) openTunnel(ctx context.Context, setup *connectSetup) (swutunnel.Info, error) {
	session, err := swutunnel.Dial(ctx, setup.tunnelCfg)
	if err != nil {
		return swutunnel.Info{}, fmt.Errorf("dialing tunnel: %w", err)
	}
	setup.tunnel = session

	c.emitStatus(StatusAuthenticating)
	c.logger.Info("connecting SWu tunnel", "tunnel_remote_addr", setup.tunnelCfg.RemoteAddr)

	if err := session.Connect(ctx, c.cfg.Terminal.ID, c.card); err != nil {
		return swutunnel.Info{}, fmt.Errorf("connecting swu: %w", err)
	}
	tunnelInfo := session.Info()
	c.logger.Info("SWu tunnel established", "inner_ip", tunnelInfo.InnerIP, "pcscf_ip", tunnelInfo.PCSCFIP, "pcscf_ips", tunnelInfo.PCSCFIPs, "esp_initiator_spi", tunnelInfo.ESPInitiatorSPI, "esp_responder_spi", tunnelInfo.ESPResponderSPI)
	return tunnelInfo, nil
}
