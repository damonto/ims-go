package ims

import (
	"context"
	"strings"

	"github.com/damonto/ims-go/wfcsetup"
)

func (c *Client) checkWFCSetup(ctx context.Context, cfg *Config, card Card) error {
	terminal := cfg.Terminal.trimmed()
	result, err := wfcsetup.Check(ctx, wfcsetup.Request{
		Card: cfg.IMS.coordinatedCard(card),
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
