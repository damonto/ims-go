package wfcsetup

import "context"

const (
	vzwCarrier = "Verizon Wireless"
	vzwReason  = "vzw setup is unsupported because Verizon SSO requires the carrier content provider"
)

type vzwFlow struct{}

var vzwSIMs = []simMatch{
	{MCC: "204", MNC: "04", GID1: "BAE0000000000000"},
	{MCC: "310", MNC: "004"},
	{MCC: "310", MNC: "590"},
	{MCC: "310", MNC: "599"},
	{MCC: "311", MNC: "270"},
	{MCC: "311", MNC: "280"},
	{MCC: "311", MNC: "480"},
}

func newVZWFlow(req Request) (flow, bool, error) {
	if !matchAnySIM(req.Card, vzwSIMs) {
		return nil, false, nil
	}
	return vzwFlow{}, true, nil
}

func (f vzwFlow) Check(context.Context) (Result, error) {
	result := Result{
		Scheme:  SchemeVZW,
		Carrier: vzwCarrier,
		Action:  ActionDenied,
	}
	return result, wrapResultError(result, ErrNotImplemented)
}

func (f vzwFlow) E911UpdateSupport(context.Context) (E911UpdateSupport, error) {
	return E911UpdateSupport{
		Supported: false,
		BuiltIn:   false,
		Scheme:    SchemeVZW,
		Carrier:   vzwCarrier,
		Reason:    vzwReason,
	}, nil
}
