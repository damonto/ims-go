package tunnel

import (
	"context"

	usim "github.com/damonto/wwan-go/sim"
)

type Card interface {
	IMSI() string
	MCC() string
	MNC() string
}

type AKAAuthenticator func(context.Context, []byte, []byte) (usim.AKAResult, error)

// ConnectStage identifies an operation in the initial SWu handshake.
type ConnectStage string

// SWu handshake stages reported by ConnectRequest.OnStage.
const (
	StageIKEInit ConnectStage = "epdg_ike_init"
	StageEAPAKA  ConnectStage = "epdg_eap_aka"
	StageIPSec   ConnectStage = "epdg_ipsec"
)

type ConnectRequest struct {
	IMEI            string
	Card            Card
	AuthenticateAKA AKAAuthenticator
	// OnStage observes handshake stages synchronously and must return promptly.
	OnStage func(ConnectStage)
}
