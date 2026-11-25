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
