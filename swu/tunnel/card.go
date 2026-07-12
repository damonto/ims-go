package tunnel

import (
	"context"

	usim "github.com/damonto/wwan-go/sim"
)

type Card interface {
	IMSI() string
	MCC() string
	MNC() string
	AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error)
}
