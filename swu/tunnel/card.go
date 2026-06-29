package tunnel

import (
	"context"

	"github.com/damonto/uicc-go/usim"
)

type Card interface {
	IMSI() string
	MCC() string
	MNC() string
	AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error)
}
