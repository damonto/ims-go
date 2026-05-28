package qmi

import (
	"context"

	qrtrtransport "github.com/damonto/vowifi-go/driver/qmi/transport/qrtr"
	"github.com/damonto/vowifi-go/driver/qmi/uim"
	usimreader "github.com/damonto/vowifi-go/usim/reader"
)

func OpenQRTR(ctx context.Context, slot int) (usimreader.Reader, error) {
	transport, err := qrtrtransport.Open()
	if err != nil {
		return nil, err
	}
	return uim.Open(ctx, transport, uint8(slot), "")
}
