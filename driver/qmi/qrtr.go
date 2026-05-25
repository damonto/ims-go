package qmi

import (
	"context"

	qrtrtransport "github.com/damonto/ims-client/driver/qmi/transport/qrtr"
	"github.com/damonto/ims-client/driver/qmi/uim"
	usimreader "github.com/damonto/ims-client/usim/reader"
)

func OpenQRTR(ctx context.Context, slot int) (usimreader.Reader, error) {
	transport, err := qrtrtransport.Open()
	if err != nil {
		return nil, err
	}
	return uim.Open(ctx, transport, uint8(slot), "")
}
