package qmi

import (
	"context"

	"github.com/damonto/ims-client/driver/qmi/core"
	qrtrtransport "github.com/damonto/ims-client/driver/qmi/transport/qrtr"
	usimreader "github.com/damonto/ims-client/usim/reader"
)

func OpenQRTR(ctx context.Context, slot int) (usimreader.Reader, error) {
	transport, err := qrtrtransport.Open()
	if err != nil {
		return nil, err
	}
	return core.Open(ctx, transport, uint8(slot), "")
}
