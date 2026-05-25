package qmi

import (
	"context"
	"errors"
	"strings"

	qmitransport "github.com/damonto/ims-client/driver/qmi/transport/qmi"
	"github.com/damonto/ims-client/driver/qmi/uim"
	usimreader "github.com/damonto/ims-client/usim/reader"
)

func Open(ctx context.Context, device string, slot int) (usimreader.Reader, error) {
	if strings.TrimSpace(device) == "" {
		return nil, errors.New("opening QMI reader: device is empty")
	}
	transport, err := qmitransport.Open()
	if err != nil {
		return nil, err
	}
	return uim.Open(ctx, transport, uint8(slot), device)
}
