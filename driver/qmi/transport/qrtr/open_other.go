//go:build !linux

package qrtr

import (
	"errors"

	"github.com/damonto/ims-client/driver/qmi/protocol"
)

func Open() (protocol.Transport, error) {
	return nil, errors.New("opening QRTR reader: QRTR is only supported on linux")
}
