//go:build !linux

package qmi

import (
	"errors"

	"github.com/damonto/ims-client/driver/qmi/protocol"
)

func Open() (protocol.Transport, error) {
	return nil, errors.New("opening QMI reader: qmi-proxy is only supported on linux")
}
