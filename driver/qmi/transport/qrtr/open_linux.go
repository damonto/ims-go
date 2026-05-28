//go:build linux

package qrtr

import (
	"fmt"

	"github.com/damonto/vowifi-go/driver/qmi/protocol"
	qrtrsocket "github.com/damonto/vowifi-go/driver/qmi/qrtr"
)

func Open() (protocol.Transport, error) {
	conn, err := qrtrsocket.Open(protocol.ServiceUIM)
	if err != nil {
		return nil, fmt.Errorf("opening QRTR UIM service: %w", err)
	}
	return New(conn), nil
}
