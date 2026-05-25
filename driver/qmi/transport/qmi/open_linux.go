//go:build linux

package qmi

import (
	"fmt"
	"net"

	"github.com/damonto/ims-client/driver/qmi/protocol"
)

func Open() (protocol.Transport, error) {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: "\x00qmi-proxy", Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("connecting to qmi-proxy: %w", err)
	}
	return New(conn), nil
}
