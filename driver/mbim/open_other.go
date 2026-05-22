//go:build !linux

package mbim

import (
	"errors"
	"net"
)

func openProxyConnection() (net.Conn, error) {
	return nil, errors.New("opening MBIM reader: mbim-proxy is only supported on linux")
}
