//go:build linux

package mbim

import "net"

func openProxyConnection() (net.Conn, error) {
	return net.DialUnix("unix", nil, &net.UnixAddr{Name: "\x00mbim-proxy", Net: "unix"})
}
