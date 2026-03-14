//go:build linux

package qmi

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/damonto/ims-client/driver/qmi/core"
)

func Open() (core.Transport, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("creating qmi-proxy socket: %w", err)
	}
	if err := syscall.Connect(fd, &syscall.SockaddrUnix{Name: "\x00qmi-proxy"}); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("connecting to qmi-proxy: %w", err)
	}

	file := os.NewFile(uintptr(fd), "ims-client-qmi-proxy")
	conn, err := net.FileConn(file)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("wrapping qmi-proxy socket: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("closing qmi-proxy file wrapper: %w", err)
	}
	return New(conn), nil
}
