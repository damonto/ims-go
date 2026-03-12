//go:build !linux && !windows

package driver

import (
	"errors"
	"io"
)

func openATSerialPort(string, int) (io.ReadWriteCloser, error) {
	return nil, errors.New("opening AT driver: supported only on linux and windows")
}
