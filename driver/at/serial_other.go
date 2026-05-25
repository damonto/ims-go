//go:build !linux && !windows

package at

import (
	"errors"
	"io"
)

func openSerialPort(string, int) (io.ReadWriteCloser, error) {
	return nil, errors.New("opening AT reader: supported only on linux and windows")
}
