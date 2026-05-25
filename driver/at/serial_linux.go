//go:build linux

package at

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const linuxReadTimeoutDeciseconds = 50

type serialPort struct {
	file       *os.File
	oldTermios *unix.Termios
}

func openSerialPort(name string, baudRate int) (io.ReadWriteCloser, error) {
	fd, err := unix.Open(name, unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0o666)
	if err != nil {
		return nil, err
	}

	oldTermios, err := setTermios(fd, baudRate)
	if err != nil {
		return nil, errors.Join(err, unix.Close(fd))
	}
	if err := flushSerial(fd); err != nil {
		return nil, errors.Join(err, unix.IoctlSetTermios(fd, unix.TCSETS, oldTermios), unix.Close(fd))
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		return nil, errors.Join(err, unix.IoctlSetTermios(fd, unix.TCSETS, oldTermios), unix.Close(fd))
	}

	return &serialPort{
		file:       os.NewFile(uintptr(fd), name),
		oldTermios: oldTermios,
	}, nil
}

func setTermios(fd int, baudRate int) (*unix.Termios, error) {
	baud, err := baudConstant(baudRate)
	if err != nil {
		return nil, err
	}
	oldTermios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, fmt.Errorf("reading termios: %w", err)
	}

	termios := *oldTermios
	termios.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON | unix.IXOFF | unix.IXANY
	termios.Oflag &^= unix.OPOST
	termios.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	termios.Cflag &^= unix.CSIZE | unix.PARENB | unix.CSTOPB | unix.CRTSCTS | unix.CBAUD
	termios.Cflag |= unix.CS8 | unix.CLOCAL | unix.CREAD | baud
	termios.Ispeed = baud
	termios.Ospeed = baud
	termios.Cc[unix.VMIN] = 0
	termios.Cc[unix.VTIME] = linuxReadTimeoutDeciseconds
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &termios); err != nil {
		return nil, fmt.Errorf("writing termios: %w", err)
	}
	return oldTermios, nil
}

func flushSerial(fd int) error {
	return unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIOFLUSH)
}

func (p *serialPort) Read(buf []byte) (int, error) {
	n, err := p.file.Read(buf)
	if n == 0 && err == nil {
		return 0, errReadTimeout
	}
	return n, err
}

func (p *serialPort) Write(data []byte) (int, error) {
	return p.file.Write(data)
}

func (p *serialPort) Close() error {
	var errs []error
	if p.oldTermios != nil {
		if err := unix.IoctlSetTermios(int(p.file.Fd()), unix.TCSETS, p.oldTermios); err != nil {
			errs = append(errs, fmt.Errorf("restoring termios: %w", err))
		}
	}
	if err := p.file.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing serial port: %w", err))
	}
	return errors.Join(errs...)
}

func baudConstant(baudRate int) (uint32, error) {
	switch baudRate {
	case 9600:
		return unix.B9600, nil
	case 19200:
		return unix.B19200, nil
	case 38400:
		return unix.B38400, nil
	case 57600:
		return unix.B57600, nil
	case 115200:
		return unix.B115200, nil
	case 230400:
		return unix.B230400, nil
	case 460800:
		return unix.B460800, nil
	default:
		return 0, fmt.Errorf("configuring serial port: unsupported baud rate %d", baudRate)
	}
}
