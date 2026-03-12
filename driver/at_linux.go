//go:build linux

package driver

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

type atSerialPort struct {
	file       *os.File
	oldTermios *unix.Termios
}

func openATSerialPort(name string, baudRate int) (io.ReadWriteCloser, error) {
	file, err := os.OpenFile(name, os.O_RDWR|unix.O_NOCTTY, 0o666)
	if err != nil {
		return nil, err
	}
	port := &atSerialPort{file: file}
	if err := port.setTermios(baudRate); err != nil {
		_ = file.Close()
		return nil, err
	}
	return port, nil
}

func (p *atSerialPort) setTermios(baudRate int) error {
	baud, err := atBaudConstant(baudRate)
	if err != nil {
		return err
	}
	fd := int(p.file.Fd())
	oldTermios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return fmt.Errorf("reading termios: %w", err)
	}
	p.oldTermios = oldTermios

	termios := unix.Termios{
		Ispeed: baud,
		Ospeed: baud,
	}
	termios.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	termios.Oflag &^= unix.OPOST
	termios.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	termios.Cflag &^= unix.CSIZE | unix.PARENB
	termios.Cflag |= unix.CS8 | unix.CLOCAL | unix.CREAD
	termios.Cc[unix.VMIN] = 1
	termios.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &termios); err != nil {
		return fmt.Errorf("writing termios: %w", err)
	}
	return nil
}

func (p *atSerialPort) Read(buf []byte) (int, error) {
	return p.file.Read(buf)
}

func (p *atSerialPort) Write(data []byte) (int, error) {
	return p.file.Write(data)
}

func (p *atSerialPort) Close() error {
	if p.oldTermios != nil {
		if err := unix.IoctlSetTermios(int(p.file.Fd()), unix.TCSETS, p.oldTermios); err != nil {
			_ = p.file.Close()
			return fmt.Errorf("restoring termios: %w", err)
		}
	}
	if err := p.file.Close(); err != nil {
		return fmt.Errorf("closing serial port: %w", err)
	}
	return nil
}

func atBaudConstant(baudRate int) (uint32, error) {
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
