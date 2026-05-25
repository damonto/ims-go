//go:build windows

package at

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	readWriteTimeout = 30_000
	flagBinary       = 0x00000001
	flagParity       = 0x00000002
	dtrControlMask   = windows.DTR_CONTROL_ENABLE | windows.DTR_CONTROL_HANDSHAKE
	rtsControlMask   = windows.RTS_CONTROL_ENABLE | windows.RTS_CONTROL_HANDSHAKE | windows.RTS_CONTROL_TOGGLE
)

type serialPort struct {
	handle     windows.Handle
	readEvent  windows.Handle
	writeEvent windows.Handle
}

func openSerialPort(name string, baudRate int) (io.ReadWriteCloser, error) {
	device := windowsSerialDevice(name)
	deviceUTF16, err := windows.UTF16PtrFromString(device)
	if err != nil {
		return nil, fmt.Errorf("encoding serial device %q: %w", name, err)
	}

	handle, err := windows.CreateFile(
		deviceUTF16,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("opening serial device %q: %w", device, err)
	}

	readEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("creating serial read event: %w", err)
	}
	writeEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(readEvent)
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("creating serial write event: %w", err)
	}

	port := &serialPort{
		handle:     handle,
		readEvent:  readEvent,
		writeEvent: writeEvent,
	}
	if err := port.configure(baudRate); err != nil {
		_ = port.Close()
		return nil, err
	}
	return port, nil
}

func windowsSerialDevice(name string) string {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, `\\.\`) {
		return name
	}
	return `\\.\` + name
}

func (p *serialPort) configure(baudRate int) error {
	if err := windows.SetupComm(p.handle, 4096, 4096); err != nil {
		return fmt.Errorf("configuring serial buffers: %w", err)
	}

	var dcb windows.DCB
	dcb.DCBlength = uint32(unsafe.Sizeof(dcb))
	if err := windows.GetCommState(p.handle, &dcb); err != nil {
		return fmt.Errorf("reading comm state: %w", err)
	}
	dcb.BaudRate = uint32(baudRate)
	dcb.ByteSize = 8
	dcb.Parity = windows.NOPARITY
	dcb.StopBits = windows.ONESTOPBIT
	dcb.Flags |= flagBinary
	dcb.Flags &^= flagParity
	dcb.Flags &^= dtrControlMask
	dcb.Flags |= windows.DTR_CONTROL_ENABLE
	dcb.Flags &^= rtsControlMask
	dcb.Flags |= windows.RTS_CONTROL_ENABLE
	if err := windows.SetCommState(p.handle, &dcb); err != nil {
		return fmt.Errorf("writing comm state: %w", err)
	}

	timeouts := windows.CommTimeouts{
		ReadIntervalTimeout:         50,
		ReadTotalTimeoutMultiplier:  10,
		ReadTotalTimeoutConstant:    50,
		WriteTotalTimeoutMultiplier: 10,
		WriteTotalTimeoutConstant:   50,
	}
	if err := windows.SetCommTimeouts(p.handle, &timeouts); err != nil {
		return fmt.Errorf("writing comm timeouts: %w", err)
	}
	if err := windows.PurgeComm(p.handle, windows.PURGE_RXCLEAR|windows.PURGE_TXCLEAR); err != nil {
		return fmt.Errorf("purging serial buffers: %w", err)
	}
	return nil
}

func (p *serialPort) Read(buf []byte) (int, error) {
	if err := windows.ResetEvent(p.readEvent); err != nil {
		return 0, fmt.Errorf("resetting serial read event: %w", err)
	}
	overlapped := windows.Overlapped{HEvent: p.readEvent}
	var bytesRead uint32

	err := windows.ReadFile(p.handle, buf, &bytesRead, &overlapped)
	if err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, fmt.Errorf("reading serial port: %w", err)
	}
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		waitStatus, waitErr := windows.WaitForSingleObject(p.readEvent, readWriteTimeout)
		if waitErr != nil {
			return 0, fmt.Errorf("waiting for serial read: %w", waitErr)
		}
		switch waitStatus {
		case uint32(windows.WAIT_OBJECT_0):
		case uint32(windows.WAIT_TIMEOUT):
			_ = windows.CancelIoEx(p.handle, &overlapped)
			return 0, errors.New("reading serial port: timeout")
		default:
			return 0, fmt.Errorf("waiting for serial read: unexpected status %d", waitStatus)
		}
	}

	if err := windows.GetOverlappedResult(p.handle, &overlapped, &bytesRead, false); err != nil {
		return 0, fmt.Errorf("reading serial port: %w", err)
	}
	return int(bytesRead), nil
}

func (p *serialPort) Write(buf []byte) (int, error) {
	if err := windows.ResetEvent(p.writeEvent); err != nil {
		return 0, fmt.Errorf("resetting serial write event: %w", err)
	}
	overlapped := windows.Overlapped{HEvent: p.writeEvent}
	var bytesWritten uint32

	err := windows.WriteFile(p.handle, buf, &bytesWritten, &overlapped)
	if err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, fmt.Errorf("writing serial port: %w", err)
	}
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		waitStatus, waitErr := windows.WaitForSingleObject(p.writeEvent, readWriteTimeout)
		if waitErr != nil {
			return 0, fmt.Errorf("waiting for serial write: %w", waitErr)
		}
		switch waitStatus {
		case uint32(windows.WAIT_OBJECT_0):
		case uint32(windows.WAIT_TIMEOUT):
			_ = windows.CancelIoEx(p.handle, &overlapped)
			return 0, errors.New("writing serial port: timeout")
		default:
			return 0, fmt.Errorf("waiting for serial write: unexpected status %d", waitStatus)
		}
	}

	if err := windows.GetOverlappedResult(p.handle, &overlapped, &bytesWritten, false); err != nil {
		return 0, fmt.Errorf("writing serial port: %w", err)
	}
	return int(bytesWritten), nil
}

func (p *serialPort) Close() error {
	var errs []error
	if p.handle != 0 {
		if err := windows.EscapeCommFunction(p.handle, windows.CLRDTR); err != nil {
			errs = append(errs, fmt.Errorf("clearing DTR: %w", err))
		}
		if err := windows.CancelIoEx(p.handle, nil); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			errs = append(errs, fmt.Errorf("canceling serial I/O: %w", err))
		}
		if err := windows.PurgeComm(p.handle, windows.PURGE_RXABORT|windows.PURGE_TXABORT|windows.PURGE_RXCLEAR|windows.PURGE_TXCLEAR); err != nil {
			errs = append(errs, fmt.Errorf("purging serial port: %w", err))
		}
		if err := windows.CloseHandle(p.handle); err != nil {
			errs = append(errs, fmt.Errorf("closing serial handle: %w", err))
		}
		p.handle = 0
	}
	if p.readEvent != 0 {
		if err := windows.CloseHandle(p.readEvent); err != nil {
			errs = append(errs, fmt.Errorf("closing serial read event: %w", err))
		}
		p.readEvent = 0
	}
	if p.writeEvent != 0 {
		if err := windows.CloseHandle(p.writeEvent); err != nil {
			errs = append(errs, fmt.Errorf("closing serial write event: %w", err))
		}
		p.writeEvent = 0
	}
	return errors.Join(errs...)
}
