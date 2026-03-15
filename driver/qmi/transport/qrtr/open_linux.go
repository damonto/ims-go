//go:build linux

package qrtr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
	"unsafe"

	"github.com/damonto/ims-client/driver/qmi/core"
	"golang.org/x/sys/unix"
)

const (
	nodeBroadcast         = 0xffffffff
	portControl           = 0xfffffffe
	defaultRequestTimeout = 30 * time.Second
)

type packetType uint32

const (
	packetTypeData packetType = iota + 1
	packetTypeHello
	packetTypeBye
	packetTypeNewServer
	packetTypeDelServer
	packetTypeDelClient
	packetTypeResumeTx
	packetTypeExit
	packetTypePing
	packetTypeNewLookup
	packetTypeDelLookup
)

type sockAddr struct {
	Family uint16
	Node   uint32
	Port   uint32
}

func (s *sockAddr) Network() string {
	return "qrtr"
}

func (s *sockAddr) String() string {
	return fmt.Sprintf("qrtr://%d:%d/%d", unix.AF_QIPCRTR, s.Node, s.Port)
}

type service struct {
	Service  uint32
	Instance uint32
	Node     uint32
	Port     uint32
}

type controlPacket struct {
	Command packetType
	Service service
}

type conn struct {
	fd          int
	service     *service
	readTimeout time.Duration
}

func Open() (core.Transport, error) {
	conn, err := newConn()
	if err != nil {
		return nil, err
	}

	service, err := conn.findService(core.ServiceUIM)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	conn.service = service
	return New(conn), nil
}

func newConn() (*conn, error) {
	fd, err := unix.Socket(unix.AF_QIPCRTR, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, fmt.Errorf("creating QRTR socket: %w", err)
	}
	return &conn{fd: fd, readTimeout: defaultRequestTimeout}, nil
}

func (c *conn) findService(serviceType core.Service) (*service, error) {
	if err := c.sendControlPacket(serviceType); err != nil {
		return nil, err
	}

	timeout := time.Now().Add(5 * time.Second)
	for time.Now().Before(timeout) {
		buf := make([]byte, 1024)
		n, _, err := c.recv(buf)
		if err != nil {
			return nil, err
		}
		if n < 20 {
			continue
		}
		if packetType(binary.LittleEndian.Uint32(buf[:4])) != packetTypeNewServer {
			continue
		}

		var svc service
		if err := binary.Read(bytes.NewReader(buf[4:n]), binary.LittleEndian, &svc); err != nil {
			return nil, fmt.Errorf("reading QRTR service announcement: %w", err)
		}
		if svc.Service == uint32(serviceType) {
			return &svc, nil
		}
	}
	return nil, errors.New("finding QRTR UIM service: timeout")
}

func (c *conn) sendControlPacket(serviceType core.Service) error {
	packet := &controlPacket{
		Command: packetTypeNewLookup,
		Service: service{Service: uint32(serviceType)},
	}

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, packet); err != nil {
		return fmt.Errorf("encoding QRTR lookup packet: %w", err)
	}

	_, err := c.sendTo(&sockAddr{
		Family: unix.AF_QIPCRTR,
		Node:   nodeBroadcast,
		Port:   portControl,
	}, buf.Bytes())
	return err
}

func (c *conn) Read(b []byte) (int, error) {
	for {
		n, from, err := c.recv(b)
		if err != nil {
			return 0, err
		}
		if from.Port == portControl {
			continue
		}
		if c.service != nil && (from.Node != c.service.Node || from.Port != c.service.Port) {
			continue
		}
		return n, nil
	}
}

func (c *conn) Write(b []byte) (int, error) {
	if c.service == nil {
		return 0, errors.New("writing QRTR packet: service is not bound")
	}
	return c.sendTo(&sockAddr{
		Family: unix.AF_QIPCRTR,
		Node:   c.service.Node,
		Port:   c.service.Port,
	}, b)
}

func (c *conn) Close() error {
	return unix.Close(c.fd)
}

func (c *conn) LocalAddr() net.Addr {
	return &sockAddr{Family: unix.AF_QIPCRTR}
}

func (c *conn) RemoteAddr() net.Addr {
	if c.service == nil {
		return &sockAddr{Family: unix.AF_QIPCRTR}
	}
	return &sockAddr{
		Family: unix.AF_QIPCRTR,
		Node:   c.service.Node,
		Port:   c.service.Port,
	}
}

func (c *conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *conn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.readTimeout = defaultRequestTimeout
		return nil
	}
	c.readTimeout = max(time.Until(t), time.Millisecond)
	return nil
}

func (c *conn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *conn) sendTo(dest *sockAddr, data []byte) (int, error) {
	if len(data) == 0 {
		return 0, errors.New("writing QRTR packet: payload is empty")
	}

	n, _, errno := unix.Syscall6(
		unix.SYS_SENDTO,
		uintptr(c.fd),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		0,
		uintptr(unsafe.Pointer(dest)),
		uintptr(unsafe.Sizeof(*dest)),
	)
	if errno != 0 {
		return 0, fmt.Errorf("writing QRTR packet: %w", errno)
	}
	return int(n), nil
}

func (c *conn) recvFrom(buf []byte) (int, *sockAddr, error) {
	var addr sockAddr
	addrLen := uintptr(unsafe.Sizeof(addr))
	n, _, errno := unix.Syscall6(
		unix.SYS_RECVFROM,
		uintptr(c.fd),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&addrLen)),
	)
	if errno != 0 {
		return 0, nil, fmt.Errorf("reading QRTR packet: %w", errno)
	}
	return int(n), &addr, nil
}

func (c *conn) recv(buf []byte) (int, *sockAddr, error) {
	tv := unix.NsecToTimeval(time.Second.Nanoseconds())
	if err := unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return 0, nil, fmt.Errorf("setting QRTR receive timeout: %w", err)
	}

	timeout := time.Now().Add(c.readTimeout)
	for time.Now().Before(timeout) {
		n, from, err := c.recvFrom(buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return 0, nil, err
		}
		return n, from, nil
	}
	return 0, nil, os.ErrDeadlineExceeded
}
