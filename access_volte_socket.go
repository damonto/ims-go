package ims

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
)

type voLTENetwork struct {
	interfaceName  string
	interfaceIndex int
}

var voLTEInterfaceByName = net.InterfaceByName

func newVoLTENetwork(interfaceName string) (voLTENetwork, error) {
	interfaceName = strings.TrimSpace(interfaceName)
	if interfaceName == "" {
		return voLTENetwork{}, errors.New("IMS interface is required")
	}
	ifi, err := voLTEInterfaceByName(interfaceName)
	if err != nil {
		return voLTENetwork{}, fmt.Errorf("find IMS interface %s: %w", interfaceName, err)
	}
	return voLTENetwork{interfaceName: ifi.Name, interfaceIndex: ifi.Index}, nil
}

func (n voLTENetwork) DialTCP(ctx context.Context, local, remote *net.TCPAddr) (*net.TCPConn, error) {
	if local == nil || len(local.IP) == 0 {
		return nil, errors.New("local TCP address is required")
	}
	if remote == nil || len(remote.IP) == 0 {
		return nil, errors.New("remote TCP address is required")
	}
	dialer := net.Dialer{LocalAddr: local, Control: n.control(local.IP)}
	conn, err := dialer.DialContext(ctx, "tcp", remote.String())
	if err != nil {
		return nil, err
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("TCP connection has unexpected type")
	}
	return tcp, nil
}

func (n voLTENetwork) ListenUDP(ctx context.Context, local *net.UDPAddr) (*net.UDPConn, error) {
	if local == nil || len(local.IP) == 0 {
		return nil, errors.New("local UDP address is required")
	}
	listenConfig := net.ListenConfig{Control: n.control(local.IP)}
	conn, err := listenConfig.ListenPacket(ctx, "udp", local.String())
	if err != nil {
		return nil, err
	}
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("UDP listener has unexpected type")
	}
	return udp, nil
}

func (n voLTENetwork) ListenIP(ctx context.Context, network string, local *net.IPAddr) (*net.IPConn, error) {
	if local == nil || len(local.IP) == 0 {
		return nil, errors.New("local IP address is required")
	}
	listenConfig := net.ListenConfig{Control: n.control(local.IP)}
	conn, err := listenConfig.ListenPacket(ctx, network, local.String())
	if err != nil {
		return nil, err
	}
	ip, ok := conn.(*net.IPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("IP listener has unexpected type")
	}
	return ip, nil
}

func (n voLTENetwork) ListenIPPacket(ctx context.Context, network string, local *net.IPAddr) (net.PacketConn, error) {
	return n.ListenIP(ctx, network, local)
}

func (n voLTENetwork) ListenUDPPacket(ctx context.Context, local *net.UDPAddr) (net.PacketConn, error) {
	return n.ListenUDP(ctx, local)
}

func (n voLTENetwork) control(ip net.IP) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var bindErr error
		if err := raw.Control(func(fd uintptr) {
			bindErr = bindVoLTESocket(fd, n.interfaceName, n.interfaceIndex, ip.To4() == nil)
		}); err != nil {
			return err
		}
		return bindErr
	}
}
