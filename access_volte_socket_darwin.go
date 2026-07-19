//go:build darwin

package ims

import "golang.org/x/sys/unix"

func bindVoLTESocket(fd uintptr, _ string, interfaceIndex int, ipv6 bool) error {
	if ipv6 {
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, interfaceIndex)
	}
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, interfaceIndex)
}
