//go:build windows

package ims

import (
	"math/bits"

	"golang.org/x/sys/windows"
)

const (
	windowsIPUnicastInterface   = 31
	windowsIPv6UnicastInterface = 31
)

func bindVoLTESocket(fd uintptr, _ string, interfaceIndex int, ipv6 bool) error {
	if ipv6 {
		return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windowsIPv6UnicastInterface, interfaceIndex)
	}
	// Winsock expects the IPv4 interface index in network byte order.
	value := int(bits.ReverseBytes32(uint32(interfaceIndex)))
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windowsIPUnicastInterface, value)
}
