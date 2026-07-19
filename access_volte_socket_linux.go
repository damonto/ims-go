//go:build linux

package ims

import "golang.org/x/sys/unix"

func bindVoLTESocket(fd uintptr, interfaceName string, _ int, _ bool) error {
	return unix.BindToDevice(int(fd), interfaceName)
}
