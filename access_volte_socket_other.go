//go:build !linux && !darwin && !windows

package ims

import "errors"

func bindVoLTESocket(_ uintptr, _ string, _ int, _ bool) error {
	return errors.New("binding VoLTE sockets to an interface is unsupported on this platform")
}
