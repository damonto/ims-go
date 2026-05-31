package tunnel

import (
	"errors"
	"net"
)

var ErrPCSCFReselectionRequested = errors.New("p-cscf reselection requested")

type pcscfReselectionError struct {
	info Info
}

func (e *pcscfReselectionError) Error() string {
	return ErrPCSCFReselectionRequested.Error()
}

func (e *pcscfReselectionError) Is(target error) bool {
	return target == ErrPCSCFReselectionRequested
}

func (e *pcscfReselectionError) Info() Info {
	return cloneInfo(e.info)
}

type pcscfReselectionInfoCarrier interface {
	Info() Info
}

func PCSCFReselectionRequested(err error) bool {
	return errors.Is(err, ErrPCSCFReselectionRequested)
}

func PCSCFReselectionInfo(err error) (Info, bool) {
	var carrier pcscfReselectionInfoCarrier
	if !errors.As(err, &carrier) {
		return Info{}, false
	}
	return carrier.Info(), true
}

func pcscfReselectionRequestedError(info Info) error {
	return &pcscfReselectionError{info: cloneInfo(info)}
}

func pcscfInfoFromAddresses(previous Info, ips []net.IP) Info {
	info := cloneInfo(previous)
	info.PCSCFIPs = cloneIPList(ips)
	info.PCSCFIP = nil
	if len(info.PCSCFIPs) != 0 {
		info.PCSCFIP = append(net.IP(nil), info.PCSCFIPs[0]...)
	}
	return info
}
