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
	info.PCSCFIPs = nil
	for _, ip := range ips {
		if ip.To4() != nil {
			if len(info.InnerIPv4) != 0 {
				info.PCSCFIPs = appendUniqueIP(info.PCSCFIPs, ip)
			}
			continue
		}
		if ip.To16() != nil {
			if !info.InnerIPv6.IsZero() {
				info.PCSCFIPs = appendUniqueIP(info.PCSCFIPs, ip)
			}
		}
	}
	return info
}
