package usim

import "strings"

type ServiceCenter struct {
	Address string
	PSI     string
}

func (s ServiceCenter) Target() string {
	if psi := strings.TrimSpace(s.PSI); psi != "" {
		return psi
	}
	address := strings.TrimSpace(s.Address)
	if address == "" {
		return ""
	}
	return "tel:" + address
}
