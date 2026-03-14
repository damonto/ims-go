package usim

import "strings"

type ServiceCentre struct {
	Address string
	PSI     string
}

func (s ServiceCentre) Target() string {
	if psi := strings.TrimSpace(s.PSI); psi != "" {
		return psi
	}
	address := strings.TrimSpace(s.Address)
	if address == "" {
		return ""
	}
	return "tel:" + address
}
