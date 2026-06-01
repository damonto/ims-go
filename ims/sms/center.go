package sms

import (
	"errors"
	"strings"

	"github.com/damonto/vowifi-go/usim"
)

func (s *Service) resolveServiceCenter() (serviceCenter, error) {
	cfgValue := strings.TrimSpace(s.cfg.ServiceCenter)
	cardCenter := usim.ServiceCenter{Address: strings.TrimSpace(s.card.SMSC())}
	if provider, ok := s.card.(serviceCenterProvider); ok {
		cardCenter = provider.ServiceCenter()
		cardCenter.Address = strings.TrimSpace(cardCenter.Address)
		cardCenter.PSI = strings.TrimSpace(cardCenter.PSI)
		if cardCenter.Address == "" {
			cardCenter.Address = strings.TrimSpace(s.card.SMSC())
		}
	}

	sc := serviceCenter{
		target:  cardCenter.Target(),
		address: cardCenter.Address,
	}
	if cfgValue != "" {
		sc.target = serviceCenterTarget(cfgValue)
		if address := serviceCenterAddress(cfgValue); address != "" {
			sc.address = address
		}
	}
	if sc.target == "" && sc.address != "" {
		sc.target = "tel:" + sc.address
	}
	if sc.target == "" {
		return serviceCenter{}, errors.New("sending SMS: service center target is empty")
	}
	if sc.address == "" {
		return serviceCenter{}, errors.New("sending SMS: SMSC address is empty")
	}
	return sc, nil
}

func serviceCenterTarget(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") || strings.HasPrefix(lower, "tel:") {
		return value
	}
	return "tel:" + value
}

func serviceCenterAddress(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "tel:") {
		return strings.TrimSpace(value[len("tel:"):])
	}
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") {
		return ""
	}
	return value
}
