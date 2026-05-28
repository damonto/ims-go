package sms

import (
	"errors"
	"github.com/damonto/vowifi-go/usim"
	"strings"
)

func (s *Service) resolveServiceCentre() (serviceCentre, error) {
	cfgValue := strings.TrimSpace(s.cfg.ServiceCenter)
	cardCentre := usim.ServiceCentre{Address: strings.TrimSpace(s.card.SMSC())}
	if provider, ok := s.card.(serviceCentreProvider); ok {
		cardCentre = provider.ServiceCentre()
		cardCentre.Address = strings.TrimSpace(cardCentre.Address)
		cardCentre.PSI = strings.TrimSpace(cardCentre.PSI)
		if cardCentre.Address == "" {
			cardCentre.Address = strings.TrimSpace(s.card.SMSC())
		}
	}

	sc := serviceCentre{
		target:  cardCentre.Target(),
		address: cardCentre.Address,
	}
	if cfgValue != "" {
		sc.target = serviceCentreTarget(cfgValue)
		if address := serviceCentreAddress(cfgValue); address != "" {
			sc.address = address
		}
	}
	if sc.target == "" && sc.address != "" {
		sc.target = "tel:" + sc.address
	}
	if sc.target == "" {
		return serviceCentre{}, errors.New("sending SMS: service centre target is empty")
	}
	if sc.address == "" {
		return serviceCentre{}, errors.New("sending SMS: SMSC address is empty")
	}
	return sc, nil
}

func serviceCentreTarget(value string) string {
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

func serviceCentreAddress(value string) string {
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
