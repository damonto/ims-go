package vowifi

import (
	"strings"

	swutunnel "github.com/damonto/vowifi-go/swu/tunnel"
)

type swuPDNTypeRestrictionGate struct {
	entries map[swuPDNTypeRestrictionKey]swutunnel.PDNType
}

type swuPDNTypeRestrictionKey struct {
	mcc string
	mnc string
	apn string
}

func (c *Client) recordSWUPDNTypeRestriction(info swutunnel.Info) {
	restriction := info.PDNTypeRestriction
	if restriction != swutunnel.PDNTypeIPv4 && restriction != swutunnel.PDNTypeIPv6 {
		return
	}
	c.withStateLock(func(s *clientState) {
		key, ok := swuPDNTypeRestrictionKeyFor(c.card, c.cfg.Tunnel)
		if !ok {
			return
		}
		if s.swuPDNTypes.entries == nil {
			s.swuPDNTypes.entries = make(map[swuPDNTypeRestrictionKey]swutunnel.PDNType)
		}
		s.swuPDNTypes.entries[key] = restriction
	})
}

func (c *Client) applySWUPDNTypeRestriction(cfg *swutunnel.Config) {
	var restriction swutunnel.PDNType
	c.withStateLock(func(s *clientState) {
		key, ok := swuPDNTypeRestrictionKeyFor(c.card, *cfg)
		if !ok {
			return
		}
		restriction = s.swuPDNTypes.entries[key]
	})
	if restriction == swutunnel.PDNTypeIPv4 || restriction == swutunnel.PDNTypeIPv6 {
		cfg.PDNType = restriction
	}
}

func (c *Client) clearSWUPDNTypeRestrictionAfterDisconnect(cause error) {
	if !swutunnel.PDNDeactivated(cause) || swutunnel.ReactivationRequested(cause) {
		return
	}
	c.clearSWUPDNTypeRestriction()
}

func (c *Client) clearSWUPDNTypeRestriction() {
	c.withStateLock(func(s *clientState) {
		key, ok := swuPDNTypeRestrictionKeyFor(c.card, c.cfg.Tunnel)
		if !ok || len(s.swuPDNTypes.entries) == 0 {
			return
		}
		delete(s.swuPDNTypes.entries, key)
	})
}

func swuPDNTypeRestrictionKeyFor(card Card, cfg swutunnel.Config) (swuPDNTypeRestrictionKey, bool) {
	if card == nil {
		return swuPDNTypeRestrictionKey{}, false
	}
	mcc, mnc, ok := normalizedBackoffPLMN(card)
	if !ok {
		return swuPDNTypeRestrictionKey{}, false
	}
	return swuPDNTypeRestrictionKey{
		mcc: mcc,
		mnc: mnc,
		apn: swuPDNTypeRestrictionAPNFor(cfg),
	}, true
}

func swuPDNTypeRestrictionAPNFor(cfg swutunnel.Config) string {
	apn := strings.ToLower(strings.TrimSpace(cfg.APN))
	if apn == "" {
		return swutunnel.DefaultAPN
	}
	return apn
}
