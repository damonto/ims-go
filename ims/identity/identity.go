package identity

import (
	"net/url"
	"strings"

	"github.com/damonto/ims-go/ims/sip"
)

// MSISDN extracts an MSISDN-like number from a SIP name-addr, SIP URI, or TEL URI.
func MSISDN(value string) string {
	uri := strings.TrimSpace(sip.AddressURI(value))
	lower := strings.ToLower(uri)
	switch {
	case strings.HasPrefix(lower, "tel:"):
		return msisdnFromTELUser(uri[len("tel:"):])
	case strings.HasPrefix(lower, "sip:"):
		return msisdnFromSIPUser(uri[len("sip:"):])
	case strings.HasPrefix(lower, "sips:"):
		return msisdnFromSIPUser(uri[len("sips:"):])
	default:
		return ""
	}
}

func msisdnFromTELUser(value string) string {
	number := msisdnFromUser(value)
	if !isMSISDN(number) {
		return ""
	}
	return number
}

func msisdnFromSIPUser(value string) string {
	if before, _, ok := strings.Cut(value, "@"); ok {
		value = before
	}
	number := msisdnFromUser(value)
	if !isMSISDN(number) {
		return ""
	}
	return number
}

func msisdnFromUser(value string) string {
	if before, _, ok := strings.Cut(value, ";"); ok {
		value = before
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if unescaped, err := url.PathUnescape(value); err == nil {
		value = unescaped
	}
	return strings.TrimSpace(value)
}

func isMSISDN(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for i, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r == '+' && i == 0:
		default:
			return false
		}
	}
	return value != "+"
}
