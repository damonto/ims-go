package registration

import (
	"net/url"
	"slices"
	"strings"
)

// Info contains the identities supplied by the network for a current registration.
// MSISDN is empty unless the associated identities identify one global number.
type Info struct {
	Registered     bool
	AssociatedURIs []string
	MSISDN         string
	// MSISDNAmbiguous distinguishes conflicting numbers from absent numbers.
	MSISDNAmbiguous bool
}

// Info returns a detached snapshot without exposing SIP security state.
func (s *Registrar) Info() Info {
	s.mu.Lock()
	info := Info{Registered: s.state.Registered}
	if info.Registered {
		info.AssociatedURIs = slices.Clone(s.state.AssociatedURIs)
	}
	s.mu.Unlock()
	info.MSISDN, info.MSISDNAmbiguous = associatedMSISDN(info.AssociatedURIs)
	return info
}

func (s *Registrar) notifyRegistrationChange() {
	if s.cfg.OnRegistrationChange != nil {
		s.cfg.OnRegistrationChange()
	}
}

func associatedMSISDN(uris []string) (string, bool) {
	var number string
	for _, uri := range uris {
		candidate := subscriberNumber(uri)
		if candidate == "" {
			continue
		}
		if number != "" && number != candidate {
			return "", true
		}
		number = candidate
	}
	return number, false
}

func subscriberNumber(uri string) string {
	scheme, subscriber, ok := strings.Cut(strings.TrimSpace(uri), ":")
	if !ok {
		return ""
	}
	switch strings.ToLower(scheme) {
	case "tel":
	case "sip", "sips":
		parsed, ok := parseComparableSIPURI(uri)
		if !ok || (parsed.parameters["user"] != "" && parsed.parameters["user"] != "phone") {
			return ""
		}
		subscriber = parsed.userinfo
	default:
		return ""
	}
	number, parameterText, _ := strings.Cut(subscriber, ";")
	parameters, ok := parseURIComponents(parameterText, ";")
	if !ok {
		return ""
	}
	for name := range parameters {
		// A local context is not an E.164 prefix. Extensions and subaddresses
		// identify endpoints that cannot be represented by a bare MSISDN.
		if name == "phone-context" || name == "ext" || name == "isub" || strings.HasPrefix(name, "m-") {
			return ""
		}
	}
	number, err := url.PathUnescape(number)
	if err != nil || !strings.HasPrefix(number, "+") {
		return ""
	}
	var normalized strings.Builder
	normalized.WriteByte('+')
	for _, digit := range number[1:] {
		switch {
		case digit >= '0' && digit <= '9':
			normalized.WriteRune(digit)
		case digit == '-' || digit == '.' || digit == '(' || digit == ')':
		default:
			return ""
		}
	}
	number = normalized.String()
	if len(number) < 2 || len(number) > 16 || number[1] == '0' {
		return ""
	}
	return number
}
