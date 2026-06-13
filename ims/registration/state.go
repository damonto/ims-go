package registration

import (
	"strings"
	"time"

	"github.com/damonto/vowifi-go/ims/sip"
)

func associatedURIsFromMessage(msg sip.Message) []string {
	uris := make([]string, 0)
	for _, value := range msg.HeadersByName("P-Associated-URI") {
		for _, part := range sip.SplitHeaderList(value) {
			if uri := strings.TrimSpace(sip.AddressURI(part)); uri != "" {
				uris = append(uris, uri)
			}
		}
	}
	return uris
}

func registerResponseExpires(msg sip.Message, contactURI string) (time.Duration, bool) {
	for _, value := range msg.HeadersByName("Contact") {
		for _, part := range sip.SplitHeaderList(value) {
			uri, params := sip.AddressURIAndParams(part)
			if uri == "" || !sameContactURI(uri, contactURI) {
				continue
			}
			if expires, ok := parsePositiveSeconds(sip.HeaderParam(params, "expires")); ok {
				return expires, true
			}
		}
	}
	return parsePositiveSeconds(msg.Header("Expires"))
}

func sameContactURI(got, want string) bool {
	got = strings.TrimSpace(got)
	want = strings.TrimSpace(want)
	if strings.EqualFold(got, want) {
		return true
	}
	gotHostPort := contactURIHostPort(got)
	wantHostPort := contactURIHostPort(want)
	return gotHostPort != "" && strings.EqualFold(gotHostPort, wantHostPort)
}

func contactURIHostPort(uri string) string {
	uri = strings.TrimSpace(uri)
	uri = strings.TrimPrefix(strings.ToLower(uri), "sip:")
	if user, hostPort, ok := strings.Cut(uri, "@"); ok && user != "" {
		uri = hostPort
	}
	if hostPort, _, ok := strings.Cut(uri, ";"); ok {
		uri = hostPort
	}
	return strings.TrimSpace(uri)
}

func (s *Service) currentRegisterContactURI() string {
	flow := s.CurrentFlow()
	port := flow.RegisterPort
	if flow.MessagePort != 0 {
		port = flow.MessagePort
	}
	return contactURI(flow.ContactHost, port)
}

func (s *Service) applyAssociatedURI(msg sip.Message) {
	uris := associatedURIsFromMessage(msg)
	if len(uris) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.DefaultPublicID = uris[0]
	s.state.SIPPublicID = ""
	s.state.TelPublicID = ""
	for _, uri := range uris {
		lower := strings.ToLower(uri)
		if (strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:")) && s.state.SIPPublicID == "" {
			s.state.SIPPublicID = uri
		}
		if strings.HasPrefix(lower, "tel:") && s.state.TelPublicID == "" {
			s.state.TelPublicID = uri
		}
	}
}

func (s *Service) applyServiceRoutes(msg sip.Message) {
	routes := serviceRoutesFromMessage(msg)
	s.mu.Lock()
	s.flow.ServiceRoutes = append([]string(nil), routes...)
	s.mu.Unlock()
}

func serviceRoutesFromMessage(msg sip.Message) []string {
	routes := make([]string, 0)
	for _, value := range msg.HeadersByName("Service-Route") {
		for _, route := range sip.SplitHeaderList(value) {
			uri := strings.ToLower(strings.TrimSpace(sip.AddressURI(route)))
			if strings.HasPrefix(uri, "sip:") || strings.HasPrefix(uri, "sips:") {
				routes = append(routes, route)
			}
		}
	}
	return routes
}

func (s *Service) currentRegisterExpires() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.RegisterExpires > 0 {
		return s.state.RegisterExpires
	}
	return s.cfg.RegisterExpires
}

func (s *Service) setRegisterExpires(expires time.Duration) {
	if expires <= 0 {
		return
	}
	s.mu.Lock()
	s.state.RegisterExpires = expires
	s.mu.Unlock()
}

func (s *Service) registerExpiresSeconds() int {
	return expiresSeconds(s.currentRegisterExpires())
}

func expiresSeconds(expires time.Duration) int {
	seconds := int(expires / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

func (s *Service) refreshInterval() time.Duration {
	return refreshIntervalFor(s.currentRegisterExpires())
}

func (s *Service) applyRegisterExpires(msg sip.Message) {
	expires, ok := registerResponseExpires(msg, s.currentRegisterContactURI())
	if !ok {
		return
	}
	s.setRegisterExpires(expires)
}

func (s *Service) applyRegisterSuccess(msg sip.Message) {
	s.resetRegInfoState()
	s.applyAssociatedURI(msg)
	s.applyServiceRoutes(msg)
	s.applyAuthenticationInfo(msg)
	s.applyRegisterExpires(msg)
	s.extendActiveSecureAssociationLifetime(s.secureAssociationExpiresAt(time.Now()))
	s.setRegistered(true)
	s.applyRegisterKeepAlive(msg)
}

func (s *Service) setRegistered(registered bool) {
	s.mu.Lock()
	s.state.Registered = registered
	s.mu.Unlock()
}

func (s *Service) isRegistered() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Registered
}
