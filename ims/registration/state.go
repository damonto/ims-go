package registration

import (
	"strings"
	"time"

	"github.com/damonto/ims-go/ims/security"
	"github.com/damonto/ims-go/ims/sip"
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
	gotURI, gotOK := parseComparableSIPURI(got)
	wantURI, wantOK := parseComparableSIPURI(want)
	if !gotOK || !wantOK {
		return false
	}
	return gotURI.scheme == wantURI.scheme &&
		gotURI.userinfo == wantURI.userinfo &&
		strings.EqualFold(gotURI.hostPort, wantURI.hostPort) &&
		uriParametersMatch(gotURI.parameters, wantURI.parameters) &&
		uriComponentsMatch(gotURI.headers, wantURI.headers)
}

type comparableSIPURI struct {
	scheme     string
	userinfo   string
	hostPort   string
	parameters map[string]string
	headers    map[string]string
}

func parseComparableSIPURI(value string) (comparableSIPURI, bool) {
	value = strings.TrimSpace(value)
	colon := strings.IndexByte(value, ':')
	if colon <= 0 {
		return comparableSIPURI{}, false
	}
	scheme := strings.ToLower(value[:colon])
	if scheme != "sip" && scheme != "sips" {
		return comparableSIPURI{}, false
	}
	rest := value[colon+1:]
	userinfo := ""
	if at := strings.IndexByte(rest, '@'); at >= 0 {
		userinfo = normalizeURIPercentEncoding(rest[:at])
		rest = rest[at+1:]
		if userinfo == "" || rest == "" {
			return comparableSIPURI{}, false
		}
	}
	rest, headerText, _ := strings.Cut(rest, "?")
	authority, parameterText, _ := strings.Cut(rest, ";")
	if authority == "" || strings.ContainsAny(authority, " \t\r\n") {
		return comparableSIPURI{}, false
	}
	hostPort := authority
	parameters, parametersOK := parseURIComponents(parameterText, ";")
	headers, headersOK := parseURIComponents(headerText, "&")
	if !parametersOK || !headersOK {
		return comparableSIPURI{}, false
	}
	return comparableSIPURI{
		scheme:     scheme,
		userinfo:   userinfo,
		hostPort:   hostPort,
		parameters: parameters,
		headers:    headers,
	}, true
}

func parseURIComponents(value, separator string) (map[string]string, bool) {
	if value == "" {
		return nil, true
	}
	components := make(map[string]string)
	for component := range strings.SplitSeq(value, separator) {
		name, componentValue, hasValue := strings.Cut(strings.TrimSpace(component), "=")
		name = strings.ToLower(normalizeURIPercentEncoding(name))
		if name == "" {
			return nil, false
		}
		if _, exists := components[name]; exists {
			return nil, false
		}
		if hasValue {
			componentValue = strings.ToLower(normalizeURIPercentEncoding(strings.TrimSpace(componentValue)))
		} else {
			componentValue = ""
		}
		components[name] = componentValue
	}
	return components, true
}

func uriParametersMatch(left, right map[string]string) bool {
	for name, leftValue := range left {
		if rightValue, ok := right[name]; ok && leftValue != rightValue {
			return false
		}
	}
	for _, name := range []string{"transport", "user", "ttl", "method", "maddr"} {
		_, leftHas := left[name]
		_, rightHas := right[name]
		if leftHas != rightHas {
			return false
		}
	}
	return true
}

func uriComponentsMatch(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for name, leftValue := range left {
		if rightValue, ok := right[name]; !ok || leftValue != rightValue {
			return false
		}
	}
	return true
}

func normalizeURIPercentEncoding(value string) string {
	var normalized strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '%' || i+2 >= len(value) {
			normalized.WriteByte(value[i])
			continue
		}
		high, highOK := hexDigit(value[i+1])
		low, lowOK := hexDigit(value[i+2])
		if !highOK || !lowOK {
			normalized.WriteByte(value[i])
			continue
		}
		decoded := high<<4 | low
		if uriUnreserved(decoded) {
			normalized.WriteByte(decoded)
		} else {
			normalized.WriteByte('%')
			normalized.WriteByte("0123456789ABCDEF"[high])
			normalized.WriteByte("0123456789ABCDEF"[low])
		}
		i += 2
	}
	return normalized.String()
}

func hexDigit(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func uriUnreserved(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' ||
		strings.ContainsRune("-_.!~*'()", rune(value))
}

func (s *Registrar) currentRegisterContactURI() string {
	flow := s.CurrentFlow()
	port := flow.RegisterPort
	if flow.MessagePort != 0 {
		port = flow.MessagePort
	}
	return contactURI(flow.ContactHost, port)
}

func (s *Registrar) applyAssociatedURI(msg sip.Message) {
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

func (s *Registrar) applyServiceRoutes(msg sip.Message) {
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

func (s *Registrar) currentRegisterExpires() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.RegisterExpires > 0 {
		return s.state.RegisterExpires
	}
	return s.cfg.RegisterExpires
}

func (s *Registrar) setRegisterExpires(expires time.Duration) {
	if expires <= 0 {
		return
	}
	s.mu.Lock()
	s.state.RegisterExpires = expires
	s.mu.Unlock()
}

func (s *Registrar) registerExpiresSeconds() int {
	return expiresSeconds(s.currentRegisterExpires())
}

func expiresSeconds(expires time.Duration) int {
	seconds := int(expires / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

func (s *Registrar) refreshInterval() time.Duration {
	return refreshIntervalFor(s.currentRegisterExpires())
}

func (s *Registrar) applyRegisterExpires(msg sip.Message) {
	expires, ok := registerResponseExpires(msg, s.currentRegisterContactURI())
	if !ok {
		return
	}
	s.setRegisterExpires(expires)
}

func (s *Registrar) applyRegisterSuccess(msg sip.Message) {
	s.resetRegInfoState()
	s.rememberRegisterTransaction(msg)
	s.applyAssociatedURI(msg)
	s.applyServiceRoutes(msg)
	s.applyAuthenticationInfo(msg)
	s.applyRegisterExpires(msg)
	s.extendActiveSecureAssociationLifetime(s.secureAssociationExpiresAt(time.Now()))
	s.setRegistered(true)
	s.applyRegisterKeepAlive(msg)
}

func (s *Registrar) clearRegistrationState() error {
	secureErr := s.clearSecureResources()
	s.resetRegistrationState()
	return secureErr
}

func (s *Registrar) resetRegistrationState() {
	flow := s.CurrentFlow()
	nextFlow := newFlow(flow.ContactHost, flow.RegisterPort, ipsecAlgorithmsFromConfig(s.cfg))
	callID, sessionID, tag, _ := sip.NewTransaction()

	s.mu.Lock()
	s.state.Registered = false
	s.state.DefaultPublicID = s.state.PublicIdentity
	s.state.SIPPublicID = ""
	s.state.TelPublicID = ""
	s.state.RegisterExpires = s.cfg.RegisterExpires
	s.state.Flow = Flow{}
	s.state.ServiceRoutes = nil
	s.state.SecurityClient = nextFlow.SecurityClient
	s.state.SecurityClients = append(security.Params(nil), nextFlow.SecurityClients...)
	s.state.SecurityVerify = nil
	s.state.ContactHost = nextFlow.ContactHost
	s.state.RegisterPort = nextFlow.RegisterPort
	s.state.MessagePort = nextFlow.MessagePort
	s.flow = nextFlow
	s.authCK = nil
	s.authIK = nil
	s.authNonce = ""
	s.authRealm = ""
	s.authAlgorithm = ""
	s.authQOP = ""
	s.authOpaque = ""
	s.authHeader = ""
	s.authNonceCount = 0
	s.authDigestNonce = ""
	s.authDigestAlgorithm = ""
	s.authDigestPassword = ""
	s.callID = callID
	s.sessionID = sessionID
	s.tag = tag
	s.cseq = 0
	s.lastRegisterCallID = ""
	s.lastRegisterCSeq = 0
	s.subscribeExpires = 0
	s.subscribeUnsupported = false
	s.subscription = subscriptionDialog{}
	s.regInfoVersion = 0
	s.regInfoVersionSet = false
	s.regInfoRegistrations = make(map[string]regInfoRegistrationEntry)
	s.mu.Unlock()
}

func (s *Registrar) rememberRegisterTransaction(msg sip.Message) {
	callID := strings.TrimSpace(msg.Header("Call-ID"))
	cseq := sip.CSeqNumber(msg.Header("CSeq"))
	if callID == "" || cseq <= 0 {
		return
	}
	s.mu.Lock()
	s.lastRegisterCallID = callID
	s.lastRegisterCSeq = cseq
	s.mu.Unlock()
}

func (s *Registrar) setRegistered(registered bool) {
	s.mu.Lock()
	s.state.Registered = registered
	s.mu.Unlock()
}

func (s *Registrar) isRegistered() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Registered
}
