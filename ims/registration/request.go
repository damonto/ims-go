package registration

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/damonto/vowifi-go/ims/pidf"
	"github.com/damonto/vowifi-go/ims/security"
	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Service) buildRegister(auth *security.Authorization, verify *security.Param) sip.Message {
	return s.buildRegisterForFlow(auth, verify, s.CurrentFlow())
}

func (s *Service) buildRegisterForFlow(auth *security.Authorization, verify *security.Param, flow Flow) sip.Message {
	port := s.State().RegisterPort
	if registerUsesProtectedPort(auth, verify) {
		port = flow.SecurityClient.PortS
	}
	legacyAuthorization := ""
	if auth == nil {
		legacyAuthorization = s.initialAuthorizationValue()
	}
	return s.buildRegisterRequestForFlow(auth, legacyAuthorization, verify, flow, s.registerContactValue(port), s.registerExpiresSeconds(), port)
}

func (s *Service) buildDeregister(auth *security.Authorization, verify *security.Param) sip.Message {
	port := s.State().RegisterPort
	if registerUsesProtectedPort(auth, verify) {
		port = s.State().SecurityClient.PortS
	}
	return s.buildRegisterRequest(auth, "", verify, "*", 0, port)
}

func (s *Service) registerRealm(auth *security.Authorization) string {
	realm := strings.TrimPrefix(s.State().RegisterURI, "sip:")
	if auth == nil || strings.TrimSpace(auth.Realm) == "" {
		return realm
	}
	return auth.Realm
}

func (s *Service) initialAuthorizationValue() string {
	return (security.Authorization{
		Nonce:              "",
		URI:                s.State().RegisterURI,
		Response:           "",
		Username:           s.State().PrivateIdentity,
		Realm:              s.registerRealm(nil),
		Algorithm:          s.cfg.AuthAlgorithm,
		IntegrityProtected: registerInitialIntegrityProtectedValue(s.cfg.AuthAlgorithm),
	}).String()
}

func (s *Service) nextRegisterTransaction() (int64, string, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cseq++
	if s.cseq > maxSIPCSeq {
		callID, sessionID, tag, _ := sip.NewTransaction()
		s.callID = callID
		s.sessionID = sessionID
		s.tag = tag
		s.cseq = 1
	}
	return s.cseq, s.callID, s.sessionID, s.tag
}

func (s *Service) nextStandaloneCSeq() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cseq++
	if s.cseq > maxSIPCSeq {
		s.cseq = 1
	}
	return s.cseq
}

func (s *Service) resetRegisterTransaction() {
	callID, sessionID, tag, _ := sip.NewTransaction()
	s.mu.Lock()
	s.callID = callID
	s.sessionID = sessionID
	s.tag = tag
	s.cseq = 0
	s.mu.Unlock()
}

func (s *Service) buildRegisterRequest(auth *security.Authorization, legacyAuthorization string, verify *security.Param, contact string, expiresSeconds, port int) sip.Message {
	return s.buildRegisterRequestForFlow(auth, legacyAuthorization, verify, s.CurrentFlow(), contact, expiresSeconds, port)
}

func (s *Service) buildRegisterRequestForFlow(auth *security.Authorization, legacyAuthorization string, verify *security.Param, flow Flow, contact string, expiresSeconds, port int) sip.Message {
	_, _, _, branch := sip.NewTransaction()
	state := s.State()
	cseq, callID, sessionID, tag := s.nextRegisterTransaction()
	state.Flow = flow.clone()
	state.SecurityClient = flow.SecurityClient
	state.SecurityClients = append(security.Params(nil), flow.SecurityClients...)
	state.SecurityVerify = nil
	if flow.SecurityVerify != nil {
		verifyCopy := *flow.SecurityVerify
		state.SecurityVerify = &verifyCopy
	}
	state.ContactHost = flow.ContactHost
	state.RegisterPort = flow.RegisterPort
	state.MessagePort = flow.MessagePort
	msg := sip.NewRequest("REGISTER", state.RegisterURI)
	msg.Headers.Add("To", fmt.Sprintf("<%s>", state.PublicIdentity))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", state.PublicIdentity, tag))
	msg.Headers.Add("Expires", strconv.Itoa(expiresSeconds))
	if registerUsesIPSec(auth, verify, authorizationAlgorithm(legacyAuthorization, s.cfg.AuthAlgorithm)) {
		verifyValue := securityVerifyValueForFlow(flow, verify)
		sip.SecurityAgreement{Verify: verifyValue, Required: true}.Apply(&msg)
		msg.Headers.Add("Security-Client", state.Flow.SecurityClientValue())
	}
	msg.Headers.Add("Call-ID", callID)
	msg.Headers.Add("Session-ID", sessionID)
	msg.Headers.Add("Contact", contact)
	msg.Headers.Add("Supported", "path")
	if auth != nil {
		msg.Headers.Add("Authorization", auth.String())
	} else if legacyAuthorization != "" {
		msg.Headers.Add("Authorization", legacyAuthorization)
	}
	msg.Headers.Add("CSeq", fmt.Sprintf("%d REGISTER", cseq))
	transport := sip.TransportToken(s.sess.LocalAddr())
	msg.Headers.Add("Via", sip.BuildViaWithOptions(transport, state.ContactHost, port, branch, sip.ViaOptions{
		Keep: strings.EqualFold(transport, "UDP"),
	}))
	accessNetworkInfo := ""
	if registerCanCarryAccessNetworkInfo(auth, verify, flow) {
		accessNetworkInfo = state.AccessNetworkInfo
	}
	sip.ClientRequestPolicy{
		UserAgent:         state.UserAgent,
		AccessNetworkInfo: accessNetworkInfo,
	}.Apply(&msg)
	if s.includePIDFForRegister() {
		s.setRegisterPIDFBody(&msg, state)
	}
	return msg
}

func registerCanCarryAccessNetworkInfo(auth *security.Authorization, verify *security.Param, flow Flow) bool {
	return auth != nil || verify != nil || flow.SecurityVerify != nil
}

func registerUsesIPSec(auth *security.Authorization, verify *security.Param, algorithm string) bool {
	if verify != nil {
		return true
	}
	if auth != nil {
		return !registerUsesTLSAKA(auth.Algorithm)
	}
	return !registerUsesTLSAKA(algorithm)
}

func registerUsesProtectedPort(auth *security.Authorization, verify *security.Param) bool {
	if verify != nil {
		return true
	}
	if auth == nil {
		return false
	}
	return !registerUsesTLSAKA(auth.Algorithm)
}

func authorizationAlgorithm(authorization, fallback string) string {
	if authorization == "" {
		return fallback
	}
	for _, field := range splitAuthorizationFields(authorization) {
		name, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if ok && strings.EqualFold(strings.TrimSpace(name), "algorithm") {
			return strings.Trim(strings.TrimSpace(value), `"`)
		}
	}
	return fallback
}

func splitAuthorizationFields(value string) []string {
	if strings.HasPrefix(strings.ToLower(value), "digest ") {
		value = value[len("Digest "):]
	}
	fields := make([]string, 0, strings.Count(value, ",")+1)
	start := 0
	inQuotes := false
	for i := range len(value) {
		switch value[i] {
		case '"':
			inQuotes = !inQuotes
		case ',':
			if inQuotes {
				continue
			}
			fields = append(fields, value[start:i])
			start = i + 1
		}
	}
	fields = append(fields, value[start:])
	return fields
}

func registerInitialIntegrityProtectedValue(algorithm string) string {
	if registerUsesTLSAKA(algorithm) {
		return "tls-connected"
	}
	return "no"
}

func registerIntegrityProtectedValue(algorithm string) string {
	if registerUsesTLSAKA(algorithm) {
		return "tls-connected"
	}
	return "yes"
}

func registerUsesTLSAKA(algorithm string) bool {
	return strings.EqualFold(strings.TrimSpace(algorithm), security.AlgorithmAKAv2SHA256)
}

func securityServerSupportsTLS(values []string) bool {
	var params security.Params
	for _, value := range values {
		if err := params.UnmarshalText([]byte(value)); err != nil {
			continue
		}
		for _, param := range params {
			if strings.EqualFold(param.Mechanism, "tls") {
				return true
			}
		}
	}
	return false
}

func (s *Service) includePIDFForRegister() bool {
	return slices.Contains(s.cfg.GeolocationPIDFRegister, pidf.GeolocationPIDFNonEmergencyWiFi)
}

func (s *Service) setRegisterPIDFBody(msg *sip.Message, state State) {
	locationID := "pidf-" + sip.RandomAlphaNum(16)
	msg.Headers.Add("Geolocation", "<cid:"+locationID+">")
	msg.Headers.Add("Geolocation-Routing", "yes")
	msg.Headers.Add("Content-Type", "application/pidf+xml")
	msg.Headers.Add("Content-ID", "<"+locationID+">")
	msg.Headers.Add("Content-Disposition", "render;handling=optional")
	msg.Body = pidf.Build(registerPIDFEntityURI(state), state.GeolocationCountry)
}

func registerPIDFEntityURI(state State) string {
	if state.UseTelURIForPIDFXML {
		if uri := strings.TrimSpace(state.TelPublicID); uri != "" {
			return uri
		}
	}
	if uri := strings.TrimSpace(state.SIPPublicID); uri != "" {
		return uri
	}
	if uri := strings.TrimSpace(state.DefaultPublicID); uri != "" {
		return uri
	}
	return state.PublicIdentity
}

func (s *Service) buildSubscribe() sip.Message {
	return s.buildSubscribeWithDialog(subscriptionDialog{})
}

func (s *Service) buildSubscribeWithDialog(subscription subscriptionDialog) sip.Message {
	state := s.State()
	publicID := subscribePublicIdentity(state)
	callID := subscription.callID
	sessionID := subscription.sessionID
	localTag := subscription.localTag
	newCallID, newSessionID, newTag, branch := sip.NewTransaction()
	if callID == "" {
		callID = newCallID
	}
	if sessionID == "" {
		sessionID = newSessionID
	}
	if localTag == "" {
		localTag = newTag
	}
	cseq := subscription.cseq
	if cseq > 0 {
		cseq++
	} else {
		cseq = s.nextStandaloneCSeq()
	}
	requestURI := publicID
	if subscription.active && strings.TrimSpace(subscription.targetURI) != "" {
		requestURI = subscription.targetURI
	}
	msg := sip.NewRequest("SUBSCRIBE", requestURI)
	msg.Headers.Add("Accept", regInfoContentType)
	msg.Headers.Add("Expires", strconv.Itoa(expiresSeconds(s.currentSubscribeExpires())))
	msg.Headers.Add("Event", regEventPackage)
	msg.Headers.Add("From", subscribeHeaderWithTag(subscription.localHeader, publicID, localTag))
	msg.Headers.Add("To", subscribeHeaderWithTag(subscription.remoteHeader, publicID, subscription.remoteTag))
	msg.Headers.Add("Call-ID", callID)
	msg.Headers.Add("Session-ID", sessionID)
	msg.Headers.Add("Contact", s.subscribeContactValue(s.messagePort()))
	msg.Headers.Add("CSeq", fmt.Sprintf("%d SUBSCRIBE", cseq))
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(s.sess.LocalAddr()), state.ContactHost, s.messagePort(), branch))
	if subscription.active {
		s.StrictDialogRequestPolicy(subscription.routeSet).Apply(&msg)
	} else {
		s.RequestPolicy().Apply(&msg)
	}
	return msg
}

func subscribePublicIdentity(state State) string {
	if state.DefaultPublicID != "" {
		return state.DefaultPublicID
	}
	return state.PublicIdentity
}

func subscribeHeaderWithTag(headerValue, fallbackURI, tag string) string {
	if strings.TrimSpace(tag) == "" {
		if strings.TrimSpace(headerValue) != "" {
			return headerValue
		}
		return fmt.Sprintf("<%s>", fallbackURI)
	}
	return sip.WithTag(headerValue, fallbackURI, tag)
}

func (s *Service) messagePort() int {
	flow := s.CurrentFlow()
	if flow.MessagePort != 0 {
		return flow.MessagePort
	}
	return flow.RegisterPort
}

func (s *Service) subscribeContactValue(port int) string {
	params := []string{"text"}
	return fmt.Sprintf("<%s>;%s", contactURI(s.State().ContactHost, port), strings.Join(params, ";"))
}

func firstAddressURI(values []string) string {
	for _, value := range values {
		if uri := strings.TrimSpace(sip.AddressURI(value)); uri != "" {
			return uri
		}
	}
	return ""
}

func reverseHeaderValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for i := len(values) - 1; i >= 0; i-- {
		if value := strings.TrimSpace(values[i]); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func (s *Service) registerContactValue(port int) string {
	params := []string{
		`+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`,
		`+g.3gpp.mid-call`,
		`+g.3gpp.nw-init-ussi`,
		`+g.3gpp.ps2cs-srvcc-orig-pre-alerting`,
		`+g.3gpp.smsip`,
		`+g.3gpp.smsip-msisdn-less`,
		`+g.3gpp.srvcc-alerting`,
	}
	if s.cfg.IMEI != "" {
		params = append(params, fmt.Sprintf(`+sip.instance="<urn:gsma:imei:%s>"`, s.cfg.IMEI))
	}
	params = append(params, "text")
	return fmt.Sprintf("<%s>;%s", contactURI(s.State().ContactHost, port), strings.Join(params, ";"))
}

func contactURI(host string, port int) string {
	return "sip:" + net.JoinHostPort(host, strconv.Itoa(port))
}
