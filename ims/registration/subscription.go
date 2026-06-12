package registration

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"slices"
	"strings"
	"time"

	"github.com/damonto/vowifi-go/ims/sip"
)

type subscriptionDialog struct {
	active       bool
	callID       string
	sessionID    string
	cseq         int64
	remoteCSeq   int64
	localHeader  string
	remoteHeader string
	localTag     string
	remoteTag    string
	targetURI    string
	routeSet     []string
}

type regInfoRegistrationEntry struct {
	AOR      string
	State    string
	Event    string
	Contacts map[string]regInfoContact
}

func (s *Service) currentSubscribeExpires() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subscribeExpires > 0 {
		return s.subscribeExpires
	}
	return defaultIMSExpires
}

func (s *Service) setSubscribeExpires(expires time.Duration) {
	if expires <= 0 {
		return
	}
	s.mu.Lock()
	s.subscribeExpires = expires
	s.mu.Unlock()
}

func (s *Service) subscribeRefreshInterval() time.Duration {
	return refreshIntervalFor(s.currentSubscribeExpires())
}

func (s *Service) setSubscribeUnsupported(unsupported bool) {
	s.mu.Lock()
	s.subscribeUnsupported = unsupported
	s.mu.Unlock()
}

func (s *Service) isSubscribeUnsupported() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.subscribeUnsupported
}

func (s *Service) currentSubscription() subscriptionDialog {
	s.mu.Lock()
	defer s.mu.Unlock()
	subscription := s.subscription
	subscription.routeSet = append([]string(nil), subscription.routeSet...)
	return subscription
}

func (s *Service) resetSubscription() {
	s.mu.Lock()
	s.subscription = subscriptionDialog{}
	s.mu.Unlock()
}

func (s *Service) resetRegInfoState() {
	s.mu.Lock()
	s.regInfoVersion = 0
	s.regInfoVersionSet = false
	s.regInfoRegistrations = make(map[string]regInfoRegistrationEntry)
	s.mu.Unlock()
}

func (s *Service) applySubscribeRequestCSeq(req sip.Message) {
	cseq := sip.CSeqNumber(req.Header("CSeq"))
	if cseq <= 0 {
		return
	}
	localTag := sip.HeaderTag(req.Header("From"))
	remoteTag := sip.HeaderTag(req.Header("To"))
	s.mu.Lock()
	if s.subscription.active &&
		s.subscription.callID == req.Header("Call-ID") &&
		s.subscription.localTag == localTag &&
		s.subscription.remoteTag == remoteTag {
		s.subscription.cseq = cseq
	}
	s.mu.Unlock()
}

func (s *Service) applySubscribeDialog(req, resp sip.Message) {
	localHeader := req.Header("From")
	remoteHeader := resp.Header("To")
	remoteTag := sip.HeaderTag(remoteHeader)
	if remoteTag == "" {
		s.resetSubscription()
		s.logger.Debug("registration event subscription response missing remote tag")
		return
	}
	targetURI := firstAddressURI(resp.HeadersByName("Contact"))
	if targetURI == "" {
		targetURI = sip.AddressURI(remoteHeader)
	}
	if targetURI == "" {
		targetURI = sip.RequestURI(req)
	}
	s.mu.Lock()
	s.subscription = subscriptionDialog{
		active:       true,
		callID:       req.Header("Call-ID"),
		sessionID:    req.Header("Session-ID"),
		cseq:         sip.CSeqNumber(req.Header("CSeq")),
		localHeader:  localHeader,
		remoteHeader: remoteHeader,
		localTag:     sip.HeaderTag(localHeader),
		remoteTag:    remoteTag,
		targetURI:    targetURI,
		routeSet:     reverseHeaderValues(resp.HeadersByName("Record-Route")),
	}
	s.mu.Unlock()
}

func (s *Service) publishRegistrationEvent(err error) {
	if err == nil {
		return
	}
	select {
	case s.registrationEvents <- err:
	default:
	}
}

func (s *Service) requestSubscribeRefresh() {
	select {
	case s.subscribeRefreshRequests <- struct{}{}:
	default:
	}
}

func (s *Service) refreshSubscription(ctx context.Context) {
	if s.isSubscribeUnsupported() {
		return
	}
	if err := s.Subscribe(ctx); err != nil {
		s.logger.Warn("refreshing registration event subscription", "err", err)
	}
}

func resetTimer(timer *time.Timer, next time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(next)
}

func refreshIntervalFor(expires time.Duration) time.Duration {
	interval := expires / 2
	if expires > 1200*time.Second {
		interval = expires - 600*time.Second
	}
	if interval < time.Second {
		return time.Second
	}
	return interval
}

func (s *Service) applySubscribeExpires(msg sip.Message) {
	expires, ok := parsePositiveSeconds(msg.Header("Expires"))
	if !ok {
		return
	}
	s.setSubscribeExpires(expires)
}

func (s *Service) notifyMatchesSubscription(msg sip.Message) bool {
	subscription := s.currentSubscription()
	if !subscription.active {
		return true
	}
	return sip.DialogID{
		CallID:    subscription.callID,
		LocalTag:  subscription.localTag,
		RemoteTag: subscription.remoteTag,
	}.Matches(msg)
}

func (s *Service) recordNotifyCSeq(msg sip.Message) (int, string) {
	if !s.currentSubscription().active {
		return 0, ""
	}
	cseq := sip.CSeqNumber(msg.Header("CSeq"))
	if cseq <= 0 || !strings.EqualFold(sip.CSeqMethod(msg.Header("CSeq")), "NOTIFY") {
		return sipStatusBadRequest, "Bad Request"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cseq <= s.subscription.remoteCSeq {
		return sipStatusServerInternalError, "Server Internal Error"
	}
	s.subscription.remoteCSeq = cseq
	return 0, ""
}

func (s *Service) applySubscriptionStateFromNotify(msg sip.Message) {
	if !strings.EqualFold(strings.TrimSpace(msg.Header("Event")), regEventPackage) {
		return
	}
	var subscription subscriptionStateHeader
	if err := subscription.UnmarshalText([]byte(msg.Header("Subscription-State"))); err != nil {
		return
	}
	if subscription.expires > 0 {
		s.setSubscribeExpires(subscription.expires)
	}
	if strings.EqualFold(subscription.state, subscriptionStateTerminated) {
		s.resetSubscription()
		s.resetRegInfoState()
		s.requestSubscribeRefresh()
	}
}

func (s *Service) applyRegInfoNotify(msg sip.Message) error {
	if !strings.EqualFold(strings.TrimSpace(msg.Header("Event")), regEventPackage) {
		return nil
	}
	contentType := strings.TrimSpace(msg.Header("Content-Type"))
	if contentType != "" && !regInfoContentTypeMatches(contentType) {
		return nil
	}
	info, ok, err := parseRegInfo(msg.Body)
	if err != nil {
		s.logger.Debug("parsing registration event body failed", "err", err)
		return nil
	}
	if !ok {
		return nil
	}
	refresh, err := s.applyRegInfo(info)
	if refresh {
		s.requestSubscribeRefresh()
	}
	return err
}

const subscriptionStateTerminated = "terminated"

type subscriptionStateHeader struct {
	state   string
	expires time.Duration
}

func (h *subscriptionStateHeader) UnmarshalText(text []byte) error {
	state, params, _ := strings.Cut(strings.TrimSpace(string(text)), ";")
	state = strings.TrimSpace(state)
	if state == "" {
		return errors.New("parsing Subscription-State: state is empty")
	}
	expires, _ := parsePositiveSeconds(sip.HeaderParam(params, "expires"))
	*h = subscriptionStateHeader{state: state, expires: expires}
	return nil
}

func regInfoContentTypeMatches(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return false
	}
	return strings.EqualFold(mediaType, regInfoContentType)
}

func (s *Service) applyRegInfo(info regInfo) (bool, error) {
	s.mu.Lock()
	var versionGap bool
	var currentVersion, receivedVersion int
	defer func() {
		if versionGap {
			s.logger.Debug("registration event version gap", "current", currentVersion, "received", receivedVersion)
		}
	}()
	defer s.mu.Unlock()

	version, ok := info.version()
	refresh := false
	if ok {
		if !s.regInfoVersionSet {
			s.regInfoVersion = version
			s.regInfoVersionSet = true
		} else if version <= s.regInfoVersion {
			return false, nil
		} else {
			refresh = version > s.regInfoVersion+1
			if refresh {
				versionGap = true
				currentVersion = s.regInfoVersion
				receivedVersion = version
			}
			s.regInfoVersion = version
		}
	}

	s.updateRegInfoTable(info)
	state := s.state
	port := s.flow.RegisterPort
	if s.flow.MessagePort != 0 {
		port = s.flow.MessagePort
	}
	contactURI := contactURI(s.flow.ContactHost, port)
	fullState := strings.EqualFold(strings.TrimSpace(info.State), regInfoStateFull)
	foundOwnContact := false
	foundActiveContact := false
	var initialRequired bool
	var initialReason string

	for _, reg := range s.regInfoRegistrations {
		if !samePublicIdentity(reg.AOR, state) {
			continue
		}
		if reg.terminatedByNetwork() {
			s.state.Registered = false
			return refresh, networkDeregisteredError(reg.Event)
		}
		if reg.terminated() {
			initialRequired = true
			initialReason = "registration terminated"
			continue
		}
		for _, contact := range reg.Contacts {
			if !contactMatchesCurrentBinding(contact, state, contactURI) {
				continue
			}
			foundOwnContact = true
			if contact.active() {
				foundActiveContact = true
				s.state.Registered = true
				if expires, ok := contact.expiresDuration(); ok {
					s.state.RegisterExpires = expires
				}
				continue
			}
			if contact.terminated() {
				if contact.terminatedByNetwork() {
					s.state.Registered = false
					return refresh, networkDeregisteredError(contact.Event)
				}
				initialRequired = true
				initialReason = "registration contact terminated"
			}
		}
	}

	if (initialRequired && !foundActiveContact) || (fullState && (!foundOwnContact || !foundActiveContact)) {
		s.state.Registered = false
		if initialReason == "" {
			initialReason = "registration event full state missing current contact"
		}
		return refresh, initialRegistrationRequiredFromRegInfo(initialReason)
	}
	return refresh, nil
}

func (s *Service) updateRegInfoTable(info regInfo) {
	if strings.EqualFold(strings.TrimSpace(info.State), regInfoStateFull) {
		s.regInfoRegistrations = make(map[string]regInfoRegistrationEntry, len(info.Registration))
	}
	for _, reg := range info.Registration {
		id := strings.TrimSpace(reg.ID)
		entry, ok := s.regInfoRegistrations[id]
		if !ok {
			entry = regInfoRegistrationEntry{
				Contacts: make(map[string]regInfoContact, len(reg.Contact)),
			}
		}
		entry.AOR = strings.TrimSpace(reg.AOR)
		entry.State = strings.TrimSpace(reg.State)
		entry.Event = strings.TrimSpace(reg.Event)
		if entry.Contacts == nil {
			entry.Contacts = make(map[string]regInfoContact, len(reg.Contact))
		}
		for _, contact := range reg.Contact {
			entry.Contacts[strings.TrimSpace(contact.ID)] = cloneRegInfoContact(contact)
		}
		s.regInfoRegistrations[id] = entry
	}
}

func cloneRegInfoContact(contact regInfoContact) regInfoContact {
	contact.Unknown = append([]regInfoUnknownParam(nil), contact.Unknown...)
	return contact
}

func (r regInfoRegistrationEntry) terminatedByNetwork() bool {
	return r.terminated() && networkDeregistrationEvent(r.Event)
}

func (r regInfoRegistrationEntry) terminated() bool {
	return strings.EqualFold(strings.TrimSpace(r.State), regInfoRegistrationStateTerminated)
}

func (c regInfoContact) terminatedByNetwork() bool {
	return c.terminated() && networkDeregistrationEvent(c.Event)
}

func networkDeregistrationEvent(event string) bool {
	switch strings.ToLower(strings.TrimSpace(event)) {
	case regInfoContactEventDeactivated, regInfoContactEventRejected:
		return true
	default:
		return false
	}
}

func initialRegistrationRequiredFromRegInfo(reason string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return &initialRegistrationRequired{}
	}
	return fmt.Errorf("%w: %s", &initialRegistrationRequired{}, reason)
}

func contactMatchesCurrentBinding(contact regInfoContact, state State, contactURI string) bool {
	if sameContactURI(contact.URI, contactURI) {
		return true
	}
	instance := contactSIPInstance(contact)
	return instance != "" && strings.EqualFold(instance, currentSIPInstance(state))
}

func contactSIPInstance(contact regInfoContact) string {
	for _, param := range contact.Unknown {
		if strings.EqualFold(strings.TrimSpace(param.Name), "+sip.instance") {
			return normalizeSIPInstance(param.Value)
		}
	}
	return ""
}

func currentSIPInstance(state State) string {
	imei := strings.TrimSpace(state.IMEI)
	if imei == "" {
		return ""
	}
	return "urn:gsma:imei:" + imei
}

func normalizeSIPInstance(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">") {
		value = strings.TrimSpace(value[1 : len(value)-1])
	}
	return value
}

func networkDeregisteredError(event string) error {
	event = strings.TrimSpace(event)
	if event == "" {
		return errNetworkDeregistered
	}
	return fmt.Errorf("%w: %s", errNetworkDeregistered, event)
}

func samePublicIdentity(aor string, state State) bool {
	aor = strings.TrimSpace(aor)
	if aor == "" {
		return false
	}
	identities := []string{
		state.PublicIdentity,
		state.DefaultPublicID,
		state.SIPPublicID,
		state.TelPublicID,
	}
	return slices.ContainsFunc(identities, func(identity string) bool {
		return strings.EqualFold(strings.TrimSpace(identity), aor)
	})
}
