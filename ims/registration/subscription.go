package registration

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/damonto/ims-go/ims/sip"
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

type pendingSubscription struct {
	request   sip.Message
	done      chan struct{}
	completed bool
	accepted  bool
}

type subscribeExchangeResult struct {
	response sip.Message
	err      error
}

type regInfoRegistrationEntry struct {
	AOR      string
	State    string
	Contacts map[string]regInfoContact
}

func (s *Registrar) Subscribe(ctx context.Context) (retErr error) {
	defer func() {
		if retErr != nil {
			retErr = fmt.Errorf("subscribing IMS registration: %w", retErr)
		}
	}()

	operationCtx, finishOperation, err := s.beginMaintenanceOperation(ctx)
	if err != nil {
		return err
	}
	defer func() {
		finishOperation()
		if errors.Is(context.Cause(operationCtx), errRegistrationStopped) {
			retErr = errRegistrationStopped
		}
	}()
	return s.subscribe(operationCtx, false)
}

func (s *Registrar) subscribe(ctx context.Context, retried bool) error {
	if err := ctx.Err(); err != nil {
		if errors.Is(context.Cause(ctx), errRegistrationStopped) {
			return errRegistrationStopped
		}
		return err
	}
	if channelClosed(s.registrationMaintenanceStop) {
		return errRegistrationStopped
	}
	if s.isSubscribeUnsupported() {
		return nil
	}
	subscription := s.currentSubscription()
	msg := s.buildSubscribeWithDialog(subscription)
	pending := s.beginPendingSubscription(msg, subscription.active)
	defer s.finishPendingSubscription(pending)
	resp, acceptedByNotify, err := s.exchangeSubscribe(ctx, msg, pending)
	if err != nil {
		if subscription.active {
			s.resetSubscription()
			s.resetRegInfoState()
		}
		return err
	}
	s.registrationCommitMu.Lock()
	if channelClosed(s.registrationMaintenanceStop) {
		s.registrationCommitMu.Unlock()
		return errRegistrationStopped
	}
	if acceptedByNotify {
		s.setSubscribeUnsupported(false)
		s.registrationCommitMu.Unlock()
		s.logger.Info("registration event subscription active", "expires", s.currentSubscribeExpires())
		return nil
	}
	if subscription.active && resp.StatusCode() != sipStatusCallTransactionDoesNotExist {
		s.applySubscribeRequestCSeq(msg)
	}
	if resp.StatusCode() == sipStatusBadEvent {
		s.setSubscribeUnsupported(true)
		s.resetSubscription()
		s.registrationCommitMu.Unlock()
		s.logger.Info("registration event subscription unavailable", "status", resp.StatusCode())
		return nil
	}
	if subscription.active && resp.StatusCode() == sipStatusCallTransactionDoesNotExist && !retried {
		s.resetSubscription()
		s.resetRegInfoState()
		s.registrationCommitMu.Unlock()
		return s.subscribe(ctx, true)
	}
	if resp.StatusCode() == sipStatusServiceUnavailable {
		if retryAfter, ok := retryAfterDelay(resp); ok {
			s.registrationCommitMu.Unlock()
			return fmt.Errorf("%w after %w", &subscriptionRetryAfter{retryAfter: retryAfter}, sip.NewResponseError(resp))
		}
	}
	if resp.StatusCode() != sipStatusOK {
		s.registrationCommitMu.Unlock()
		return fmt.Errorf("expected 200, got %w", sip.NewResponseError(resp))
	}
	s.setSubscribeUnsupported(false)
	s.applySubscribeExpires(resp)
	s.applySubscribeDialog(msg, resp)
	s.registrationCommitMu.Unlock()
	s.logger.Info("registration event subscription active", "expires", s.currentSubscribeExpires())
	return nil
}

func (s *Registrar) exchangeSubscribe(ctx context.Context, msg sip.Message, pending *pendingSubscription) (sip.Message, bool, error) {
	if pending == nil {
		resp, err := s.sess.ExchangeWithOptions(ctx, msg, s.protectedRegisterExchangeOptions())
		return resp, false, err
	}
	exchangeCtx, cancel := context.WithCancel(ctx)
	resultCh := make(chan subscribeExchangeResult, 1)
	go func() {
		resp, err := s.sess.ExchangeWithOptions(exchangeCtx, msg, s.protectedRegisterExchangeOptions())
		resultCh <- subscribeExchangeResult{response: resp, err: err}
	}()

	select {
	case result := <-resultCh:
		cancel()
		return result.response, false, result.err
	case <-pending.done:
		accepted := s.pendingSubscriptionAccepted(pending)
		cancel()
		<-resultCh
		if accepted {
			return sip.Message{}, true, nil
		}
		return sip.Message{}, false, errors.New("subscription terminated by NOTIFY")
	}
}

func (s *Registrar) beginPendingSubscription(req sip.Message, active bool) *pendingSubscription {
	if active {
		return nil
	}
	pending := &pendingSubscription{request: req, done: make(chan struct{})}
	s.mu.Lock()
	s.pendingSubscription = pending
	s.mu.Unlock()
	return pending
}

func (s *Registrar) finishPendingSubscription(pending *pendingSubscription) {
	if pending == nil {
		return
	}
	s.mu.Lock()
	if s.pendingSubscription == pending {
		s.pendingSubscription = nil
	}
	s.mu.Unlock()
}

func (s *Registrar) pendingSubscriptionAccepted(pending *pendingSubscription) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return pending.completed && pending.accepted
}

func (s *Registrar) currentSubscribeExpires() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subscribeExpires > 0 {
		return s.subscribeExpires
	}
	return defaultIMSExpires
}

func (s *Registrar) setSubscribeExpires(expires time.Duration) {
	if expires <= 0 {
		return
	}
	s.mu.Lock()
	s.subscribeExpires = expires
	s.mu.Unlock()
}

func (s *Registrar) subscribeRefreshInterval() time.Duration {
	return refreshIntervalFor(s.currentSubscribeExpires())
}

func (s *Registrar) setSubscribeUnsupported(unsupported bool) {
	s.mu.Lock()
	s.subscribeUnsupported = unsupported
	s.mu.Unlock()
}

func (s *Registrar) isSubscribeUnsupported() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.subscribeUnsupported
}

func (s *Registrar) currentSubscription() subscriptionDialog {
	s.mu.Lock()
	defer s.mu.Unlock()
	subscription := s.subscription
	subscription.routeSet = append([]string(nil), subscription.routeSet...)
	return subscription
}

func (s *Registrar) resetSubscription() {
	s.mu.Lock()
	s.subscription = subscriptionDialog{}
	s.mu.Unlock()
}

func (s *Registrar) resetRegInfoState() {
	s.mu.Lock()
	s.regInfoVersion = 0
	s.regInfoVersionSet = false
	s.regInfoRegistrations = make(map[string]regInfoRegistrationEntry)
	s.mu.Unlock()
}

func (s *Registrar) applySubscribeRequestCSeq(req sip.Message) {
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

func (s *Registrar) applySubscribeDialog(req, resp sip.Message) {
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
		routeSet:     reverseHeaderValues(resp.HeaderList("Record-Route")),
	}
	s.mu.Unlock()
}

func (s *Registrar) publishRegistrationEvent(err error) {
	if err == nil {
		return
	}
	select {
	case s.registrationEvents <- err:
	default:
	}
}

func (s *Registrar) requestSubscribeRefresh() {
	if channelClosed(s.registrationMaintenanceStop) {
		return
	}
	select {
	case s.subscribeRefreshRequests <- struct{}{}:
	default:
	}
}

func (s *Registrar) refreshSubscription(ctx context.Context) {
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

func stopTimer(timer *time.Timer) {
	if timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
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

func (s *Registrar) applySubscribeExpires(msg sip.Message) {
	expires, ok := parsePositiveSeconds(msg.Header("Expires"))
	if !ok {
		return
	}
	s.setSubscribeExpires(expires)
}

func (s *Registrar) notifyMatchesSubscription(msg sip.Message) bool {
	s.mu.Lock()
	subscription := s.subscription
	pending := s.pendingSubscription
	s.mu.Unlock()
	if subscription.active {
		return sip.DialogID{
			CallID:    subscription.callID,
			LocalTag:  subscription.localTag,
			RemoteTag: subscription.remoteTag,
		}.Matches(msg)
	}
	if pending == nil {
		return true
	}
	return pendingSubscriptionMatches(pending.request, msg)
}

func pendingSubscriptionMatches(req, notify sip.Message) bool {
	return req.Header("Call-ID") != "" &&
		req.Header("Call-ID") == notify.Header("Call-ID") &&
		sip.HeaderTag(req.Header("From")) == sip.HeaderTag(notify.Header("To"))
}

func (s *Registrar) preparePendingSubscriptionNotify(msg sip.Message) (*pendingSubscription, bool) {
	var state subscriptionStateHeader
	if err := state.UnmarshalText([]byte(msg.Header("Subscription-State"))); err != nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := s.pendingSubscription
	if pending == nil || pending.completed || !pendingSubscriptionMatches(pending.request, msg) {
		return nil, false
	}
	accepted := !strings.EqualFold(state.state, subscriptionStateTerminated)
	if !accepted {
		return pending, false
	}
	localHeader := msg.Header("To")
	remoteHeader := msg.Header("From")
	remoteTag := sip.HeaderTag(remoteHeader)
	if remoteTag == "" {
		return nil, false
	}
	targetURI := firstAddressURI(msg.HeadersByName("Contact"))
	if targetURI == "" {
		targetURI = sip.AddressURI(remoteHeader)
	}
	if targetURI == "" {
		targetURI = sip.RequestURI(pending.request)
	}
	s.subscription = subscriptionDialog{
		active:       true,
		callID:       pending.request.Header("Call-ID"),
		sessionID:    pending.request.Header("Session-ID"),
		cseq:         sip.CSeqNumber(pending.request.Header("CSeq")),
		localHeader:  localHeader,
		remoteHeader: remoteHeader,
		localTag:     sip.HeaderTag(localHeader),
		remoteTag:    remoteTag,
		targetURI:    targetURI,
		routeSet:     append([]string(nil), msg.HeaderList("Record-Route")...),
	}
	return pending, true
}

func (s *Registrar) completePendingSubscription(pending *pendingSubscription, accepted bool) {
	if pending == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingSubscription != pending || pending.completed {
		return
	}
	pending.completed = true
	pending.accepted = accepted
	close(pending.done)
}

func (s *Registrar) recordNotifyCSeq(msg sip.Message) (int, string) {
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

func (s *Registrar) applySubscriptionStateFromNotify(msg sip.Message) bool {
	if !strings.EqualFold(strings.TrimSpace(msg.Header("Event")), regEventPackage) {
		return false
	}
	var subscription subscriptionStateHeader
	if err := subscription.UnmarshalText([]byte(msg.Header("Subscription-State"))); err != nil {
		return false
	}
	if subscription.expires > 0 {
		s.setSubscribeExpires(subscription.expires)
	}
	return strings.EqualFold(subscription.state, subscriptionStateTerminated)
}

func (s *Registrar) applyRegInfoNotify(msg sip.Message) error {
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
	if errors.Is(err, errInvalidRegInfo) {
		s.logger.Debug("applying registration event body failed", "err", err)
		return nil
	}
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

func (s *Registrar) applyRegInfo(info regInfo) (bool, error) {
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
	if !ok {
		return false, fmtRegInfoError("version must be a 32-bit non-negative integer")
	}
	refresh := false
	if s.regInfoVersionSet {
		if version <= s.regInfoVersion {
			return false, nil
		}
		refresh = version > s.regInfoVersion+1
		if refresh {
			versionGap = true
			currentVersion = s.regInfoVersion
			receivedVersion = version
		}
	}
	if err := s.validateRegInfoIDsLocked(info); err != nil {
		return false, err
	}
	s.regInfoVersion = version
	s.regInfoVersionSet = true

	s.updateRegInfoTable(info)
	state := s.state
	// A registrar that omitted Require: outbound cannot identify the active
	// binding by reg-id because the network may omit that parameter in reginfo.
	if !s.flow.Outbound {
		state.registrationID = 0
	}
	port := s.flow.RegisterPort
	if s.flow.MessagePort != 0 {
		port = s.flow.MessagePort
	}
	contactURI := s.registerContactURI(s.flow.ContactHost, port)
	registerCallID := s.lastRegisterCallID
	registerCSeq := s.lastRegisterCSeq
	fullState := strings.EqualFold(strings.TrimSpace(info.State), regInfoStateFull)
	foundOwnContact := false
	foundActiveContact := false
	var networkTermination bool
	var networkEvent string
	var initialRequired bool
	var initialReason string

	for _, reg := range s.regInfoRegistrations {
		if !samePublicIdentity(reg.AOR, state) {
			continue
		}
		registrationTerminated := reg.terminated()
		if registrationTerminated {
			initialRequired = true
			initialReason = "registration terminated"
		}
		for _, contact := range reg.Contacts {
			if !contactMatchesCurrentBinding(contact, state, contactURI, registerCallID, registerCSeq) {
				continue
			}
			foundOwnContact = true
			if contact.active() {
				if registrationTerminated {
					continue
				}
				foundActiveContact = true
				s.state.Registered = true
				if expires, ok := contact.expiresDuration(); ok {
					s.state.RegisterExpires = expires
				}
				continue
			}
			if contact.terminated() {
				if contact.terminatedByNetwork() {
					networkTermination = true
					networkEvent = contact.Event
					continue
				}
				initialRequired = true
				initialReason = "registration contact terminated"
			}
		}
	}

	if networkTermination && !foundActiveContact {
		s.state.Registered = false
		return refresh, networkDeregisteredError(networkEvent)
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

func (s *Registrar) validateRegInfoIDsLocked(info regInfo) error {
	contacts := make(map[string]string)
	for _, registration := range s.regInfoRegistrations {
		for contactID, contact := range registration.Contacts {
			contacts[contactID] = contact.URI
		}
	}
	for _, registration := range info.Registration {
		registrationID := strings.TrimSpace(registration.ID)
		if previous, ok := s.regInfoRegistrations[registrationID]; ok && !sameRegInfoURI(previous.AOR, registration.AOR) {
			return fmtRegInfoError("registration id changed address-of-record")
		}
		for previousID, previous := range s.regInfoRegistrations {
			if previousID != registrationID && sameRegInfoURI(previous.AOR, registration.AOR) {
				return fmtRegInfoError("address-of-record changed registration id")
			}
		}
		for _, contact := range registration.Contact {
			contactID := strings.TrimSpace(contact.ID)
			previous, ok := contacts[contactID]
			if !ok {
				continue
			}
			if !sameRegInfoURI(previous, contact.URI) {
				return fmtRegInfoError("contact id changed contact URI")
			}
		}
	}
	return nil
}

func sameRegInfoURI(left, right string) bool {
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	leftLower := strings.ToLower(left)
	rightLower := strings.ToLower(right)
	if (strings.HasPrefix(leftLower, "sip:") || strings.HasPrefix(leftLower, "sips:")) &&
		(strings.HasPrefix(rightLower, "sip:") || strings.HasPrefix(rightLower, "sips:")) {
		return sameContactURI(left, right)
	}
	return strings.EqualFold(left, right)
}

func (s *Registrar) updateRegInfoTable(info regInfo) {
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

func (r regInfoRegistrationEntry) terminated() bool {
	return strings.EqualFold(strings.TrimSpace(r.State), regInfoRegistrationStateTerminated)
}

func (c regInfoContact) terminatedByNetwork() bool {
	return c.terminated() && networkDeregistrationEvent(c.Event)
}

func networkDeregistrationEvent(event string) bool {
	switch strings.ToLower(strings.TrimSpace(event)) {
	case regInfoContactEventUnregistered, regInfoContactEventDeactivated, regInfoContactEventRejected:
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

func contactMatchesCurrentBinding(contact regInfoContact, state State, contactURI string, registerCallID string, registerCSeq int64) bool {
	regID := contactRegistrationID(contact)
	if state.registrationID != 0 && regID != 0 && regID != state.registrationID {
		return false
	}
	if sameRegisterContactURI(contact.URI, contactURI) {
		return true
	}
	// TS 24.229 section 5.1.1.2.1 recommends a globally unique Contact user,
	// which each Registrar generates. Some IMS proxies preserve that user but
	// rewrite the host, port and parameters in reginfo. RFC 3680 section 5.1
	// makes callid, cseq and unknown-param optional, so match the unique user
	// when those other binding identifiers are unavailable.
	var got, want comparableSIPURI
	gotErr := got.UnmarshalText([]byte(contact.URI))
	wantErr := want.UnmarshalText([]byte(contactURI))
	if gotErr == nil && wantErr == nil && got.scheme == want.scheme && want.userinfo != "" && got.userinfo == want.userinfo {
		return true
	}
	instance := contactSIPInstance(contact)
	if instance != "" && strings.EqualFold(instance, currentSIPInstance(state)) {
		if state.registrationID == 0 || regID == state.registrationID {
			return true
		}
	}
	if strings.TrimSpace(contact.CallID) != strings.TrimSpace(registerCallID) {
		return false
	}
	cseq, err := strconv.ParseInt(strings.TrimSpace(contact.CSeq), 10, 64)
	return err == nil && cseq == registerCSeq
}

func contactRegistrationID(contact regInfoContact) uint32 {
	for _, param := range contact.Unknown {
		if !strings.EqualFold(strings.TrimSpace(param.Name), "reg-id") {
			continue
		}
		if regID, ok := parseRegistrationID(param.Value); ok {
			return regID
		}
	}
	return 0
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
	return imeiURN(imei)
}

func normalizeSIPInstance(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">") {
		value = strings.TrimSpace(value[1 : len(value)-1])
	}
	const imeiURNPrefix = "urn:gsma:imei:"
	if len(value) > len(imeiURNPrefix) && strings.EqualFold(value[:len(imeiURNPrefix)], imeiURNPrefix) {
		if imei := value[len(imeiURNPrefix):]; validIMEI(imei) {
			return imeiURN(imei)
		}
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
		if strings.HasPrefix(strings.ToLower(aor), "sip:") || strings.HasPrefix(strings.ToLower(aor), "sips:") {
			return sameContactURI(aor, identity)
		}
		return strings.EqualFold(strings.TrimSpace(identity), aor)
	})
}
