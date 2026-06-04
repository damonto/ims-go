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

func (s *Service) resetRegInfoVersion() {
	s.mu.Lock()
	s.regInfoVersion = 0
	s.regInfoVersionSet = false
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
		s.resetRegInfoVersion()
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
	apply, refresh := s.shouldApplyRegInfo(info)
	if refresh {
		s.requestSubscribeRefresh()
	}
	if !apply {
		return nil
	}
	return s.applyRegInfo(info)
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

func (s *Service) shouldApplyRegInfo(info regInfo) (apply bool, refresh bool) {
	version, ok := info.version()
	if !ok {
		return true, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.regInfoVersionSet {
		s.regInfoVersion = version
		s.regInfoVersionSet = true
		return true, false
	}
	if version <= s.regInfoVersion {
		return false, false
	}
	refresh = version > s.regInfoVersion+1
	if version > s.regInfoVersion+1 {
		s.logger.Debug("registration event version gap", "current", s.regInfoVersion, "received", version)
	}
	s.regInfoVersion = version
	return true, refresh
}

func (s *Service) applyRegInfo(info regInfo) error {
	state := s.State()
	contactURI := s.currentRegisterContactURI()
	foundRegistration := false
	foundActiveContact := false

	for _, reg := range info.Registration {
		if !samePublicIdentity(reg.AOR, state) {
			continue
		}
		foundRegistration = true
		for _, contact := range reg.Contact {
			if !sameContactURI(contact.URI, contactURI) {
				continue
			}
			if contact.active() {
				foundActiveContact = true
				s.setRegistered(true)
				if expires, ok := contact.expiresDuration(); ok {
					s.setRegisterExpires(expires)
				}
				continue
			}
			if contact.terminated() {
				s.setRegistered(false)
				return networkDeregisteredError(contact.Event)
			}
		}
	}

	if strings.EqualFold(strings.TrimSpace(info.State), regInfoStateFull) {
		if !foundRegistration || !foundActiveContact {
			s.setRegistered(false)
			return errNetworkDeregistered
		}
	}
	return nil
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
