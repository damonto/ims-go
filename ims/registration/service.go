package registration

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"mime"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/damonto/vowifi-go/ims/pidf"
	"github.com/damonto/vowifi-go/ims/security"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"github.com/damonto/vowifi-go/usim"
)

const (
	sipStatusOK                          = 200
	sipStatusBadRequest                  = 400
	sipStatusUnauthorized                = 401
	sipStatusForbidden                   = 403
	sipStatusRequestTimeout              = 408
	sipStatusIntervalTooBrief            = 423
	sipStatusCallTransactionDoesNotExist = 481
	sipStatusBadEvent                    = 489
	sipStatusServerInternalError         = 500
	sipStatusServiceUnavailable          = 503
	sipStatusServerTimeout               = 504
)

type Config struct {
	PrivateIdentity         string
	PublicIdentity          string
	HomeDomain              string
	UserAgent               string
	AccessNetworkInfo       string
	WLANNodeID              string
	RegisterExpires         time.Duration
	IMEI                    string
	AuthAlgorithm           string
	GeolocationPIDFRegister []int
	GeolocationCountry      string
	UseTelURIForPIDFXML     bool
	Logger                  *slog.Logger

	DialSecureTCP   func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error)
	DialSecureUDP   func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error)
	ListenSecureTCP func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error)
	ListenSecureUDP func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error)
}

type Card interface {
	IMSI() string
	MCC() string
	MNC() string
	AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error)
}

type IdentityProvider interface {
	PrivateIdentity() string
	PublicIdentity() string
	HomeDomain() string
}

type State struct {
	Registered          bool
	PublicIdentity      string
	DefaultPublicID     string
	PrivateIdentity     string
	HomeDomain          string
	RegisterURI         string
	SIPPublicID         string
	TelPublicID         string
	Flow                Flow
	ServiceRoutes       []string
	SecurityClient      security.Param
	SecurityClients     security.Params
	SecurityVerify      *security.Param
	RegisterExpires     time.Duration
	ContactHost         string
	RegisterPort        int
	MessagePort         int
	UserAgent           string
	AccessNetworkInfo   string
	IMEI                string
	GeolocationCountry  string
	UseTelURIForPIDFXML bool
}

type Service struct {
	cfg        Config
	sess       *session.Session
	card       Card
	logger     *slog.Logger
	attachment session.Attachment

	mu                  sync.Mutex
	state               State
	flow                Flow
	authCK              []byte
	authIK              []byte
	authNonce           string
	authRealm           string
	authAlgorithm       string
	authQOP             string
	authNonceCount      uint32
	authDigestNonce     string
	authDigestAlgorithm string
	authDigestPassword  string
	callID              string
	sessionID           string
	tag                 string
	cseq                int64

	subscribeExpires     time.Duration
	subscribeUnsupported bool
	subscription         subscriptionDialog
	regInfoVersion       int
	regInfoVersionSet    bool

	registrationEvents       chan error
	subscribeRefreshRequests chan struct{}
	registrationGate         chan struct{}
	secureServerAttachments  []session.Attachment
	drainTimers              []*attachmentDrain
	activeSecureSAExpiresAt  time.Time
	activeSecureSATimer      *time.Timer
}

const defaultIMSExpires = 600000 * time.Second
const secureAssociationLifetimeGrace = 30 * time.Second
const maxSIPCSeq = 1<<31 - 1

var (
	errNetworkDeregistered       = errors.New("ims registration terminated by network")
	errInitialRegistrationNeeded = errors.New("initial registration required")
	errSecureSAExpired           = errors.New("ims security association lifetime expired")
	errSecurityAgreementInvalid  = errors.New("security agreement is invalid")
)

type initialRegistrationRequired struct {
	retryAfter time.Duration
}

func (e *initialRegistrationRequired) Error() string {
	return errInitialRegistrationNeeded.Error()
}

func (e *initialRegistrationRequired) Is(target error) bool {
	return target == errInitialRegistrationNeeded
}

func (e *initialRegistrationRequired) retryAfterDelay() time.Duration {
	return e.retryAfter
}

type subscriptionRetryAfter struct {
	retryAfter time.Duration
}

func (e *subscriptionRetryAfter) Error() string {
	return "registration event subscription retry after"
}

func (e *subscriptionRetryAfter) retryAfterDelay() time.Duration {
	return e.retryAfter
}

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

type attachmentDrain struct {
	cancel      context.CancelFunc
	done        chan struct{}
	closeOnce   sync.Once
	attachments []session.Attachment
}

type registerSecurity struct {
	outbound           session.Transport
	outboundAttachment session.Attachment
	inboundTransports  []session.Transport
	inboundAttachments []session.Attachment
}

func New(cfg Config, sess *session.Session, card Card) (*Service, error) {
	cfg, err := normalizeConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating registration service: %w", err)
	}

	identity, err := resolveIdentity(cfg, card)
	if err != nil {
		return nil, fmt.Errorf("creating registration service: %w", err)
	}
	host, port, err := resolveLocalAddr(sess.LocalAddr())
	if err != nil {
		return nil, fmt.Errorf("creating registration service: %w", err)
	}
	callID, sessionID, tag, _ := sip.NewTransaction()
	svc := &Service{
		cfg:    cfg,
		sess:   sess,
		card:   card,
		logger: cfg.Logger.With("component", "ims-registration"),
		state: State{
			PublicIdentity:      identity.publicIdentity,
			DefaultPublicID:     identity.publicIdentity,
			PrivateIdentity:     identity.privateIdentity,
			HomeDomain:          identity.realm,
			RegisterURI:         "sip:" + identity.realm,
			RegisterExpires:     cfg.RegisterExpires,
			UserAgent:           cfg.UserAgent,
			AccessNetworkInfo:   accessNetworkInfo(cfg),
			IMEI:                cfg.IMEI,
			GeolocationCountry:  cfg.GeolocationCountry,
			UseTelURIForPIDFXML: cfg.UseTelURIForPIDFXML,
		},
		flow:                     newFlow(host, port),
		callID:                   callID,
		sessionID:                sessionID,
		tag:                      tag,
		registrationEvents:       make(chan error, 1),
		subscribeRefreshRequests: make(chan struct{}, 1),
		registrationGate:         make(chan struct{}, 1),
	}
	attachment, err := sess.Attach(svc)
	if err != nil {
		return nil, fmt.Errorf("creating registration service: %w", err)
	}
	svc.attachment = attachment
	return svc, nil
}

func (s *Service) Register(ctx context.Context) error {
	release, err := s.beginRegistrationProcedure(ctx, "registering IMS")
	if err != nil {
		return err
	}
	defer release()

	s.logger.Info("registering IMS", "public_identity", s.State().PublicIdentity)
	challengeMsg, err := s.awaitRegisterChallenge(ctx)
	if err != nil {
		return err
	}
	challenge, err := s.applyRegisterChallenge(challengeMsg)
	if err != nil {
		if !errors.Is(err, errSecurityAgreementInvalid) {
			return fmt.Errorf("registering IMS: %w", err)
		}
		s.logger.Info("retrying initial IMS registration after invalid Security-Server", "err", err)
		s.resetRegisterTransaction()
		challengeMsg, err = s.awaitRegisterChallenge(ctx)
		if err != nil {
			return err
		}
		challenge, err = s.applyRegisterChallenge(challengeMsg)
		if err != nil {
			return fmt.Errorf("registering IMS: %w", err)
		}
	}
	var initialAuth *security.Authorization
	resynchronized := false
	for {
		initialAuth, err = s.buildRegisterAuthorization(ctx, challenge.Realm, challenge.Nonce, challenge.Algorithm, challenge.QOP)
		if err == nil {
			break
		}
		resp, err := s.exchangeAKAFailure(ctx, "registering IMS", challenge, err)
		if err != nil {
			return err
		}
		if resynchronized {
			return errors.New("registering IMS: repeated AKA synchronization failure")
		}
		challenge, err = s.applyRegisterChallenge(resp)
		if err != nil {
			return fmt.Errorf("registering IMS: %w", err)
		}
		resynchronized = true
	}
	if err := s.completeRegistration(ctx, challenge, initialAuth); err != nil {
		return err
	}
	state := s.State()
	s.logger.Info("IMS registration established", "public_identity", state.PublicIdentity, "register_expires", state.RegisterExpires, "service_routes", len(state.ServiceRoutes))
	return nil
}

func (s *Service) Subscribe(ctx context.Context) error {
	return s.subscribe(ctx, false)
}

func (s *Service) subscribe(ctx context.Context, retried bool) error {
	if s.isSubscribeUnsupported() {
		return nil
	}
	subscription := s.currentSubscription()
	msg := s.buildSubscribeWithDialog(subscription)
	resp, err := s.sess.Exchange(ctx, msg)
	if err != nil {
		if subscription.active {
			s.resetSubscription()
			s.resetRegInfoVersion()
		}
		return fmt.Errorf("subscribing IMS registration: %w", err)
	}
	if subscription.active && resp.StatusCode() != sipStatusCallTransactionDoesNotExist {
		s.applySubscribeRequestCSeq(msg)
	}
	if resp.StatusCode() == sipStatusBadEvent {
		s.setSubscribeUnsupported(true)
		s.resetSubscription()
		s.logger.Info("registration event subscription unavailable", "status", resp.StatusCode())
		return nil
	}
	if subscription.active && resp.StatusCode() == sipStatusCallTransactionDoesNotExist && !retried {
		s.resetSubscription()
		s.resetRegInfoVersion()
		return s.subscribe(ctx, true)
	}
	if resp.StatusCode() == sipStatusServiceUnavailable {
		if retryAfter, ok := retryAfterDelay(resp); ok {
			return fmt.Errorf("subscribing IMS registration: %w after %w", &subscriptionRetryAfter{retryAfter: retryAfter}, sip.NewResponseError(resp))
		}
	}
	if resp.StatusCode() != sipStatusOK {
		return fmt.Errorf("subscribing IMS registration: expected 200, got %w", sip.NewResponseError(resp))
	}
	s.setSubscribeUnsupported(false)
	s.applySubscribeExpires(resp)
	s.applySubscribeDialog(msg, resp)
	s.logger.Info("registration event subscription active", "expires", s.currentSubscribeExpires())
	return nil
}

func (s *Service) Establish(ctx context.Context) error {
	return s.Register(ctx)
}

func (s *Service) Refresh(ctx context.Context) error {
	release, err := s.beginRegistrationProcedure(ctx, "refreshing IMS registration")
	if err != nil {
		return err
	}
	defer release()

	state := refreshRegisterState{}
	for range 6 {
		req, auth, err := s.buildRefreshRegister(ctx)
		if err != nil {
			resp, err := s.exchangeCurrentAKAFailure(ctx, "refreshing IMS registration", err)
			if err != nil {
				return err
			}
			done, err := s.handleRefreshRegistration(ctx, resp, &state, nil)
			if err != nil {
				return err
			}
			if done {
				return nil
			}
			continue
		}
		resp, err := s.sess.Exchange(ctx, req)
		if err != nil {
			return fmt.Errorf("refreshing IMS registration: %w", err)
		}
		done, err := s.handleRefreshRegistration(ctx, resp, &state, auth)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return errors.New("refreshing IMS registration: exhausted retries")
}

func (s *Service) Maintain(ctx context.Context) error {
	registerTimer := time.NewTimer(s.refreshInterval())
	defer registerTimer.Stop()
	subscribeTimer := time.NewTimer(s.subscribeRefreshInterval())
	defer subscribeTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-s.registrationEvents:
			return err
		case <-s.subscribeRefreshRequests:
			s.refreshSubscription(ctx)
			resetTimer(subscribeTimer, s.subscribeRefreshInterval())
		case <-registerTimer.C:
			if err := s.Refresh(ctx); err != nil {
				if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
					return ctx.Err()
				}
				return err
			}
			s.logger.Info("IMS registration refreshed", "next_refresh", s.refreshInterval())
			registerTimer.Reset(s.refreshInterval())
		case <-subscribeTimer.C:
			s.refreshSubscription(ctx)
			subscribeTimer.Reset(s.subscribeRefreshInterval())
		}
	}
}

func (s *Service) Deregister(ctx context.Context) error {
	release, err := s.beginRegistrationProcedure(ctx, "deregistering IMS")
	if err != nil {
		return err
	}
	defer release()

	if !s.isRegistered() {
		return nil
	}
	verify := s.currentSecurityVerify()
	realm, nonce, algorithm, qop := s.currentAuthState()
	challenged := false
	for range 2 {
		req, err := s.buildDeregisterMessage(ctx, verify, realm, nonce, algorithm, qop)
		if err != nil {
			return err
		}
		resp, err := s.sess.Exchange(ctx, req)
		if err != nil {
			return fmt.Errorf("deregistering IMS: %w", err)
		}
		done, err := s.handleDeregisterResponse(resp, &challenged, &realm, &nonce, &algorithm, &qop)
		if err != nil {
			return err
		}
		if done {
			s.setRegistered(false)
			s.logger.Info("IMS deregistered")
			return nil
		}
	}
	return errors.New("deregistering IMS: exhausted retries")
}

func (s *Service) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state
	state.Flow = s.flow.clone()
	state.ServiceRoutes = append([]string(nil), state.Flow.ServiceRoutes...)
	state.SecurityClient = state.Flow.SecurityClient
	state.SecurityClients = append(security.Params(nil), state.Flow.SecurityClients...)
	state.SecurityVerify = nil
	if state.Flow.SecurityVerify != nil {
		verify := *state.Flow.SecurityVerify
		state.SecurityVerify = &verify
	}
	state.ContactHost = state.Flow.ContactHost
	state.RegisterPort = state.Flow.RegisterPort
	state.MessagePort = state.Flow.MessagePort
	return state
}

func (s *Service) CurrentFlow() Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flow.clone()
}

func (s *Service) SecurityVerifyValue() string {
	return s.CurrentFlow().SecurityVerifyValue()
}

func (s *Service) RequestPolicy() sip.ClientRequestPolicy {
	state := s.State()
	return state.Flow.requestPolicy(s.preloadedRoutes(state.Flow), state.UserAgent, state.AccessNetworkInfo)
}

func (s *Service) DialogRequestPolicy(routes []string) sip.ClientRequestPolicy {
	state := s.State()
	return state.Flow.DialogRequestPolicy(routes, state.UserAgent, state.AccessNetworkInfo)
}

func (s *Service) StrictDialogRequestPolicy(routes []string) sip.ClientRequestPolicy {
	state := s.State()
	return state.Flow.StrictDialogRequestPolicy(routes, state.UserAgent, state.AccessNetworkInfo)
}

func parsePositiveSeconds(value string) (time.Duration, bool) {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds <= 0 {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

func (s *Service) preloadedRoutes(flow Flow) []string {
	routes := make([]string, 0, len(flow.ServiceRoutes)+1)
	if route := pcscfRoute(s.sess.RemoteAddr(), flow); route != "" {
		routes = append(routes, route)
	}
	for _, route := range flow.ServiceRoutes {
		route = strings.TrimSpace(route)
		if route == "" || slices.ContainsFunc(routes, func(existing string) bool {
			return strings.EqualFold(existing, route)
		}) {
			continue
		}
		routes = append(routes, route)
	}
	return routes
}

func pcscfRoute(addr net.Addr, flow Flow) string {
	host, port := addrHostPort(addr)
	if host == "" || port == 0 {
		return ""
	}
	if flow.SecurityVerify != nil && flow.SecurityVerify.PortS != 0 {
		port = flow.SecurityVerify.PortS
	}
	return fmt.Sprintf("<%s;lr>", contactURI(host, port))
}

func addrHostPort(addr net.Addr) (string, int) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		if a == nil {
			return "", 0
		}
		return sanitizeHost(a.IP.String()), a.Port
	case *net.TCPAddr:
		if a == nil {
			return "", 0
		}
		return sanitizeHost(a.IP.String()), a.Port
	}
	if addr == nil {
		return "", 0
	}
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", 0
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", 0
	}
	return sanitizeHost(host), port
}

func retryAfterDelay(msg sip.Message) (time.Duration, bool) {
	value := strings.TrimSpace(msg.Header("Retry-After"))
	if value == "" {
		return 0, false
	}
	if cut := strings.IndexAny(value, ";("); cut >= 0 {
		value = value[:cut]
	}
	return parsePositiveSeconds(value)
}

func statusClass(status int) int {
	return status / 100
}

// InitialRegistrationRetryAfter returns the Retry-After delay carried by an
// initial registration error. The caller owns scheduling; registration only
// reports the protocol constraint.
func InitialRegistrationRetryAfter(err error) (time.Duration, bool) {
	var initial *initialRegistrationRequired
	if !errors.As(err, &initial) || initial.retryAfter <= 0 {
		return 0, false
	}
	return initial.retryAfter, true
}

func RetryAfterDelay(err error) (time.Duration, bool) {
	var retryAfter interface {
		retryAfterDelay() time.Duration
	}
	if !errors.As(err, &retryAfter) {
		return 0, false
	}
	delay := retryAfter.retryAfterDelay()
	return delay, delay > 0
}

func InitialRegistrationRequired(err error) bool {
	var initial *initialRegistrationRequired
	return errors.As(err, &initial)
}

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

func (s *Service) CloseContext(ctx context.Context) error {
	defer s.closeSecureResources()
	defer s.setRegistered(false)
	return s.Deregister(ctx)
}

func (s *Service) Abort() {
	s.closeSecureResources()
	s.setRegistered(false)
}

func (s *Service) HandleRequest(ctx context.Context, req session.Request) (bool, error) {
	if !strings.EqualFold(req.Message.Method(), "NOTIFY") {
		return false, nil
	}
	if !s.notifyMatchesSubscription(req.Message) {
		return true, s.sess.WriteStatus(ctx, req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist")
	}
	if status, reason := s.recordNotifyCSeq(req.Message); status != 0 {
		return true, s.sess.WriteStatus(ctx, req, status, reason)
	}
	s.applySubscriptionStateFromNotify(req.Message)
	notifyErr := s.applyRegInfoNotify(req.Message)
	if err := s.sess.WriteStatus(ctx, req, sipStatusOK, "OK"); err != nil {
		return true, err
	}
	if notifyErr != nil {
		s.publishRegistrationEvent(notifyErr)
	}
	return true, nil
}

func (s *Service) HandleError(err error) {
	if err == nil {
		return
	}
	s.logger.Warn("IMS registration session error", "err", err)
}

type refreshRegisterState struct {
	adjustedExpires bool
}

type clientIdentity struct {
	realm           string
	privateIdentity string
	publicIdentity  string
}

func (s *Service) beginRegistrationProcedure(ctx context.Context, action string) (func(), error) {
	select {
	case s.registrationGate <- struct{}{}:
		return func() { <-s.registrationGate }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("%s: %w", action, ctx.Err())
	}
}

func (s *Service) awaitRegisterChallenge(ctx context.Context) (sip.Message, error) {
	adjustedExpires := false
	for {
		resp, err := s.sess.Exchange(ctx, s.buildRegister(nil, nil))
		if err != nil {
			return sip.Message{}, fmt.Errorf("registering IMS: %w", err)
		}
		if resp.StatusCode() == sipStatusIntervalTooBrief {
			if err := s.adjustRegisterExpiresFrom423("registering IMS", resp, &adjustedExpires); err != nil {
				return sip.Message{}, err
			}
			continue
		}
		if resp.StatusCode() != sipStatusUnauthorized {
			if initialRegistrationRetryResponse(resp) {
				return sip.Message{}, initialRegistrationRequiredError("registering IMS", resp)
			}
			return sip.Message{}, fmt.Errorf("registering IMS: expected 401, got %d", resp.StatusCode())
		}
		return resp, nil
	}
}

func (s *Service) completeRegistration(ctx context.Context, challenge security.Challenge, initialAuth *security.Authorization) error {
	adjustedExpires := false
	rechallenged := false
	resynchronized := false
	auth := initialAuth
	var pendingSecurity *registerSecurity
	secureTransportStale := false
	committedSecurity := false
	defer func() {
		if !committedSecurity {
			pendingSecurity.close()
		}
	}()
	for {
		if auth == nil {
			var err error
			auth, err = s.buildRegisterAuthorization(ctx, challenge.Realm, challenge.Nonce, challenge.Algorithm, challenge.QOP)
			if err != nil {
				resp, err := s.exchangeAKAFailure(ctx, "registering IMS", challenge, err)
				if err != nil {
					return err
				}
				if resynchronized {
					return errors.New("registering IMS: repeated AKA synchronization failure")
				}
				nextChallenge, err := s.applyRegisterChallenge(resp)
				if err != nil {
					return fmt.Errorf("registering IMS: %w", err)
				}
				challenge = nextChallenge
				resynchronized = true
				rechallenged = true
				auth = nil
				continue
			}
		}
		if pendingSecurity == nil || secureTransportStale {
			pendingSecurity.close()
			nextSecurity, err := s.openRegisterSecurity(ctx)
			if err != nil {
				return fmt.Errorf("registering IMS: %w", err)
			}
			pendingSecurity = nextSecurity
			secureTransportStale = false
		}
		resp, err := s.exchangeProtectedRegister(ctx, pendingSecurity, auth)
		if err != nil {
			return fmt.Errorf("registering IMS: %w", err)
		}
		if resp.StatusCode() == sipStatusIntervalTooBrief {
			if err := s.adjustRegisterExpiresFrom423("registering IMS", resp, &adjustedExpires); err != nil {
				return err
			}
			rechallenged = false
			auth = nil
			continue
		}
		if resp.StatusCode() == sipStatusUnauthorized {
			if rechallenged {
				return errors.New("registering IMS: repeated 401 response")
			}
			nextChallenge, err := s.applyRegisterChallenge(resp)
			if err != nil {
				return fmt.Errorf("registering IMS: %w", err)
			}
			challenge = nextChallenge
			rechallenged = true
			secureTransportStale = s.currentSecurityVerify() != nil
			auth = nil
			continue
		}
		if resp.StatusCode() != sipStatusOK {
			if initialRegistrationRetryResponse(resp) {
				return initialRegistrationRequiredError("registering IMS", resp)
			}
			return fmt.Errorf("registering IMS: expected 200, got %w", sip.NewResponseError(resp))
		}
		if err := s.verifyAuthenticationInfo(resp, auth); err != nil {
			return fmt.Errorf("registering IMS: %w", err)
		}
		if err := s.commitRegisterSecurity(pendingSecurity); err != nil {
			return fmt.Errorf("registering IMS: %w", err)
		}
		s.applyRegisterSuccess(resp)
		committedSecurity = true
		return nil
	}
}

func (s *Service) protectedRegisterExchangeOptions() session.ExchangeOptions {
	if !strings.EqualFold(sip.TransportToken(s.sess.LocalAddr()), "UDP") {
		return session.ExchangeOptions{}
	}
	transports := s.currentSecureServerTransports()
	if len(transports) == 0 {
		return session.ExchangeOptions{}
	}
	return session.ExchangeOptions{
		AcceptResponseTransport: acceptResponseFrom(transports),
		ResponseTransports:      transports,
	}
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

func (s *Service) currentSecurityVerify() *security.Param {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flow.SecurityVerify == nil {
		return nil
	}
	verify := *s.flow.SecurityVerify
	return &verify
}

func securityVerifyValueForFlow(flow Flow, verify *security.Param) string {
	if verify == nil {
		return ""
	}
	if value := flow.SecurityVerifyValue(); value != "" {
		return value
	}
	return verify.String()
}

func (s *Service) applySelectedSecurityServer(verify *security.Param, raw []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flow.SecurityServerRaw = append([]string(nil), raw...)
	s.flow.SecurityVerify = verify
	if verify == nil {
		s.flow.MessagePort = s.flow.RegisterPort
		return
	}
	s.flow.MessagePort = s.flow.SecurityClient.PortS
}

func (s *Service) verifyAuthenticationInfo(msg sip.Message, auth *security.Authorization) error {
	var info security.Info
	if err := info.UnmarshalText([]byte(msg.Header("Authentication-Info"))); err != nil {
		return err
	}
	if info.RSPAuth == "" {
		return nil
	}
	if auth == nil {
		return errors.New("authentication-info rspauth without authorization")
	}
	password, ok := s.currentDigestCredential(auth.Nonce, auth.Algorithm)
	if !ok {
		return errors.New("authentication-info rspauth without digest credential")
	}
	if err := security.VerifyAuthenticationInfo(*auth, info, password); err != nil {
		return err
	}
	return nil
}

func (s *Service) applyAuthenticationInfo(msg sip.Message) {
	var info security.Info
	if err := info.UnmarshalText([]byte(msg.Header("Authentication-Info"))); err != nil || info.NextNonce == "" {
		return
	}
	s.mu.Lock()
	s.authNonce = info.NextNonce
	s.authNonceCount = 0
	if s.authDigestPassword != "" {
		s.authDigestNonce = info.NextNonce
	}
	s.mu.Unlock()
}

func (s *Service) applyRegisterExpires(msg sip.Message) {
	expires, ok := registerResponseExpires(msg, s.currentRegisterContactURI())
	if !ok {
		return
	}
	s.setRegisterExpires(expires)
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

func (s *Service) applyRegisterSuccess(msg sip.Message) {
	s.applyAssociatedURI(msg)
	s.applyServiceRoutes(msg)
	s.applyAuthenticationInfo(msg)
	s.applyRegisterExpires(msg)
	s.extendActiveSecureAssociationLifetime(s.secureAssociationExpiresAt(time.Now()))
	s.setRegistered(true)
}

func (s *Service) storeAuthChallenge(challenge security.Challenge) {
	realm := strings.TrimSpace(challenge.Realm)
	if realm == "" {
		realm = strings.TrimPrefix(s.State().RegisterURI, "sip:")
	}
	s.mu.Lock()
	if s.authDigestNonce != challenge.Nonce || !strings.EqualFold(s.authDigestAlgorithm, challenge.Algorithm) {
		s.authDigestNonce = ""
		s.authDigestAlgorithm = ""
		s.authDigestPassword = ""
	}
	s.authRealm = realm
	s.authNonce = challenge.Nonce
	s.authAlgorithm = challenge.Algorithm
	s.authQOP = challenge.QOP
	s.authNonceCount = 0
	s.mu.Unlock()
}

func (s *Service) currentAuthState() (string, string, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	realm := s.authRealm
	if realm == "" {
		realm = strings.TrimPrefix(s.state.RegisterURI, "sip:")
	}
	return realm, s.authNonce, s.authAlgorithm, s.authQOP
}

func (s *Service) nextAuthNonceCount() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authNonceCount++
	return s.authNonceCount
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

func (s *Service) buildRegisterAuthorization(ctx context.Context, realm, nonce, algorithm, qop string) (*security.Authorization, error) {
	if nonce == "" {
		return nil, nil
	}
	nonceCount := s.nextAuthNonceCount()
	if password, ok := s.currentDigestCredential(nonce, algorithm); ok {
		auth, err := s.calculateDigestRegisterAuthorization(realm, nonce, algorithm, qop, nonceCount, password)
		if err != nil {
			return nil, err
		}
		return auth, nil
	}
	auth, ck, ik, password, err := s.calculateRegisterAuthorization(ctx, realm, nonce, algorithm, qop, nonceCount)
	if err != nil {
		return nil, err
	}
	s.storeDigestCredential(auth.Algorithm, auth.Nonce, password, ck, ik)
	return auth, nil
}

func (s *Service) calculateRegisterAuthorization(ctx context.Context, realm, nonce, algorithm, qop string, nonceCount uint32) (*security.Authorization, []byte, []byte, string, error) {
	if nonce == "" {
		return nil, nil, nil, "", nil
	}
	result, err := security.BuildAKAAuthorization(ctx, akaProvider{s.card}, security.Identity{
		PrivateIdentity: s.State().PrivateIdentity,
		RegisterURI:     s.State().RegisterURI,
		Realm:           defaultRealm(realm, s.State().RegisterURI),
	}, security.Challenge{
		Realm:     realm,
		Nonce:     nonce,
		Algorithm: algorithm,
		QOP:       qop,
	}, nonceCount)
	if err != nil {
		return nil, nil, nil, "", err
	}
	auth := result.Authorization
	auth.IntegrityProtected = registerIntegrityProtectedValue(auth.Algorithm)
	return &auth, result.EncryptionKey, result.IntegrityKey, result.DigestPassword, nil
}

func (s *Service) calculateDigestRegisterAuthorization(realm, nonce, algorithm, qop string, nonceCount uint32, password string) (*security.Authorization, error) {
	result, err := security.BuildDigestAuthorization(security.Identity{
		PrivateIdentity: s.State().PrivateIdentity,
		RegisterURI:     s.State().RegisterURI,
		Realm:           defaultRealm(realm, s.State().RegisterURI),
	}, security.Challenge{
		Realm:     realm,
		Nonce:     nonce,
		Algorithm: algorithm,
		QOP:       qop,
	}, nonceCount, password)
	if err != nil {
		return nil, err
	}
	result.IntegrityProtected = registerIntegrityProtectedValue(result.Algorithm)
	return &result, nil
}

func (s *Service) currentDigestCredential(nonce, algorithm string) (string, bool) {
	normalized, ok := security.NormalizeAKAAlgorithm(algorithm)
	if !ok {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.authDigestPassword == "" || s.authDigestNonce != nonce || !strings.EqualFold(s.authDigestAlgorithm, normalized) {
		return "", false
	}
	return s.authDigestPassword, true
}

func (s *Service) storeDigestCredential(algorithm, nonce, password string, ck, ik []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if password != "" {
		s.authDigestAlgorithm = algorithm
		s.authDigestNonce = nonce
		s.authDigestPassword = password
	}
	if !registerUsesTLSAKA(algorithm) && len(ik) != 0 {
		s.authIK = append([]byte(nil), ik...)
	}
	if !registerUsesTLSAKA(algorithm) && len(ck) != 0 {
		s.authCK = append([]byte(nil), ck...)
	}
}

func (s *Service) applyRegisterChallenge(resp sip.Message) (security.Challenge, error) {
	challenge, verify, raw, err := parseRegisterChallenge(resp)
	if err != nil {
		return security.Challenge{}, err
	}
	s.applySelectedSecurityServer(verify, raw)
	s.storeAuthChallenge(challenge)
	return challenge, nil
}

func parseRegisterChallenge(resp sip.Message) (security.Challenge, *security.Param, []string, error) {
	challenge, err := selectRegisterChallenge(resp.HeadersByName("WWW-Authenticate"))
	if err != nil {
		return security.Challenge{}, nil, nil, err
	}
	if challenge.Algorithm == security.AlgorithmAKAv2SHA256 {
		if !securityServerSupportsTLS(resp.HeadersByName("Security-Server")) {
			return security.Challenge{}, nil, nil, errors.New("applying Security-Server: AKAv2-SHA-256 requires tls security mechanism")
		}
		return security.Challenge{}, nil, nil, errors.New("applying Security-Server: AKAv2-SHA-256 over TLS is not supported by this SIP transport")
	}
	verify, raw, err := selectSecurityServer(resp.HeadersByName("Security-Server"))
	if err != nil {
		return security.Challenge{}, nil, nil, fmt.Errorf("%w: %w", errSecurityAgreementInvalid, err)
	}
	return challenge, verify, raw, nil
}

func selectRegisterChallenge(values []string) (security.Challenge, error) {
	var firstErr error
	seen := false
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		seen = true
		var challenge security.Challenge
		if err := challenge.UnmarshalText([]byte(value)); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if _, err := challenge.SelectedQOP(); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return challenge, nil
	}
	if !seen {
		return security.Challenge{}, errors.New("selecting auth challenge: WWW-Authenticate header is empty")
	}
	return security.Challenge{}, fmt.Errorf("selecting auth challenge: %w", firstErr)
}

func (s *Service) adjustRegisterExpiresFrom423(action string, resp sip.Message, adjusted *bool) error {
	if *adjusted {
		return fmt.Errorf("%s: repeated 423 response", action)
	}
	minExpires, err := minExpiresSeconds(resp.Header("Min-Expires"))
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	s.setRegisterExpires(max(s.currentRegisterExpires(), time.Duration(minExpires)*time.Second))
	*adjusted = true
	return nil
}

func (s *Service) buildRefreshRegister(ctx context.Context) (sip.Message, *security.Authorization, error) {
	realm, nonce, algorithm, qop := s.currentAuthState()
	auth, err := s.buildRegisterAuthorization(ctx, realm, nonce, algorithm, qop)
	if err != nil {
		return sip.Message{}, nil, err
	}
	return s.buildRegister(auth, s.currentSecurityVerify()), auth, nil
}

func (s *Service) handleRefreshRegistration(ctx context.Context, resp sip.Message, state *refreshRegisterState, auth *security.Authorization) (bool, error) {
	switch resp.StatusCode() {
	case sipStatusOK:
		if err := s.verifyAuthenticationInfo(resp, auth); err != nil {
			return false, fmt.Errorf("refreshing IMS registration: %w", err)
		}
		s.applyRegisterSuccess(resp)
		return true, nil
	case sipStatusUnauthorized:
		if err := s.reauthenticateRefresh(ctx, resp); err != nil {
			return false, err
		}
		return true, nil
	case sipStatusIntervalTooBrief:
		if err := s.adjustRegisterExpiresFrom423("refreshing IMS registration", resp, &state.adjustedExpires); err != nil {
			return false, err
		}
		return false, nil
	default:
		if reregistrationInitialRequiredStatus(resp.StatusCode()) {
			return false, initialRegistrationRequiredError("refreshing IMS registration", resp)
		}
		return false, fmt.Errorf("refreshing IMS registration: unexpected response: %w", sip.NewResponseError(resp))
	}
}

func initialRegistrationRetryResponse(resp sip.Message) bool {
	return statusClass(resp.StatusCode()) == 4 || statusClass(resp.StatusCode()) == 5 || statusClass(resp.StatusCode()) == 6
}

func reregistrationInitialRequiredStatus(status int) bool {
	switch status {
	case sipStatusForbidden, sipStatusRequestTimeout, sipStatusServerInternalError, sipStatusServerTimeout:
		return true
	default:
		return false
	}
}

func initialRegistrationRequiredError(action string, resp sip.Message) error {
	initial := &initialRegistrationRequired{}
	if retryAfter, ok := retryAfterDelay(resp); ok {
		initial.retryAfter = retryAfter
	}
	return fmt.Errorf("%s: %w after %w", action, initial, sip.NewResponseError(resp))
}

func (s *Service) reauthenticateRefresh(ctx context.Context, challengeResp sip.Message) error {
	challenge, verify, raw, err := parseRegisterChallenge(challengeResp)
	if err != nil {
		return fmt.Errorf("refreshing IMS registration: %w", err)
	}
	var auth *security.Authorization
	var ck, ik []byte
	var password string
	resynchronized := false
	for {
		auth, ck, ik, password, err = s.calculateRegisterAuthorization(ctx, challenge.Realm, challenge.Nonce, challenge.Algorithm, challenge.QOP, 1)
		if err == nil {
			break
		}
		resp, err := s.exchangeAKAFailure(ctx, "refreshing IMS registration", challenge, err)
		if err != nil {
			return err
		}
		if resynchronized {
			return errors.New("refreshing IMS registration: repeated AKA synchronization failure")
		}
		challenge, verify, raw, err = parseRegisterChallenge(resp)
		if err != nil {
			return fmt.Errorf("refreshing IMS registration: %w", err)
		}
		resynchronized = true
	}

	nextFlow := s.CurrentFlow()
	nextFlow.SecurityVerify = verify
	nextFlow.SecurityServerRaw = append([]string(nil), raw...)
	if verify == nil {
		nextFlow.MessagePort = nextFlow.RegisterPort
		req := s.buildRegisterForFlow(auth, nil, nextFlow)
		resp, err := s.sess.Exchange(ctx, req)
		if err != nil {
			return fmt.Errorf("refreshing IMS registration: completing AKAv2 re-authentication: %w", err)
		}
		if resp.StatusCode() != sipStatusOK {
			if reregistrationInitialRequiredStatus(resp.StatusCode()) {
				return initialRegistrationRequiredError("refreshing IMS registration", resp)
			}
			return fmt.Errorf("refreshing IMS registration: expected 200 after AKAv2 re-authentication, got %w", sip.NewResponseError(resp))
		}
		s.commitReauthentication(challenge, nextFlow, nil, nil, password)
		s.applyRegisterSuccess(resp)
		return nil
	}
	nextFlow.SecurityClient = reauthSecurityClient(nextFlow.SecurityClient, nextFlow.RegisterPort)
	nextFlow.SecurityClients = securityClientCapabilities(nextFlow.SecurityClient)
	nextFlow.MessagePort = nextFlow.SecurityClient.PortS

	outbound, err := s.dialSecureTransport(ctx, verify, nextFlow, ck, ik)
	if err != nil {
		return fmt.Errorf("refreshing IMS registration: %w", err)
	}
	outboundAttachment, err := s.sess.AddTransport(outbound)
	if err != nil {
		outbound.Close()
		return fmt.Errorf("refreshing IMS registration: adding secure IMS transport: %w", err)
	}
	cleanup := []session.Attachment{outboundAttachment}
	committed := false
	defer func() {
		if !committed {
			closeAttachments(cleanup)
		}
	}()

	inboundTransports, inboundAttachments, err := s.startSecureServerTransportsWithKeys(ctx, verify, nextFlow, ck, ik)
	if err != nil {
		return fmt.Errorf("refreshing IMS registration: %w", err)
	}
	if len(inboundTransports) == 0 {
		return errors.New("refreshing IMS registration: secure inbound transport is not configured")
	}
	cleanup = append(cleanup, inboundAttachments...)

	req := s.buildRegisterForFlow(auth, verify, nextFlow)
	responseTransports := reauthResponseTransports(outbound, inboundTransports)
	resp, err := s.sess.ExchangeWithTransport(ctx, outbound, req, session.ExchangeOptions{
		AcceptResponseTransport: acceptResponseFrom(responseTransports),
		ResponseTransports:      responseTransports,
	})
	if err != nil {
		return fmt.Errorf("refreshing IMS registration: completing re-authentication: %w", err)
	}
	if resp.StatusCode() != sipStatusOK {
		if reregistrationInitialRequiredStatus(resp.StatusCode()) {
			return initialRegistrationRequiredError("refreshing IMS registration", resp)
		}
		return fmt.Errorf("refreshing IMS registration: expected 200 after re-authentication, got %w", sip.NewResponseError(resp))
	}
	oldExpiresAt := s.currentSecureAssociationExpiresAt()
	oldAttachment, err := s.sess.PromotePrimary(outbound)
	if err != nil {
		return fmt.Errorf("refreshing IMS registration: promoting secure IMS transport: %w", err)
	}
	oldServerAttachments := s.replaceSecureServerAttachments(inboundAttachments)
	s.closeAttachmentsAfter(append(oldServerAttachments, oldAttachment), saDrainDelayBefore(oldExpiresAt, s.sess.TransactionTimers()))
	s.commitReauthentication(challenge, nextFlow, ck, ik, password)
	s.applyRegisterSuccess(resp)
	committed = true
	return nil
}

func acceptResponseFrom(inbound []session.Transport) func(session.Transport) bool {
	allowed := make(map[session.Transport]struct{}, len(inbound))
	for _, transport := range inbound {
		allowed[transport] = struct{}{}
	}
	return func(transport session.Transport) bool {
		_, ok := allowed[transport]
		return ok
	}
}

func reauthResponseTransports(outbound session.Transport, inbound []session.Transport) []session.Transport {
	transports := append([]session.Transport(nil), inbound...)
	if strings.EqualFold(sip.TransportToken(outbound.LocalAddr()), "TCP") {
		transports = append([]session.Transport{outbound}, transports...)
	}
	return uniqueSessionTransports(transports)
}

func uniqueSessionTransports(transports []session.Transport) []session.Transport {
	unique := transports[:0]
	for _, transport := range transports {
		if slices.Contains(unique, transport) {
			continue
		}
		unique = append(unique, transport)
	}
	return unique
}

func (s *Service) exchangeAKAFailure(ctx context.Context, action string, challenge security.Challenge, cause error) (sip.Message, error) {
	var failure *security.AKAChallengeFailure
	if !errors.As(cause, &failure) {
		return sip.Message{}, fmt.Errorf("%s: %w", action, cause)
	}
	auth := s.akaFailureAuthorization(challenge, failure)
	req := s.buildRegister(&auth, s.currentSecurityVerify())
	if !failure.SynchronizationFailure() {
		if err := s.sess.Send(ctx, req); err != nil {
			return sip.Message{}, fmt.Errorf("%s: reporting AKA failure: %w", action, err)
		}
		return sip.Message{}, fmt.Errorf("%s: %w", action, cause)
	}
	resp, err := s.sess.Exchange(ctx, req)
	if err != nil {
		return sip.Message{}, fmt.Errorf("%s: reporting AKA synchronization failure: %w", action, err)
	}
	if resp.StatusCode() != sipStatusUnauthorized {
		return sip.Message{}, fmt.Errorf("%s: expected 401 after AKA synchronization failure, got %w", action, sip.NewResponseError(resp))
	}
	return resp, nil
}

func (s *Service) exchangeCurrentAKAFailure(ctx context.Context, action string, cause error) (sip.Message, error) {
	realm, nonce, algorithm, qop := s.currentAuthState()
	return s.exchangeAKAFailure(ctx, action, security.Challenge{
		Realm:     realm,
		Nonce:     nonce,
		Algorithm: algorithm,
		QOP:       qop,
	}, cause)
}

func (s *Service) akaFailureAuthorization(challenge security.Challenge, failure *security.AKAChallengeFailure) security.Authorization {
	auth := security.Authorization{
		Nonce:              challenge.Nonce,
		URI:                s.State().RegisterURI,
		Response:           "",
		Username:           s.State().PrivateIdentity,
		Realm:              defaultRealm(challenge.Realm, s.State().RegisterURI),
		Algorithm:          challenge.Algorithm,
		IntegrityProtected: registerIntegrityProtectedValue(challenge.Algorithm),
	}
	if failure.SynchronizationFailure() {
		auth.AUTS = base64.StdEncoding.EncodeToString(failure.AUTS)
	}
	return auth
}

func closeAttachments(attachments []session.Attachment) {
	for _, attachment := range attachments {
		if attachment != nil {
			_ = attachment.Close()
		}
	}
}

func (r *registerSecurity) close() {
	if r == nil {
		return
	}
	closeAttachments(r.inboundAttachments)
	r.inboundAttachments = nil
	r.inboundTransports = nil
	if r.outboundAttachment != nil {
		_ = r.outboundAttachment.Close()
		r.outboundAttachment = nil
	}
	r.outbound = nil
}

func (r *registerSecurity) exchangeOptions() session.ExchangeOptions {
	if r == nil || r.outbound == nil || !strings.EqualFold(sip.TransportToken(r.outbound.LocalAddr()), "UDP") {
		return session.ExchangeOptions{}
	}
	if len(r.inboundTransports) == 0 {
		return session.ExchangeOptions{}
	}
	return session.ExchangeOptions{
		AcceptResponseTransport: acceptResponseFrom(r.inboundTransports),
		ResponseTransports:      r.inboundTransports,
	}
}

func (s *Service) replaceSecureServerAttachments(next []session.Attachment) []session.Attachment {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.secureServerAttachments
	s.secureServerAttachments = append([]session.Attachment(nil), next...)
	return old
}

func (s *Service) currentSecureServerTransports() []session.Transport {
	s.mu.Lock()
	attachments := append([]session.Attachment(nil), s.secureServerAttachments...)
	s.mu.Unlock()
	return attachmentTransports(attachments)
}

func (s *Service) closeAttachmentsAfter(attachments []session.Attachment, delay time.Duration) {
	attachments = compactAttachments(attachments)
	if len(attachments) == 0 {
		return
	}
	if delay <= 0 {
		closeAttachments(attachments)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), delay)
	drain := &attachmentDrain{
		cancel:      cancel,
		done:        make(chan struct{}),
		attachments: append([]session.Attachment(nil), attachments...),
	}
	transports := attachmentTransports(attachments)
	s.mu.Lock()
	s.drainTimers = append(s.drainTimers, drain)
	s.mu.Unlock()
	go func() {
		defer close(drain.done)
		defer cancel()
		if len(transports) == 0 {
			<-ctx.Done()
		} else {
			_ = s.sess.WaitTransportsIdle(ctx, transports...)
		}
		drain.close()
		s.forgetDrain(drain)
	}()
}

func compactAttachments(attachments []session.Attachment) []session.Attachment {
	kept := attachments[:0]
	for _, attachment := range attachments {
		if attachment != nil {
			kept = append(kept, attachment)
		}
	}
	return kept
}

func attachmentTransports(attachments []session.Attachment) []session.Transport {
	transports := make([]session.Transport, 0, len(attachments))
	for _, attachment := range attachments {
		transportAttachment, ok := attachment.(session.TransportAttachment)
		if !ok {
			continue
		}
		transports = append(transports, transportAttachment.Transport())
	}
	return transports
}

func (d *attachmentDrain) close() {
	d.closeOnce.Do(func() {
		closeAttachments(d.attachments)
	})
}

func (s *Service) forgetDrain(drain *attachmentDrain) {
	s.mu.Lock()
	s.drainTimers = slices.DeleteFunc(s.drainTimers, func(candidate *attachmentDrain) bool {
		return candidate == drain
	})
	s.mu.Unlock()
}

func (s *Service) closeSecureResources() {
	s.mu.Lock()
	attachments := s.secureServerAttachments
	s.secureServerAttachments = nil
	drains := s.drainTimers
	s.drainTimers = nil
	expiryTimer := s.activeSecureSATimer
	s.activeSecureSATimer = nil
	s.activeSecureSAExpiresAt = time.Time{}
	s.mu.Unlock()
	if expiryTimer != nil {
		expiryTimer.Stop()
	}
	for _, drain := range drains {
		drain.cancel()
		drain.close()
	}
	closeAttachments(attachments)
}

func saDrainDelay(timers session.TransactionTimers) time.Duration {
	return max(timers.TB, timers.TD, timers.TF, timers.TH, timers.TJ, timers.T4)
}

func saDrainDelayBefore(expiresAt time.Time, timers session.TransactionTimers) time.Duration {
	delay := saDrainDelay(timers)
	if expiresAt.IsZero() {
		return delay
	}
	remaining := time.Until(expiresAt)
	if remaining <= 0 {
		return 0
	}
	return min(delay, remaining)
}

func (s *Service) secureAssociationExpiresAt(now time.Time) time.Time {
	if s.currentSecurityVerify() == nil {
		return time.Time{}
	}
	return now.Add(s.currentRegisterExpires() + secureAssociationLifetimeGrace)
}

func (s *Service) currentSecureAssociationExpiresAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeSecureSAExpiresAt
}

func (s *Service) extendActiveSecureAssociationLifetime(expiresAt time.Time) {
	if expiresAt.IsZero() {
		return
	}
	s.mu.Lock()
	if !s.activeSecureSAExpiresAt.IsZero() && !expiresAt.After(s.activeSecureSAExpiresAt) {
		s.mu.Unlock()
		return
	}
	s.activeSecureSAExpiresAt = expiresAt
	delay := time.Until(expiresAt)
	if delay < 0 {
		delay = 0
	}
	if s.activeSecureSATimer == nil {
		s.activeSecureSATimer = time.AfterFunc(delay, s.expireActiveSecureAssociation)
		s.mu.Unlock()
		return
	}
	s.activeSecureSATimer.Reset(delay)
	s.mu.Unlock()
}

func (s *Service) expireActiveSecureAssociation() {
	s.closeSecureResources()
	s.setRegistered(false)
	s.publishRegistrationEvent(errSecureSAExpired)
}

func (s *Service) commitReauthentication(challenge security.Challenge, flow Flow, ck, ik []byte, password string) {
	realm := strings.TrimSpace(challenge.Realm)
	if realm == "" {
		realm = strings.TrimPrefix(s.State().RegisterURI, "sip:")
	}
	s.mu.Lock()
	s.flow = flow.clone()
	s.authRealm = realm
	s.authNonce = challenge.Nonce
	s.authAlgorithm = challenge.Algorithm
	s.authQOP = challenge.QOP
	s.authNonceCount = 1
	s.authDigestNonce = challenge.Nonce
	s.authDigestAlgorithm = challenge.Algorithm
	s.authDigestPassword = password
	s.authCK = append([]byte(nil), ck...)
	s.authIK = append([]byte(nil), ik...)
	s.mu.Unlock()
}

func (s *Service) buildDeregisterMessage(ctx context.Context, verify *security.Param, realm, nonce, algorithm, qop string) (sip.Message, error) {
	auth, err := s.buildRegisterAuthorization(ctx, realm, nonce, algorithm, qop)
	if err != nil {
		return sip.Message{}, fmt.Errorf("deregistering IMS: %w", err)
	}
	return s.buildDeregister(auth, verify), nil
}

func (s *Service) handleDeregisterResponse(resp sip.Message, challenged *bool, realm, nonce, algorithm, qop *string) (bool, error) {
	switch resp.StatusCode() {
	case sipStatusOK:
		return true, nil
	case sipStatusUnauthorized:
		if *challenged {
			return false, errors.New("deregistering IMS: repeated 401 response")
		}
		challenge, err := selectRegisterChallenge(resp.HeadersByName("WWW-Authenticate"))
		if err != nil {
			return false, fmt.Errorf("deregistering IMS: %w", err)
		}
		s.storeAuthChallenge(challenge)
		*realm = challenge.Realm
		*nonce = challenge.Nonce
		*algorithm = challenge.Algorithm
		*qop = challenge.QOP
		*challenged = true
		return false, nil
	default:
		return false, fmt.Errorf("deregistering IMS: unexpected response: %w", sip.NewResponseError(resp))
	}
}

func (s *Service) openRegisterSecurity(ctx context.Context) (*registerSecurity, error) {
	verify := s.currentSecurityVerify()
	if verify == nil {
		return nil, nil
	}
	flow := s.CurrentFlow()
	outbound, err := s.dialSecureTransport(ctx, verify, flow, s.authCK, s.authIK)
	if err != nil {
		return nil, err
	}
	registration := &registerSecurity{outbound: outbound}
	if !sameSessionEndpoint(outbound, s.sess.LocalAddr(), s.sess.RemoteAddr()) {
		attachment, err := s.sess.AddTransport(outbound)
		if err != nil {
			outbound.Close()
			return nil, fmt.Errorf("adding secure IMS transport: %w", err)
		}
		registration.outboundAttachment = attachment
	}
	inboundTransports, inboundAttachments, err := s.startSecureServerTransports(ctx, verify)
	if err != nil {
		registration.close()
		return nil, err
	}
	registration.inboundTransports = inboundTransports
	registration.inboundAttachments = inboundAttachments
	return registration, nil
}

func (s *Service) exchangeProtectedRegister(ctx context.Context, registration *registerSecurity, auth *security.Authorization) (sip.Message, error) {
	req := s.buildRegister(auth, s.currentSecurityVerify())
	if registration == nil || registration.outbound == nil {
		return s.sess.ExchangeWithOptions(ctx, req, s.protectedRegisterExchangeOptions())
	}
	return s.sess.ExchangeWithTransport(ctx, registration.outbound, req, registration.exchangeOptions())
}

func (s *Service) commitRegisterSecurity(registration *registerSecurity) error {
	if registration == nil || registration.outbound == nil {
		return nil
	}
	oldPrimary, err := s.sess.PromotePrimary(registration.outbound)
	if err != nil {
		return fmt.Errorf("promoting secure IMS transport: %w", err)
	}
	oldServers := s.replaceSecureServerAttachments(registration.inboundAttachments)
	registration.outboundAttachment = nil
	registration.inboundAttachments = nil
	closeAttachments(oldServers)
	if oldPrimary != nil {
		_ = oldPrimary.Close()
	}
	return nil
}

func sameSessionEndpoint(transport session.Transport, local, remote net.Addr) bool {
	if transport == nil {
		return false
	}
	return sameAddr(transport.LocalAddr(), local) && sameAddr(transport.RemoteAddr(), remote)
}

func sameAddr(left, right net.Addr) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Network() == right.Network() && left.String() == right.String()
}

func secureTransportConfigWithKeys(verify *security.Param, localPort, remotePort int, outboundSPI, inboundSPI uint32, ck, ik []byte) session.SecureTCPConfig {
	return session.SecureTCPConfig{
		LocalPort:     localPort,
		RemotePort:    remotePort,
		OutboundSPI:   outboundSPI,
		InboundSPI:    inboundSPI,
		Encryption:    verify.EAlg,
		EncryptionKey: append([]byte(nil), ck...),
		Integrity:     verify.Alg,
		IntegrityKey:  espIntegrityKey(verify.Alg, ik),
	}
}

func espIntegrityKey(alg string, ik []byte) []byte {
	key := append([]byte(nil), ik...)
	switch strings.ToLower(strings.TrimSpace(alg)) {
	case "hmac-sha-1-96", "hmac-sha1-96":
		if len(key) == 16 {
			key = append(key, 0, 0, 0, 0)
		}
	}
	return key
}

func (s *Service) dialSecureTransport(ctx context.Context, verify *security.Param, flow Flow, ck, ik []byte) (session.Transport, error) {
	switch sip.TransportToken(s.sess.LocalAddr()) {
	case "TCP":
		if s.cfg.DialSecureTCP == nil {
			return nil, errors.New("dialing secure IMS transport: TCP dialer is not configured")
		}
		secureTransport, err := s.cfg.DialSecureTCP(ctx, secureTransportConfigWithKeys(verify, flow.SecurityClient.PortC, verify.PortS, verify.SPIS, flow.SecurityClient.SPIC, ck, ik))
		if err != nil {
			return nil, fmt.Errorf("dialing secure IMS transport: %w", err)
		}
		return secureTransport, nil
	default:
		if s.cfg.DialSecureUDP == nil {
			return nil, errors.New("dialing secure IMS datagram transport: UDP dialer is not configured")
		}
		secureTransport, err := s.cfg.DialSecureUDP(ctx, secureTransportConfigWithKeys(verify, flow.SecurityClient.PortC, verify.PortS, verify.SPIS, flow.SecurityClient.SPIC, ck, ik))
		if err != nil {
			return nil, fmt.Errorf("dialing secure IMS datagram transport: %w", err)
		}
		return secureTransport, nil
	}
}

func (s *Service) startSecureServerTransports(ctx context.Context, verify *security.Param) ([]session.Transport, []session.Attachment, error) {
	flow := s.CurrentFlow()
	return s.startSecureServerTransportsWithKeys(ctx, verify, flow, s.authCK, s.authIK)
}

func (s *Service) startSecureServerTransportsWithKeys(ctx context.Context, verify *security.Param, flow Flow, ck, ik []byte) ([]session.Transport, []session.Attachment, error) {
	transports := make([]session.Transport, 0, 2)
	attachments := make([]session.Attachment, 0, 2)
	if s.cfg.ListenSecureTCP != nil {
		serverTransport, err := s.cfg.ListenSecureTCP(ctx, secureTransportConfigWithKeys(verify, flow.SecurityClient.PortS, verify.PortC, verify.SPIC, flow.SecurityClient.SPIS, ck, ik))
		if err != nil {
			closeAttachments(attachments)
			return nil, nil, fmt.Errorf("listening secure IMS transport: %w", err)
		}
		attachment, err := s.sess.AddTransport(serverTransport)
		if err != nil {
			serverTransport.Close()
			closeAttachments(attachments)
			return nil, nil, fmt.Errorf("adding secure IMS transport: %w", err)
		}
		transports = append(transports, serverTransport)
		attachments = append(attachments, attachment)
	}
	if s.cfg.ListenSecureUDP != nil {
		serverDatagramTransport, err := s.cfg.ListenSecureUDP(ctx, secureTransportConfigWithKeys(verify, flow.SecurityClient.PortS, verify.PortC, verify.SPIC, flow.SecurityClient.SPIS, ck, ik))
		if err != nil {
			closeAttachments(attachments)
			return nil, nil, fmt.Errorf("listening secure IMS datagram transport: %w", err)
		}
		attachment, err := s.sess.AddTransport(serverDatagramTransport)
		if err != nil {
			serverDatagramTransport.Close()
			closeAttachments(attachments)
			return nil, nil, fmt.Errorf("adding secure IMS datagram transport: %w", err)
		}
		transports = append(transports, serverDatagramTransport)
		attachments = append(attachments, attachment)
	}
	return transports, attachments, nil
}

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
	text, _ := (security.Authorization{
		Nonce:              "",
		URI:                s.State().RegisterURI,
		Response:           "",
		Username:           s.State().PrivateIdentity,
		Realm:              s.registerRealm(nil),
		Algorithm:          s.cfg.AuthAlgorithm,
		IntegrityProtected: registerInitialIntegrityProtectedValue(s.cfg.AuthAlgorithm),
	}).MarshalText()
	return string(text)
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

func normalizedPLMNDigits(card Card) (string, string, error) {
	mcc := strings.TrimSpace(card.MCC())
	if len(mcc) != 3 {
		return "", "", fmt.Errorf("mcc %q must be 3 digits", mcc)
	}

	mnc := strings.TrimSpace(card.MNC())
	switch len(mnc) {
	case 2:
		mnc = "0" + mnc
	case 3:
	default:
		return "", "", fmt.Errorf("mnc %q must be 2 or 3 digits", mnc)
	}
	return mcc, mnc, nil
}

func resolveIdentity(cfg Config, card Card) (clientIdentity, error) {
	identity := clientIdentity{
		realm:           strings.TrimSpace(cfg.HomeDomain),
		privateIdentity: strings.TrimSpace(cfg.PrivateIdentity),
		publicIdentity:  strings.TrimSpace(cfg.PublicIdentity),
	}
	if idp, ok := card.(IdentityProvider); ok {
		if identity.realm == "" {
			identity.realm = strings.TrimSpace(idp.HomeDomain())
		}
		if identity.privateIdentity == "" {
			identity.privateIdentity = strings.TrimSpace(idp.PrivateIdentity())
		}
		if identity.publicIdentity == "" {
			identity.publicIdentity = strings.TrimSpace(idp.PublicIdentity())
		}
	}
	if identity.realm == "" {
		mcc, mnc, err := normalizedPLMNDigits(card)
		if err != nil {
			return clientIdentity{}, err
		}
		identity.realm = fmt.Sprintf("ims.mnc%s.mcc%s.3gppnetwork.org", mnc, mcc)
	}
	if identity.privateIdentity == "" {
		identity.privateIdentity = fmt.Sprintf("%s@%s", card.IMSI(), identity.realm)
	}
	if identity.publicIdentity == "" {
		identity.publicIdentity = "sip:" + identity.privateIdentity
	}
	return identity, nil
}

func resolveLocalAddr(addr net.Addr) (string, int, error) {
	if addr == nil {
		return "", 0, errors.New("session has no local address")
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", 0, fmt.Errorf("parsing local address %q: %w", addr.String(), err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("parsing local port %q: %w", portStr, err)
	}
	return sanitizeHost(host), port, nil
}

func normalizeConfig(cfg Config) (Config, error) {
	cfg.PrivateIdentity = strings.TrimSpace(cfg.PrivateIdentity)
	cfg.PublicIdentity = strings.TrimSpace(cfg.PublicIdentity)
	cfg.HomeDomain = strings.TrimSpace(cfg.HomeDomain)
	cfg.UserAgent = strings.TrimSpace(cfg.UserAgent)
	cfg.AccessNetworkInfo = strings.TrimSpace(cfg.AccessNetworkInfo)
	cfg.WLANNodeID = strings.TrimSpace(cfg.WLANNodeID)
	cfg.IMEI = strings.TrimSpace(cfg.IMEI)
	cfg.AuthAlgorithm = strings.TrimSpace(cfg.AuthAlgorithm)
	if cfg.AuthAlgorithm == "" {
		cfg.AuthAlgorithm = security.AlgorithmAKAv1MD5
	} else {
		algorithm, ok := security.NormalizeAKAAlgorithm(cfg.AuthAlgorithm)
		if !ok {
			return Config{}, fmt.Errorf("normalizing registration config: unsupported AKA algorithm %q", cfg.AuthAlgorithm)
		}
		if algorithm == security.AlgorithmAKAv2SHA256 {
			return Config{}, errors.New("normalizing registration config: AKAv2-SHA-256 requires TLS SIP transport")
		}
		cfg.AuthAlgorithm = algorithm
	}
	cfg.GeolocationPIDFRegister = pidf.NormalizeTypes(cfg.GeolocationPIDFRegister)
	cfg.GeolocationCountry = strings.ToUpper(strings.TrimSpace(cfg.GeolocationCountry))
	if len(cfg.GeolocationPIDFRegister) > 0 && cfg.GeolocationCountry == "" {
		cfg.GeolocationCountry = "US"
	}
	if cfg.GeolocationCountry != "" && len(cfg.GeolocationCountry) != 2 {
		return Config{}, errors.New("normalizing registration config: geolocation country must be two letters")
	}
	if cfg.RegisterExpires == 0 {
		cfg.RegisterExpires = defaultIMSExpires
	}
	return cfg, nil
}

func accessNetworkInfo(cfg Config) string {
	if value := strings.TrimSpace(cfg.AccessNetworkInfo); value != "" {
		return value
	}
	if nodeID := strings.TrimSpace(cfg.WLANNodeID); nodeID != "" {
		return "IEEE-802.11;i-wlan-node-id=" + normalizeWLANNodeID(nodeID)
	}
	return ""
}

func normalizeWLANNodeID(nodeID string) string {
	nodeID = strings.ToLower(strings.TrimSpace(nodeID))
	nodeID = strings.ReplaceAll(nodeID, ":", "")
	nodeID = strings.ReplaceAll(nodeID, "-", "")
	nodeID = strings.ReplaceAll(nodeID, ".", "")
	return nodeID
}

func selectSecurityServer(values []string) (*security.Param, []string, error) {
	raw := make([]string, 0, len(values))
	bestQ := -1
	var best *security.Param
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		raw = append(raw, value)
		var params security.Params
		if err := params.UnmarshalText([]byte(value)); err != nil {
			return nil, nil, err
		}
		for _, param := range params {
			normalized, ok := security.NormalizeParam(param)
			if !ok {
				continue
			}
			q, err := securityQValue(param.Q)
			if err != nil {
				return nil, nil, fmt.Errorf("parsing Security-Server q-value %q: %w", param.Q, err)
			}
			if best != nil && q <= bestQ {
				continue
			}
			verify := normalized
			best = &verify
			bestQ = q
		}
	}
	if len(raw) == 0 {
		return nil, nil, errors.New("applying Security-Server: header is empty")
	}
	if best == nil {
		return nil, nil, errors.New("applying Security-Server: no compatible ipsec-3gpp security mechanism")
	}
	return best, raw, nil
}

func securityQValue(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 1000, nil
	}
	q, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, err
	}
	if q < 0 || q > 1 {
		return 0, fmt.Errorf("out of range q=%q", value)
	}
	return int(math.Round(q * 1000)), nil
}

func defaultRealm(realm, registerURI string) string {
	if strings.TrimSpace(realm) != "" {
		return realm
	}
	return strings.TrimPrefix(registerURI, "sip:")
}

func minExpiresSeconds(value string) (int, error) {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("parsing min-expires: %w", err)
	}
	if seconds < 0 {
		return 0, fmt.Errorf("parsing min-expires: negative value %d", seconds)
	}
	return seconds, nil
}

func sanitizeHost(host string) string {
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	if host == "" || host == "::" || host == "0.0.0.0" {
		return "127.0.0.1"
	}
	return host
}

func newFlow(host string, port int) Flow {
	client := newSecurityClient(port)
	return Flow{
		ContactHost:     host,
		RegisterPort:    port,
		MessagePort:     port,
		SecurityClient:  client,
		SecurityClients: securityClientCapabilities(client),
	}
}

func newSecurityClient(registerPort int) security.Param {
	clientPort := randomIMSPort()
	serverPort := randomIMSPort()
	for serverPort == clientPort || serverPort == registerPort {
		serverPort = randomIMSPort()
	}
	return security.Param{
		Mechanism: "ipsec-3gpp",
		Alg:       "hmac-sha-1-96",
		EAlg:      "aes-cbc",
		Mod:       "trans",
		PortC:     clientPort,
		PortS:     serverPort,
		Prot:      "esp",
		SPIC:      randomNonZeroUint32Except(0),
		SPIS:      randomNonZeroUint32Except(0),
	}
}

func securityClientCapabilities(base security.Param) security.Params {
	ealgs := []string{"null", "aes-cbc"}
	params := make(security.Params, 0, len(ealgs))
	for _, ealg := range ealgs {
		param := base
		param.EAlg = ealg
		params = append(params, param)
	}
	return params
}

func reauthSecurityClient(current security.Param, registerPort int) security.Param {
	next := current
	next.PortC = randomIMSPort()
	for next.PortC == current.PortC || next.PortC == current.PortS || next.PortC == registerPort {
		next.PortC = randomIMSPort()
	}
	next.SPIC = randomNonZeroUint32Except(current.SPIC)
	next.SPIS = randomNonZeroUint32Except(current.SPIS)
	return next
}

func randomNonZeroUint32Except(except uint32) uint32 {
	value := sip.RandomUint32()
	for !security.ValidESPSPI(value) || value == except {
		value = sip.RandomUint32()
	}
	return value
}

type akaProvider struct{ card Card }

func (p akaProvider) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	return p.card.AKA(ctx, rand, autn)
}

func randomIMSPort() int {
	const base = 10000
	const span = 55535
	return base + int(sip.RandomUint32()%span)
}
