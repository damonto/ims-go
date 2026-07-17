package registration

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/damonto/ims-go/ims/security"
	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
	usim "github.com/damonto/wwan-go/sim"
)

const (
	sipStatusOK                          = 200
	sipStatusUseProxy                    = 305
	sipStatusBadRequest                  = 400
	sipStatusUnsupportedMediaType        = 415
	sipStatusUnauthorized                = 401
	sipStatusProxyAuthenticationRequired = 407
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

type Registrar struct {
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
	authOpaque          string
	authHeader          string
	authNonceCount      uint32
	authDigestNonce     string
	authDigestAlgorithm string
	authDigestPassword  string
	callID              string
	sessionID           string
	tag                 string
	cseq                int64
	lastRegisterCallID  string
	lastRegisterCSeq    int64

	subscribeExpires     time.Duration
	subscribeUnsupported bool
	subscription         subscriptionDialog
	pendingSubscription  *pendingSubscription
	regInfoVersion       int
	regInfoVersionSet    bool
	regInfoRegistrations map[string]regInfoRegistrationEntry

	registrationEvents        chan error
	subscribeRefreshRequests  chan struct{}
	registrationGate          chan struct{}
	done                      chan struct{}
	secureServerAttachments   []session.Attachment
	secureResponseAttachments []session.Attachment
	unprotectedPrimary        session.Transport
	drainTimers               []*attachmentDrain
	activeSecureSAExpiresAt   time.Time
	activeSecureSAExpiry      *secureAssociationExpiry
	registrationKeepAlive     *registrationKeepAlive
	bgWG                      sync.WaitGroup
	closed                    bool
}

const defaultIMSExpires = 600000 * time.Second
const secureAssociationLifetimeGrace = 30 * time.Second
const maxSIPCSeq = 1<<31 - 1

func New(cfg Config, sess *session.Session, card Card) (*Registrar, error) {
	cfg, err := normalizeConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating IMS registrar: %w", err)
	}

	identity, err := resolveIdentity(cfg, card)
	if err != nil {
		return nil, fmt.Errorf("creating IMS registrar: %w", err)
	}
	host, port, err := resolveLocalAddr(sess.LocalAddr())
	if err != nil {
		return nil, fmt.Errorf("creating IMS registrar: %w", err)
	}
	callID, sessionID, tag, _ := sip.NewTransaction()
	registrar := &Registrar{
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
		regInfoRegistrations:     make(map[string]regInfoRegistrationEntry),
		registrationEvents:       make(chan error, 1),
		subscribeRefreshRequests: make(chan struct{}, 1),
		registrationGate:         make(chan struct{}, 1),
		done:                     make(chan struct{}),
	}
	attachment, err := sess.Attach(registrar)
	if err != nil {
		return nil, fmt.Errorf("creating IMS registrar: %w", err)
	}
	registrar.attachment = attachment
	return registrar, nil
}

func (s *Registrar) startBackgroundTaskLocked(task func()) bool {
	if s.closed {
		return false
	}
	s.bgWG.Go(task)
	return true
}

func (s *Registrar) closeDoneLocked() {
	if s.closed {
		return
	}
	s.closed = true
	close(s.done)
}

func contextWithDoneTimeout(done <-chan struct{}, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	stop := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-done:
			cancel()
		case <-stop:
		}
	}()
	return ctx, func() {
		once.Do(func() {
			close(stop)
			cancel()
		})
	}
}

func (s *Registrar) Register(ctx context.Context) error {
	release, err := s.beginRegistration(ctx)
	if err != nil {
		return fmt.Errorf("registering IMS: %w", err)
	}
	defer release()

	s.logger.Info("registering IMS", "public_identity", s.State().PublicIdentity)
	challengeMsg, err := s.awaitRegisterChallenge(ctx)
	if err != nil {
		return fmt.Errorf("registering IMS: %w", err)
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
		initialAuth, err = s.buildRegisterAuthorization(ctx, challenge)
		if err == nil {
			break
		}
		resp, err := s.exchangeAKAFailure(ctx, challenge, s.currentAuthorizationHeaderName(), s.CurrentFlow(), err)
		if err != nil {
			return fmt.Errorf("registering IMS: %w", err)
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
		return fmt.Errorf("registering IMS: %w", err)
	}
	state := s.State()
	s.logger.Info("IMS registration established", "public_identity", state.PublicIdentity, "register_expires", state.RegisterExpires, "service_routes", len(state.ServiceRoutes))
	return nil
}

func (s *Registrar) Establish(ctx context.Context) error {
	return s.Register(ctx)
}

func (s *Registrar) beginRegistration(ctx context.Context) (func(), error) {
	select {
	case s.registrationGate <- struct{}{}:
		return func() { <-s.registrationGate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Registrar) awaitRegisterChallenge(ctx context.Context) (sip.Message, error) {
	adjustedExpires := false
	for {
		resp, err := s.sess.Exchange(ctx, s.buildRegister(nil, nil))
		if err != nil {
			if registrationTimeoutRequiresInitial(err) {
				return sip.Message{}, initialRegistrationRequiredAfterError(err)
			}
			return sip.Message{}, err
		}
		if resp.StatusCode() == sipStatusIntervalTooBrief {
			if err := s.adjustRegisterExpiresFrom423(resp, &adjustedExpires); err != nil {
				return sip.Message{}, err
			}
			continue
		}
		if !registerAuthChallengeStatus(resp.StatusCode()) {
			if resp.StatusCode() == sipStatusUseProxy {
				return sip.Message{}, pcscfReselectionRequiredError(resp)
			}
			if initialRegistrationRetryResponse(resp) {
				return sip.Message{}, initialRegistrationRequiredError(resp)
			}
			return sip.Message{}, fmt.Errorf("expected authentication challenge, got %d", resp.StatusCode())
		}
		return resp, nil
	}
}

func (s *Registrar) completeRegistration(ctx context.Context, challenge security.Challenge, initialAuth *security.Authorization) error {
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
			auth, err = s.buildRegisterAuthorization(ctx, challenge)
			if err != nil {
				resp, err := s.exchangeAKAFailure(ctx, challenge, s.currentAuthorizationHeaderName(), s.CurrentFlow(), err)
				if err != nil {
					return err
				}
				if resynchronized {
					return errors.New("repeated AKA synchronization failure")
				}
				nextChallenge, err := s.applyRegisterChallenge(resp)
				if err != nil {
					return err
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
				return err
			}
			pendingSecurity = nextSecurity
			secureTransportStale = false
		}
		resp, err := s.exchangeProtectedRegister(ctx, pendingSecurity, auth)
		if err != nil {
			if registrationTimeoutRequiresInitial(err) {
				return initialRegistrationRequiredAfterError(err)
			}
			return err
		}
		if resp.StatusCode() == sipStatusIntervalTooBrief {
			if err := s.adjustRegisterExpiresFrom423(resp, &adjustedExpires); err != nil {
				return err
			}
			rechallenged = false
			auth = nil
			continue
		}
		if registerAuthChallengeStatus(resp.StatusCode()) {
			if rechallenged {
				return errors.New("repeated authentication challenge")
			}
			nextChallenge, err := s.applyRegisterChallenge(resp)
			if err != nil {
				return err
			}
			challenge = nextChallenge
			rechallenged = true
			secureTransportStale = s.currentSecurityVerify() != nil
			auth = nil
			continue
		}
		if resp.StatusCode() != sipStatusOK {
			if resp.StatusCode() == sipStatusUseProxy {
				return pcscfReselectionRequiredError(resp)
			}
			if initialRegistrationRetryResponse(resp) {
				return initialRegistrationRequiredError(resp)
			}
			return fmt.Errorf("expected 200, got %w", sip.NewResponseError(resp))
		}
		if err := s.verifyAuthenticationInfo(resp, auth); err != nil {
			return err
		}
		if err := s.commitRegisterSecurity(pendingSecurity); err != nil {
			return err
		}
		s.applyRegisterSuccess(resp)
		committedSecurity = true
		return nil
	}
}

func (s *Registrar) reauthenticateRefresh(ctx context.Context, challengeResp sip.Message, proposedFlow Flow) error {
	currentFlow := s.CurrentFlow()
	parsed, err := parseRegisterChallenge(challengeResp, proposedFlow.SecurityClients)
	if err != nil {
		return fmt.Errorf("refreshing IMS registration: %w", err)
	}
	challenge := parsed.challenge
	verify := parsed.verify
	if err := validateReauthenticationSecurityServer(currentFlow, verify); err != nil {
		return fmt.Errorf("refreshing IMS registration: %w", err)
	}
	raw := parsed.rawSecurityServer
	authorizationHeader := parsed.authorizationHeader
	var auth *security.Authorization
	var ck, ik []byte
	var password string
	resynchronized := false
	for {
		auth, ck, ik, password, err = s.calculateRegisterAuthorization(ctx, challenge, 1)
		if err == nil {
			break
		}
		resp, err := s.exchangeAKAFailure(ctx, challenge, authorizationHeader, proposedFlow, err)
		if err != nil {
			return fmt.Errorf("refreshing IMS registration: %w", err)
		}
		if resynchronized {
			return errors.New("refreshing IMS registration: repeated AKA synchronization failure")
		}
		parsed, err = parseRegisterChallenge(resp, proposedFlow.SecurityClients)
		if err != nil {
			return fmt.Errorf("refreshing IMS registration: %w", err)
		}
		challenge = parsed.challenge
		verify = parsed.verify
		if err := validateReauthenticationSecurityServer(currentFlow, verify); err != nil {
			return fmt.Errorf("refreshing IMS registration: %w", err)
		}
		raw = parsed.rawSecurityServer
		authorizationHeader = parsed.authorizationHeader
		resynchronized = true
	}

	nextFlow := proposedFlow.clone()
	nextFlow.SecurityVerify = verify
	nextFlow.SecurityServerRaw = append([]string(nil), raw...)
	if parsed.publicContactHost != "" {
		nextFlow.ContactHost = parsed.publicContactHost
	}
	if verify == nil {
		nextFlow.MessagePort = nextFlow.RegisterPort
		req := s.buildRegisterForFlowWithAuthorizationHeader(auth, nil, nextFlow, authorizationHeader)
		resp, err := s.sess.Exchange(ctx, req)
		if err != nil {
			if registrationTimeoutRequiresInitial(err) {
				return fmt.Errorf("refreshing IMS registration: completing AKAv2 re-authentication: %w", initialRegistrationRequiredAfterError(err))
			}
			return fmt.Errorf("refreshing IMS registration: completing AKAv2 re-authentication: %w", err)
		}
		if resp.StatusCode() != sipStatusOK {
			if resp.StatusCode() == sipStatusUseProxy {
				return fmt.Errorf("refreshing IMS registration: %w", pcscfReselectionRequiredError(resp))
			}
			if reregistrationInitialRequiredStatus(resp.StatusCode()) {
				return fmt.Errorf("refreshing IMS registration: %w", initialRegistrationRequiredError(resp))
			}
			return fmt.Errorf("refreshing IMS registration: expected 200 after AKAv2 re-authentication, got %w", sip.NewResponseError(resp))
		}
		s.commitReauthentication(challenge, authorizationHeader, nextFlow, nil, nil, password)
		s.applyRegisterSuccess(resp)
		return nil
	}
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

	responseAttachments, err := s.startSecureResponseTransportsWithKeys(ctx, verify, nextFlow, outbound, inboundTransports, ck, ik)
	if err != nil {
		return fmt.Errorf("refreshing IMS registration: %w", err)
	}
	cleanup = append(cleanup, responseAttachments...)

	req := s.buildRegisterForFlowWithAuthorizationHeader(auth, verify, nextFlow, authorizationHeader)
	responseTransports := reauthResponseTransports(outbound, inboundTransports)
	newTransports := append([]session.Transport{outbound}, inboundTransports...)
	newTransports = append(newTransports, attachmentTransports(responseAttachments)...)
	newTransports = uniqueSessionTransports(newTransports)
	inboundWatch, err := s.sess.WatchTransportsInboundExcept(req, newTransports...)
	if err != nil {
		return fmt.Errorf("refreshing IMS registration: watching new security associations: %w", err)
	}
	defer func() {
		if !committed {
			inboundWatch.Close()
		}
	}()
	resp, err := s.sess.ExchangeWithTransport(ctx, outbound, req, session.ExchangeOptions{
		AcceptResponseTransport: acceptResponseFrom(responseTransports),
		ResponseTransports:      responseTransports,
	})
	if err != nil {
		if registrationTimeoutRequiresInitial(err) {
			return fmt.Errorf("refreshing IMS registration: completing re-authentication: %w", initialRegistrationRequiredAfterError(err))
		}
		return fmt.Errorf("refreshing IMS registration: completing re-authentication: %w", err)
	}
	if resp.StatusCode() != sipStatusOK {
		if resp.StatusCode() == sipStatusUseProxy {
			return fmt.Errorf("refreshing IMS registration: %w", pcscfReselectionRequiredError(resp))
		}
		if reregistrationInitialRequiredStatus(resp.StatusCode()) {
			return fmt.Errorf("refreshing IMS registration: %w", initialRegistrationRequiredError(resp))
		}
		return fmt.Errorf("refreshing IMS registration: expected 200 after re-authentication, got %w", sip.NewResponseError(resp))
	}
	oldExpiresAt := s.currentSecureAssociationExpiresAt()
	oldAttachment, err := s.sess.PromotePrimary(outbound)
	if err != nil {
		return fmt.Errorf("refreshing IMS registration: promoting secure IMS transport: %w", err)
	}
	oldServerAttachments := s.replaceSecureServerAttachments(inboundAttachments)
	oldResponseAttachments := s.replaceSecureResponseAttachments(responseAttachments)
	s.commitReauthentication(challenge, authorizationHeader, nextFlow, ck, ik, password)
	s.applyRegisterSuccess(resp)
	s.closeOldSecurityAfterNewInbound(
		append(append(oldServerAttachments, oldResponseAttachments...), oldAttachment),
		oldExpiresAt,
		inboundWatch,
	)
	committed = true
	return nil
}

func (s *Registrar) Refresh(ctx context.Context) error {
	release, err := s.beginRegistration(ctx)
	if err != nil {
		return fmt.Errorf("refreshing IMS registration: %w", err)
	}
	defer release()

	flow := s.CurrentFlow()
	if flow.SecurityVerify != nil {
		flow.SecurityClient = reauthSecurityClient(flow.SecurityClient, *flow.SecurityVerify, flow.RegisterPort)
		flow.SecurityClients = reauthSecurityClientCapabilities(flow.SecurityClient, *flow.SecurityVerify)
	}
	state := refreshRegisterState{flow: flow}
	for range 6 {
		req, auth, err := s.buildRefreshRegister(ctx, state.flow)
		if err != nil {
			resp, err := s.exchangeCurrentAKAFailure(ctx, err)
			if err != nil {
				return fmt.Errorf("refreshing IMS registration: %w", err)
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
			if registrationTimeoutRequiresInitial(err) {
				return fmt.Errorf("refreshing IMS registration: %w", initialRegistrationRequiredAfterError(err))
			}
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

func (s *Registrar) Maintain(ctx context.Context) error {
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

func (s *Registrar) Deregister(ctx context.Context) error {
	return s.deregister(ctx)
}

func (s *Registrar) deregister(ctx context.Context) error {
	release, err := s.beginRegistration(ctx)
	if err != nil {
		return fmt.Errorf("deregistering IMS: %w", err)
	}
	defer release()

	if !s.isRegistered() {
		return nil
	}
	verify := s.currentSecurityVerify()
	challenge := s.currentAuthChallenge()
	challenged := false
	for range 2 {
		req, err := s.buildDeregisterMessage(ctx, verify, challenge)
		if err != nil {
			return fmt.Errorf("deregistering IMS: %w", err)
		}
		resp, err := s.sess.Exchange(ctx, req)
		if err != nil {
			return fmt.Errorf("deregistering IMS: %w", err)
		}
		done, err := s.handleDeregisterResponse(resp, &challenged, &challenge)
		if err != nil {
			return fmt.Errorf("deregistering IMS: %w", err)
		}
		if done {
			if err := s.clearRegistrationState(); err != nil {
				return fmt.Errorf("deregistering IMS: deleting registration security state: %w", err)
			}
			s.logger.Info("IMS deregistered")
			return nil
		}
	}
	return errors.New("deregistering IMS: exhausted retries")
}

func (s *Registrar) buildDeregisterMessage(ctx context.Context, verify *security.Param, challenge security.Challenge) (sip.Message, error) {
	auth, err := s.buildRegisterAuthorization(ctx, challenge)
	if err != nil {
		return sip.Message{}, err
	}
	return s.buildDeregister(auth, verify), nil
}

func (s *Registrar) handleDeregisterResponse(resp sip.Message, challenged *bool, challenge *security.Challenge) (bool, error) {
	switch resp.StatusCode() {
	case sipStatusOK:
		return true, nil
	case sipStatusUnauthorized, sipStatusProxyAuthenticationRequired:
		if *challenged {
			return false, errors.New("repeated authentication challenge")
		}
		parsed, err := selectRegisterChallengeForResponse(resp)
		if err != nil {
			return false, err
		}
		s.storeAuthChallenge(parsed.challenge, parsed.authorizationHeader)
		*challenge = parsed.challenge
		*challenged = true
		return false, nil
	default:
		return false, fmt.Errorf("unexpected response: %w", sip.NewResponseError(resp))
	}
}
