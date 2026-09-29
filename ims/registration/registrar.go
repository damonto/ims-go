package registration

import (
	"context"
	cryptorand "crypto/rand"
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

// Config specifies registration identity, transport security, and notifications.
type Config struct {
	PrivateIdentity           string
	PublicIdentity            string
	HomeDomain                string
	UserAgent                 string
	AccessNetworkInfo         string
	WLANNodeID                string
	RegisterExpires           time.Duration
	IMEI                      string
	AuthAlgorithm             string
	RegistrationGroup         *Group
	RegistrationID            uint32
	RegistrationPreference    int
	IPSecIntegrityAlgorithms  []string
	IPSecEncryptionAlgorithms []string
	IPSecModes                []string
	GeolocationPIDFRegister   []int
	GeolocationCountry        string
	UseTelURIForPIDFXML       bool
	Logger                    *slog.Logger
	// OnRegistrationChange must return promptly; consumers read Info for the
	// latest state. It can run during establishment, refresh, or cleanup.
	// It must not re-enter registration or cleanup operations on this registrar.
	OnRegistrationChange func()

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

// State is a snapshot of the registrar and its current SIP flow.
type State struct {
	Registered bool
	// AssociatedURIs comes from the latest accepted REGISTER response.
	AssociatedURIs      []string
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
	ContactURI          string
	UserAgent           string
	AccessNetworkInfo   string
	IMEI                string
	GeolocationCountry  string
	UseTelURIForPIDFXML bool
	registrationID      uint32
}

type Registrar struct {
	cfg               Config
	sess              *session.Stack
	card              Card
	logger            *slog.Logger
	attachment        session.Attachment
	group             *Group
	contactUser       string
	keepAliveInterval func(time.Duration) time.Duration

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

	registrationEvents          chan error
	subscribeRefreshRequests    chan struct{}
	registrationMaintenanceStop chan struct{}
	registrationReplacementDone chan struct{}
	done                        chan struct{}
	secureServerAttachments     []session.Attachment
	secureResponseAttachments   []session.Attachment
	unprotectedPrimary          session.Transport
	drainTimers                 []*attachmentDrain
	activeSecureSAExpiresAt     time.Time
	activeSecureSAExpiry        *secureAssociationExpiry
	registrationKeepAlive       *registrationKeepAlive
	bgWG                        sync.WaitGroup
	secureCleanupWG             sync.WaitGroup
	maintenanceWG               sync.WaitGroup
	replacementWG               sync.WaitGroup
	// registrationCommitMu serializes maintenance response commits with
	// network-driven registration cleanup.
	registrationCommitMu            sync.Mutex
	maintenanceCancels              map[uint64]context.CancelCauseFunc
	nextMaintenanceOperation        uint64
	registrationMaintenanceStopped  bool
	registrationReplacementPending  bool
	registrationReplacementFinished bool
	closed                          bool
}

const defaultIMSExpires = 600000 * time.Second
const secureAssociationLifetimeGrace = 30 * time.Second
const maxSIPCSeq = 1<<31 - 1

func New(cfg Config, sess *session.Stack, card Card) (*Registrar, error) {
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
	group := cfg.RegistrationGroup
	if group == nil {
		group = &Group{}
	}
	registrar := &Registrar{
		cfg:               cfg,
		sess:              sess,
		card:              card,
		logger:            cfg.Logger.With("component", "ims-registration"),
		group:             group,
		contactUser:       cryptorand.Text(),
		keepAliveInterval: randomizedRegistrationKeepAliveInterval,
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
			registrationID:      cfg.RegistrationID,
		},
		flow:                        newFlow(host, port, ipsecAlgorithmsFromConfig(cfg)),
		callID:                      callID,
		sessionID:                   sessionID,
		tag:                         tag,
		regInfoRegistrations:        make(map[string]regInfoRegistrationEntry),
		registrationEvents:          make(chan error, 1),
		subscribeRefreshRequests:    make(chan struct{}, 1),
		registrationMaintenanceStop: make(chan struct{}),
		registrationReplacementDone: make(chan struct{}),
		maintenanceCancels:          make(map[uint64]context.CancelCauseFunc),
		done:                        make(chan struct{}),
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

func (s *Registrar) beginMaintenanceOperation(ctx context.Context) (context.Context, func(), error) {
	operationCtx, cancel := context.WithCancelCause(ctx)
	s.mu.Lock()
	if s.closed || s.registrationMaintenanceStopped {
		s.mu.Unlock()
		cancel(errRegistrationStopped)
		return nil, nil, errRegistrationStopped
	}
	operationID := s.nextMaintenanceOperation
	s.nextMaintenanceOperation++
	s.maintenanceCancels[operationID] = cancel
	s.maintenanceWG.Add(1)
	s.mu.Unlock()

	return operationCtx, func() {
		s.mu.Lock()
		delete(s.maintenanceCancels, operationID)
		s.mu.Unlock()
		cancel(nil)
		s.maintenanceWG.Done()
	}, nil
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

func (s *Registrar) Register(ctx context.Context) (retErr error) {
	defer func() {
		if retErr != nil {
			retErr = fmt.Errorf("registering IMS: %w", retErr)
		}
	}()

	s.logger.Info("waiting for IMS registration slot", "public_identity", s.State().PublicIdentity)
	release, err := s.beginRegistration(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if !s.isRegistered() {
			s.releaseRegistrationOwnership()
		}
		release()
	}()

	s.logger.Info("registering IMS", "public_identity", s.State().PublicIdentity)
	challengeMsg, err := s.awaitRegisterChallenge(ctx)
	if err != nil {
		return err
	}
	challenge, err := s.applyRegisterChallenge(challengeMsg)
	if err != nil {
		if !errors.Is(err, errSecurityAgreementInvalid) {
			return err
		}
		s.logger.Info("retrying initial IMS registration after invalid Security-Server", "err", err)
		s.resetRegisterTransaction()
		challengeMsg, err = s.awaitRegisterChallenge(ctx)
		if err != nil {
			return err
		}
		challenge, err = s.applyRegisterChallenge(challengeMsg)
		if err != nil {
			return err
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
			return err
		}
		if resynchronized {
			return errors.New("repeated AKA synchronization failure")
		}
		challenge, err = s.applyRegisterChallenge(resp)
		if err != nil {
			return err
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

func (s *Registrar) Establish(ctx context.Context) error {
	return s.Register(ctx)
}

func (s *Registrar) beginRegistration(ctx context.Context) (func(), error) {
	return s.group.beginRegistrationForFlowUntil(
		ctx,
		s.cfg.RegistrationID,
		s.cfg.RegistrationPreference,
		s.registrationMaintenanceStop,
	)
}

func (s *Registrar) beginDeregistration(ctx context.Context) (func(), bool, error) {
	if s.cfg.RegistrationGroup != nil {
		return s.group.beginDeregistrationForFlow(ctx, s.cfg.RegistrationID, s.cfg.RegistrationPreference)
	}
	release, err := s.group.BeginRegistration(ctx, s.cfg.RegistrationPreference)
	return release, true, err
}

func (s *Registrar) awaitRegisterChallenge(ctx context.Context) (sip.Message, error) {
	adjustedExpires := false
	natPortsAdjusted := false
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
		if initialNATPortCollisionResponse(resp) {
			if natPortsAdjusted {
				return sip.Message{}, errors.New("repeated incompatible network address response")
			}
			s.rotateInitialNATProtectedPorts()
			natPortsAdjusted = true
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
			if err := pendingSecurity.close(); err != nil {
				s.logger.Warn("closing pending IMS security failed", "err", err)
			}
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
			if err := pendingSecurity.close(); err != nil {
				return fmt.Errorf("closing stale IMS security: %w", err)
			}
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
		singleRegistration, err := s.validateRegisterSuccess(resp)
		if err != nil {
			return err
		}
		if err := s.commitRegisterSecurity(pendingSecurity); err != nil {
			return err
		}
		s.applyRegisterCapability(singleRegistration)
		s.applyRegisterSuccess(resp)
		committedSecurity = true
		return nil
	}
}

func (s *Registrar) reauthenticateRefresh(ctx context.Context, challengeResp sip.Message, proposedFlow Flow) error {
	currentFlow := s.CurrentFlow()
	requiredMode := ""
	if currentFlow.SecurityVerify != nil {
		requiredMode = currentFlow.SecurityVerify.Mod
	}
	parsed, err := parseRegisterChallenge(challengeResp, proposedFlow.SecurityClients, requiredMode)
	if err != nil {
		return err
	}
	challenge := parsed.challenge
	verify := parsed.verify
	if err := validateReauthenticationSecurityServer(currentFlow, verify); err != nil {
		return err
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
			return err
		}
		if resynchronized {
			return errors.New("repeated AKA synchronization failure")
		}
		parsed, err = parseRegisterChallenge(resp, proposedFlow.SecurityClients, requiredMode)
		if err != nil {
			return err
		}
		challenge = parsed.challenge
		verify = parsed.verify
		if err := validateReauthenticationSecurityServer(currentFlow, verify); err != nil {
			return err
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
				return fmt.Errorf("completing AKAv2 re-authentication: %w", initialRegistrationRequiredAfterError(err))
			}
			return fmt.Errorf("completing AKAv2 re-authentication: %w", err)
		}
		if resp.StatusCode() != sipStatusOK {
			if resp.StatusCode() == sipStatusUseProxy {
				return pcscfReselectionRequiredError(resp)
			}
			if reregistrationInitialRequiredStatus(resp.StatusCode()) {
				return initialRegistrationRequiredError(resp)
			}
			return fmt.Errorf("expected 200 after AKAv2 re-authentication, got %w", sip.NewResponseError(resp))
		}
		singleRegistration, err := s.validateRegisterSuccessForFlow(resp, nextFlow)
		if err != nil {
			return err
		}
		s.registrationCommitMu.Lock()
		if channelClosed(s.registrationMaintenanceStop) {
			s.registrationCommitMu.Unlock()
			return errRegistrationStopped
		}
		s.commitReauthentication(challenge, authorizationHeader, nextFlow, nil, nil, password)
		s.applyRegisterCapability(singleRegistration)
		s.applyRegisterSuccess(resp)
		s.registrationCommitMu.Unlock()
		return nil
	}
	nextFlow.MessagePort = nextFlow.SecurityClient.PortS

	outbound, err := s.dialSecureTransport(ctx, verify, nextFlow, ck, ik)
	if err != nil {
		return err
	}
	outboundAttachment, err := s.sess.AddTransport(outbound)
	if err != nil {
		return errors.Join(fmt.Errorf("adding secure IMS transport: %w", err), outbound.Close())
	}
	cleanup := []session.Attachment{outboundAttachment}
	committed := false
	defer func() {
		if !committed {
			if err := closeAttachments(cleanup); err != nil {
				s.logger.Warn("closing uncommitted IMS security failed", "err", err)
			}
		}
	}()

	inboundTransports, inboundAttachments, err := s.startSecureServerTransportsWithKeys(ctx, verify, nextFlow, ck, ik)
	if err != nil {
		return err
	}
	if len(inboundTransports) == 0 {
		return errors.New("secure inbound transport is not configured")
	}
	cleanup = append(cleanup, inboundAttachments...)

	responseAttachments, err := s.startSecureResponseTransportsWithKeys(ctx, verify, nextFlow, outbound, inboundTransports, ck, ik)
	if err != nil {
		return err
	}
	cleanup = append(cleanup, responseAttachments...)

	req := s.buildRegisterForFlowWithAuthorizationHeader(auth, verify, nextFlow, authorizationHeader)
	responseTransports := reauthResponseTransports(outbound, inboundTransports)
	newTransports := append([]session.Transport{outbound}, inboundTransports...)
	newTransports = append(newTransports, attachmentTransports(responseAttachments)...)
	newTransports = uniqueSessionTransports(newTransports)
	inboundWatch, err := s.sess.WatchTransportsInboundExcept(req, newTransports...)
	if err != nil {
		return fmt.Errorf("watching new security associations: %w", err)
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
			return fmt.Errorf("completing re-authentication: %w", initialRegistrationRequiredAfterError(err))
		}
		return fmt.Errorf("completing re-authentication: %w", err)
	}
	if resp.StatusCode() != sipStatusOK {
		if resp.StatusCode() == sipStatusUseProxy {
			return pcscfReselectionRequiredError(resp)
		}
		if reregistrationInitialRequiredStatus(resp.StatusCode()) {
			return initialRegistrationRequiredError(resp)
		}
		return fmt.Errorf("expected 200 after re-authentication, got %w", sip.NewResponseError(resp))
	}
	singleRegistration, err := s.validateRegisterSuccessForFlow(resp, nextFlow)
	if err != nil {
		return err
	}
	s.registrationCommitMu.Lock()
	if channelClosed(s.registrationMaintenanceStop) {
		s.registrationCommitMu.Unlock()
		return errRegistrationStopped
	}
	oldExpiresAt := s.currentSecureAssociationExpiresAt()
	oldAttachment, err := s.sess.PromotePrimary(outbound)
	if err != nil {
		s.registrationCommitMu.Unlock()
		return fmt.Errorf("promoting secure IMS transport: %w", err)
	}
	oldServerAttachments := s.replaceSecureServerAttachments(inboundAttachments)
	oldResponseAttachments := s.replaceSecureResponseAttachments(responseAttachments)
	s.commitReauthentication(challenge, authorizationHeader, nextFlow, ck, ik, password)
	s.applyRegisterCapability(singleRegistration)
	s.applyRegisterSuccess(resp)
	s.registrationCommitMu.Unlock()
	committed = true
	s.closeOldSecurityAfterNewInbound(
		append(append(oldServerAttachments, oldResponseAttachments...), oldAttachment),
		oldExpiresAt,
		inboundWatch,
	)
	return nil
}

func (s *Registrar) Refresh(ctx context.Context) (retErr error) {
	defer func() {
		if retErr != nil {
			retErr = fmt.Errorf("refreshing IMS registration: %w", retErr)
		}
	}()

	release, err := s.beginRegistration(ctx)
	if err != nil {
		return err
	}
	defer release()
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
	ctx = operationCtx

	flow := s.CurrentFlow()
	if flow.SecurityVerify != nil {
		flow.SecurityClient = reauthSecurityClient(flow.SecurityClient, *flow.SecurityVerify, flow.RegisterPort)
		flow.SecurityClients, err = reauthenticationSecurityClientCapabilities(flow.SecurityClient, ipsecAlgorithmsFromConfig(s.cfg))
		if err != nil {
			return err
		}
	}
	state := refreshRegisterState{flow: flow}
	for range 6 {
		req, auth, err := s.buildRefreshRegister(ctx, state.flow)
		if err != nil {
			resp, err := s.exchangeCurrentAKAFailure(ctx, err)
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
			if registrationTimeoutRequiresInitial(err) {
				return initialRegistrationRequiredAfterError(err)
			}
			return err
		}
		done, err := s.handleRefreshRegistration(ctx, resp, &state, auth)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return errors.New("exhausted retries")
}

func (s *Registrar) Maintain(ctx context.Context) error {
	registerTimer := time.NewTimer(s.refreshInterval())
	defer registerTimer.Stop()
	registerTimerC := registerTimer.C
	subscribeTimer := time.NewTimer(s.subscribeRefreshInterval())
	defer subscribeTimer.Stop()
	subscribeTimerC := subscribeTimer.C
	subscribeRefreshRequests := (<-chan struct{})(s.subscribeRefreshRequests)
	maintenanceStop := (<-chan struct{})(s.registrationMaintenanceStop)
	stopMaintenance := func() {
		maintenanceStop = nil
		registerTimerC = nil
		subscribeTimerC = nil
		subscribeRefreshRequests = nil
		stopTimer(registerTimer)
		stopTimer(subscribeTimer)
		s.logger.Info("IMS registration maintenance stopped")
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-maintenanceStop:
			stopMaintenance()
		case err := <-s.registrationEvents:
			return err
		case <-subscribeRefreshRequests:
			if channelClosed(s.registrationMaintenanceStop) {
				stopMaintenance()
				continue
			}
			s.refreshSubscription(ctx)
			resetTimer(subscribeTimer, s.subscribeRefreshInterval())
		case <-registerTimerC:
			if err := s.Refresh(ctx); err != nil {
				if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
					return ctx.Err()
				}
				if errors.Is(err, errRegistrationStopped) {
					stopMaintenance()
					continue
				}
				return err
			}
			s.logger.Info("IMS registration refreshed", "next_refresh", s.refreshInterval())
			registerTimer.Reset(s.refreshInterval())
		case <-subscribeTimerC:
			if channelClosed(s.registrationMaintenanceStop) {
				stopMaintenance()
				continue
			}
			s.refreshSubscription(ctx)
			subscribeTimer.Reset(s.subscribeRefreshInterval())
		}
	}
}

func (s *Registrar) Deregister(ctx context.Context) error {
	return s.deregister(ctx)
}

func (s *Registrar) deregister(ctx context.Context) (retErr error) {
	defer func() {
		if retErr != nil {
			retErr = fmt.Errorf("deregistering IMS: %w", retErr)
		}
	}()

	release, ownsRegistration, err := s.beginDeregistration(ctx)
	if err != nil {
		return err
	}
	defer release()
	return s.deregisterCurrent(ctx, ownsRegistration)
}

func (s *Registrar) deregisterCurrent(ctx context.Context, ownsRegistration bool) error {
	if !s.isRegistered() {
		return nil
	}
	if !ownsRegistration {
		if err := s.clearRegistrationState(); err != nil {
			return fmt.Errorf("deleting replaced registration state: %w", err)
		}
		s.logger.Info("IMS registration already replaced by preferred flow")
		return nil
	}
	verify := s.currentSecurityVerify()
	challenge := s.currentAuthChallenge()
	challenged := false
	for range 2 {
		req, err := s.buildDeregisterMessage(ctx, verify, challenge)
		if err != nil {
			return err
		}
		resp, err := s.sess.Exchange(ctx, req)
		if err != nil {
			return err
		}
		done, err := s.handleDeregisterResponse(resp, &challenged, &challenge)
		if err != nil {
			return err
		}
		if done {
			if err := s.clearRegistrationState(); err != nil {
				return fmt.Errorf("deleting registration security state: %w", err)
			}
			s.logger.Info("IMS deregistered")
			return nil
		}
	}
	return errors.New("exhausted retries")
}

func (s *Registrar) retireSingleRegistration() {
	s.mu.Lock()
	if s.closed || s.registrationReplacementPending {
		s.mu.Unlock()
		return
	}
	s.registrationReplacementPending = true
	s.stopRegistrationMaintenanceLocked()
	done := s.done
	replacementDone := s.registrationReplacementDone
	// There is no dedicated protocol timer for a missing replacement NOTIFY.
	// Timer F provides a bounded watchdog consistent with other non-INVITE
	// registration transactions on this connection.
	timeout := s.sess.TransactionTimers().TF
	s.replacementWG.Go(func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			if !s.finishRegistrationReplacement() {
				return
			}
			s.logger.Warn("network replacement notification timed out; retiring IMS flow locally")
			s.registrationCommitMu.Lock()
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				s.registrationCommitMu.Unlock()
				return
			}
			err := s.clearRegistrationState()
			s.registrationCommitMu.Unlock()
			if err != nil {
				s.logger.Error("deleting replaced IMS registration security state", "err", err)
			}
			s.publishRegistrationEvent(ErrRegistrationReplaced)
		case <-replacementDone:
		case <-done:
		}
	})
	s.mu.Unlock()

	s.logger.Info("IMS registration replaced; waiting for network deregistration", "timeout", timeout)
}

func (s *Registrar) stopRegistrationMaintenance() {
	s.mu.Lock()
	s.stopRegistrationMaintenanceLocked()
	s.mu.Unlock()
}

func (s *Registrar) stopRegistrationMaintenanceLocked() {
	if s.registrationMaintenanceStopped {
		return
	}
	s.registrationMaintenanceStopped = true
	close(s.registrationMaintenanceStop)
	for _, cancel := range s.maintenanceCancels {
		cancel(errRegistrationStopped)
	}
}

func (s *Registrar) finishRegistrationReplacement() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.registrationReplacementPending || s.registrationReplacementFinished {
		return false
	}
	s.registrationReplacementFinished = true
	close(s.registrationReplacementDone)
	return true
}

func (s *Registrar) registrationReplacementActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.registrationReplacementPending
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
