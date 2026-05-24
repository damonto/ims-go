package registration

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/damonto/ims-client/ims/security"
	"github.com/damonto/ims-client/ims/session"
	"github.com/damonto/ims-client/ims/sip"
	"github.com/damonto/ims-client/usim"
)

type Config struct {
	PrivateIdentity   string
	PublicIdentity    string
	HomeDomain        string
	UserAgent         string
	AccessNetworkInfo string
	WLANNodeID        string
	RegisterExpires   time.Duration
	IMEI              string

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
	Registered        bool
	PublicIdentity    string
	DefaultPublicID   string
	PrivateIdentity   string
	HomeDomain        string
	RegisterURI       string
	TelPublicID       string
	Flow              Flow
	ServiceRoutes     []string
	SecurityClient    security.Param
	SecurityVerify    *security.Param
	RegisterExpires   time.Duration
	ContactHost       string
	RegisterPort      int
	MessagePort       int
	UserAgent         string
	AccessNetworkInfo string
	IMEI              string
}

type Service struct {
	cfg        Config
	sess       *session.Session
	card       Card
	logger     *slog.Logger
	attachment session.Attachment

	mu             sync.Mutex
	state          State
	flow           Flow
	authCK         []byte
	authIK         []byte
	authNonce      string
	authRealm      string
	authQOP        string
	authNonceCount uint32
	callID         string
	sessionID      string
	tag            string
	cseq           int64
}

const defaultUserAgent = "Google_Pixel 3XLAndroid12SQ3A.220705.004"

func New(cfg Config, sess *session.Session, card Card) (*Service, error) {
	if sess == nil {
		return nil, errors.New("creating registration service: session is nil")
	}
	if card == nil {
		return nil, errors.New("creating registration service: card is nil")
	}
	cfg = normalizeConfig(cfg)

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
		logger: slog.Default().With("component", "ims-registration"),
		state: State{
			PublicIdentity:    identity.publicIdentity,
			DefaultPublicID:   identity.publicIdentity,
			PrivateIdentity:   identity.privateIdentity,
			HomeDomain:        identity.realm,
			RegisterURI:       "sip:" + identity.realm,
			RegisterExpires:   cfg.RegisterExpires,
			UserAgent:         cfg.UserAgent,
			AccessNetworkInfo: accessNetworkInfo(cfg),
			IMEI:              cfg.IMEI,
		},
		flow: Flow{
			ContactHost:    host,
			RegisterPort:   port,
			MessagePort:    port,
			SecurityClient: newSecurityClient(port),
		},
		callID:    callID,
		sessionID: sessionID,
		tag:       tag,
	}
	attachment, err := sess.Attach(svc)
	if err != nil {
		return nil, fmt.Errorf("creating registration service: %w", err)
	}
	svc.attachment = attachment
	return svc, nil
}

func (s *Service) Register(ctx context.Context) error {
	ctx = normalizeContext(ctx)
	challengeMsg, err := s.awaitRegisterChallenge(ctx)
	if err != nil {
		return err
	}
	challenge, err := s.applyRegisterChallenge(challengeMsg)
	if err != nil {
		return fmt.Errorf("registering IMS: %w", err)
	}
	initialAuth, err := s.buildRegisterAuthorization(ctx, challenge.Realm, challenge.Nonce, challenge.QOP)
	if err != nil {
		return fmt.Errorf("registering IMS: %w", err)
	}
	if err := s.upgradeSecureTransport(ctx); err != nil {
		return fmt.Errorf("registering IMS: %w", err)
	}
	return s.completeRegistration(ctx, challenge, initialAuth)
}

func (s *Service) Subscribe(ctx context.Context) error {
	ctx = normalizeContext(ctx)
	msg := s.buildSubscribe()
	resp, err := s.sess.Exchange(ctx, msg)
	if err != nil {
		return fmt.Errorf("subscribing IMS registration: %w", err)
	}
	if resp.StatusCode() == 489 {
		s.logger.Debug("registration event subscription unavailable", "status", resp.StatusCode())
		return nil
	}
	if resp.StatusCode() != 200 {
		return fmt.Errorf("subscribing IMS registration: expected 200, got %d", resp.StatusCode())
	}
	return nil
}

func (s *Service) Establish(ctx context.Context) error {
	return s.Register(ctx)
}

func (s *Service) Refresh(ctx context.Context) error {
	ctx = normalizeContext(ctx)
	state := refreshRegisterState{}
	for range 6 {
		req, err := s.buildRefreshRegister(ctx)
		if err != nil {
			return err
		}
		resp, err := s.sess.Exchange(ctx, req)
		if err != nil {
			return fmt.Errorf("refreshing IMS registration: %w", err)
		}
		done, err := s.handleRefreshRegistration(resp, &state)
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
	ctx = normalizeContext(ctx)
	timer := time.NewTimer(s.refreshInterval())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if err := s.Refresh(ctx); err != nil {
				return err
			}
			timer.Reset(s.refreshInterval())
		}
	}
}

func (s *Service) Deregister(ctx context.Context) error {
	ctx = normalizeContext(ctx)
	if !s.isRegistered() {
		return nil
	}
	verify := s.currentSecurityVerify()
	realm, nonce, qop := s.currentAuthState()
	challenged := false
	for range 2 {
		req, err := s.buildDeregisterMessage(ctx, verify, realm, nonce, qop)
		if err != nil {
			return err
		}
		resp, err := s.sess.Exchange(ctx, req)
		if err != nil {
			return fmt.Errorf("deregistering IMS: %w", err)
		}
		done, err := s.handleDeregisterResponse(resp, &challenged, &realm, &nonce, &qop)
		if err != nil {
			return err
		}
		if done {
			s.setRegistered(false)
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
	return state.Flow.RequestPolicy(state.UserAgent, state.AccessNetworkInfo)
}

func (s *Service) DialogRequestPolicy(routes []string) sip.ClientRequestPolicy {
	state := s.State()
	return state.Flow.DialogRequestPolicy(routes, state.UserAgent, state.AccessNetworkInfo)
}

func splitHeaderList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parts := make([]string, 0, 1)
	start := 0
	inQuote := false
	angleDepth := 0
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '"':
			inQuote = !inQuote
		case '<':
			if !inQuote {
				angleDepth++
			}
		case '>':
			if !inQuote && angleDepth > 0 {
				angleDepth--
			}
		case ',':
			if !inQuote && angleDepth == 0 {
				part := strings.TrimSpace(value[start:i])
				if part != "" {
					parts = append(parts, part)
				}
				start = i + 1
			}
		}
	}
	if tail := strings.TrimSpace(value[start:]); tail != "" {
		parts = append(parts, tail)
	}
	return parts
}

func headerAddressURI(value string) string {
	uri := sip.AddressURI(value)
	if uri == "" {
		return ""
	}
	if before, _, ok := strings.Cut(uri, ";"); ok {
		return strings.TrimSpace(before)
	}
	return strings.TrimSpace(uri)
}

func contactURIAndParams(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	if left := strings.IndexByte(value, '<'); left >= 0 {
		right := strings.IndexByte(value[left+1:], '>')
		if right >= 0 {
			uri := strings.TrimSpace(value[left+1 : left+1+right])
			if semi := strings.IndexByte(uri, ';'); semi >= 0 {
				uri = strings.TrimSpace(uri[:semi])
			}
			return uri, value[left+1+right+1:]
		}
	}
	if semi := strings.IndexByte(value, ';'); semi >= 0 {
		return strings.TrimSpace(value[:semi]), value[semi:]
	}
	return value, ""
}

func headerParamValue(params, name string) string {
	for _, part := range strings.Split(params, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), name) {
			continue
		}
		return strings.Trim(strings.TrimSpace(value), `"`)
	}
	return ""
}

func parsePositiveSeconds(value string) (time.Duration, bool) {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds <= 0 {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

func associatedURIsFromMessage(msg sip.Message) []string {
	uris := make([]string, 0)
	for _, value := range msg.HeadersByName("P-Associated-URI") {
		for _, part := range splitHeaderList(value) {
			if uri := headerAddressURI(part); uri != "" {
				uris = append(uris, uri)
			}
		}
	}
	return uris
}

func registerResponseExpires(msg sip.Message, contactURI string) (time.Duration, bool) {
	for _, value := range msg.HeadersByName("Contact") {
		for _, part := range splitHeaderList(value) {
			uri, params := contactURIAndParams(part)
			if uri == "" || !sameContactURI(uri, contactURI) {
				continue
			}
			if expires, ok := parsePositiveSeconds(headerParamValue(params, "expires")); ok {
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
	return s.Deregister(ctx)
}

func (s *Service) HandleRequest(ctx context.Context, req session.Request) (bool, error) {
	if !strings.EqualFold(req.Message.Method(), "NOTIFY") {
		return false, nil
	}
	return true, s.sess.WriteStatus(ctx, req, 200, "OK")
}

func (s *Service) HandleError(err error) {
	if err == nil {
		return
	}
	s.logger.Debug("session error", "err", err)
}

type refreshRegisterState struct {
	adjustedExpires bool
	challenged      bool
	restarted       bool
}

type clientIdentity struct {
	realm           string
	privateIdentity string
	publicIdentity  string
}

func (s *Service) awaitRegisterChallenge(ctx context.Context) (sip.Message, error) {
	adjustedExpires := false
	for {
		resp, err := s.sess.Exchange(ctx, s.buildRegister(nil, nil))
		if err != nil {
			return sip.Message{}, fmt.Errorf("registering IMS: %w", err)
		}
		if resp.StatusCode() == 423 {
			if err := s.adjustRegisterExpiresFrom423("registering IMS", resp, &adjustedExpires); err != nil {
				return sip.Message{}, err
			}
			continue
		}
		if resp.StatusCode() != 401 {
			return sip.Message{}, fmt.Errorf("registering IMS: expected 401, got %d", resp.StatusCode())
		}
		return resp, nil
	}
}

func (s *Service) completeRegistration(ctx context.Context, challenge security.Challenge, initialAuth *security.Authorization) error {
	adjustedExpires := false
	rechallenged := false
	auth := initialAuth
	for {
		if auth == nil {
			var err error
			auth, err = s.buildRegisterAuthorization(ctx, challenge.Realm, challenge.Nonce, challenge.QOP)
			if err != nil {
				return fmt.Errorf("registering IMS: %w", err)
			}
		}
		resp, err := s.sess.Exchange(ctx, s.buildRegister(auth, s.currentSecurityVerify()))
		if err != nil {
			return fmt.Errorf("registering IMS: %w", err)
		}
		if resp.StatusCode() == 423 {
			if err := s.adjustRegisterExpiresFrom423("registering IMS", resp, &adjustedExpires); err != nil {
				return err
			}
			rechallenged = false
			auth = nil
			continue
		}
		if resp.StatusCode() == 401 {
			if rechallenged {
				return errors.New("registering IMS: repeated 401 response")
			}
			nextChallenge, err := s.applyRegisterChallenge(resp)
			if err != nil {
				return fmt.Errorf("registering IMS: %w", err)
			}
			challenge = nextChallenge
			rechallenged = true
			auth = nil
			continue
		}
		if resp.StatusCode() != 200 {
			return fmt.Errorf("registering IMS: expected 200, got %d", resp.StatusCode())
		}
		s.applyRegisterSuccess(resp)
		return nil
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
	s.state.TelPublicID = ""
	for _, uri := range uris {
		if strings.HasPrefix(strings.ToLower(uri), "tel:") {
			s.state.TelPublicID = uri
			break
		}
	}
}

func (s *Service) applyServiceRoutes(msg sip.Message) {
	routes := msg.HeadersByName("Service-Route")
	s.mu.Lock()
	s.flow.ServiceRoutes = append([]string(nil), routes...)
	s.mu.Unlock()
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
	seconds := int(s.currentRegisterExpires() / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

func (s *Service) refreshInterval() time.Duration {
	interval := s.currentRegisterExpires() / 2
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

func (s *Service) securityVerifyValue(verify *security.Param) string {
	if verify == nil {
		return ""
	}
	flow := s.CurrentFlow()
	if value := flow.SecurityVerifyValue(); value != "" {
		return value
	}
	return verify.String()
}

func (s *Service) applySecurityServer(headerValues []string) error {
	verify, raw, err := selectSecurityServer(headerValues)
	if err != nil {
		return err
	}
	if verify == nil {
		return errors.New("applying Security-Server: header is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flow.SecurityServerRaw = append([]string(nil), raw...)
	s.flow.SecurityVerify = verify
	s.flow.MessagePort = s.flow.SecurityClient.PortS
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
	s.mu.Unlock()
}

func (s *Service) applyRegisterExpires(msg sip.Message) {
	expires, ok := registerResponseExpires(msg, s.currentRegisterContactURI())
	if !ok {
		return
	}
	s.setRegisterExpires(expires)
}

func (s *Service) applyRegisterSuccess(msg sip.Message) {
	s.applyAssociatedURI(msg)
	s.applyServiceRoutes(msg)
	s.applyAuthenticationInfo(msg)
	s.applyRegisterExpires(msg)
	s.setRegistered(true)
}

func (s *Service) storeAuthChallenge(challenge security.Challenge) {
	realm := strings.TrimSpace(challenge.Realm)
	if realm == "" {
		realm = strings.TrimPrefix(s.State().RegisterURI, "sip:")
	}
	s.mu.Lock()
	s.authRealm = realm
	s.authNonce = challenge.Nonce
	s.authQOP = challenge.QOP
	s.authNonceCount = 0
	s.mu.Unlock()
}

func (s *Service) currentAuthState() (string, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	realm := s.authRealm
	if realm == "" {
		realm = strings.TrimPrefix(s.state.RegisterURI, "sip:")
	}
	return realm, s.authNonce, s.authQOP
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

func (s *Service) buildRegisterAuthorization(ctx context.Context, realm, nonce, qop string) (*security.Authorization, error) {
	if nonce == "" {
		return nil, nil
	}
	result, err := security.BuildAKAAuthorization(ctx, akaProvider{s.card}, security.Identity{
		PrivateIdentity: s.State().PrivateIdentity,
		RegisterURI:     s.State().RegisterURI,
		Realm:           defaultRealm(realm, s.State().RegisterURI),
	}, security.Challenge{
		Realm: realm,
		Nonce: nonce,
		QOP:   qop,
	}, s.nextAuthNonceCount())
	if err != nil {
		return nil, err
	}
	if len(result.IntegrityKey) != 0 {
		s.authIK = append([]byte(nil), result.IntegrityKey...)
	}
	if len(result.EncryptionKey) != 0 {
		s.authCK = append([]byte(nil), result.EncryptionKey...)
	}
	auth := result.Authorization
	auth.IntegrityProtected = "yes"
	return &auth, nil
}

func (s *Service) applyRegisterChallenge(resp sip.Message) (security.Challenge, error) {
	var challenge security.Challenge
	if err := challenge.UnmarshalText([]byte(resp.Header("WWW-Authenticate"))); err != nil {
		return security.Challenge{}, err
	}
	if _, err := challenge.SelectedQOP(); err != nil {
		return security.Challenge{}, err
	}
	if err := s.applySecurityServer(resp.HeadersByName("Security-Server")); err != nil {
		return security.Challenge{}, err
	}
	s.storeAuthChallenge(challenge)
	return challenge, nil
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

func (s *Service) buildRefreshRegister(ctx context.Context) (sip.Message, error) {
	realm, nonce, qop := s.currentAuthState()
	auth, err := s.buildRegisterAuthorization(ctx, realm, nonce, qop)
	if err != nil {
		return sip.Message{}, err
	}
	return s.buildRegister(auth, s.currentSecurityVerify()), nil
}

func (s *Service) handleRefreshRegistration(resp sip.Message, state *refreshRegisterState) (bool, error) {
	switch resp.StatusCode() {
	case 200:
		s.applyRegisterSuccess(resp)
		return true, nil
	case 401:
		if state.challenged {
			return false, errors.New("refreshing IMS registration: repeated 401 response")
		}
		if _, err := s.applyRegisterChallenge(resp); err != nil {
			return false, fmt.Errorf("refreshing IMS registration: %w", err)
		}
		state.challenged = true
		return false, nil
	case 423:
		if err := s.adjustRegisterExpiresFrom423("refreshing IMS registration", resp, &state.adjustedExpires); err != nil {
			return false, err
		}
		return false, nil
	case 403, 408, 500, 504:
		if state.restarted {
			return false, fmt.Errorf("refreshing IMS registration: repeated restart status %d", resp.StatusCode())
		}
		s.resetAuthStateForRefresh()
		state.challenged = false
		state.adjustedExpires = false
		state.restarted = true
		return false, nil
	default:
		return false, fmt.Errorf("refreshing IMS registration: unexpected status %d", resp.StatusCode())
	}
}

func (s *Service) resetAuthStateForRefresh() {
	s.mu.Lock()
	s.authNonce = ""
	s.authRealm = strings.TrimPrefix(s.state.RegisterURI, "sip:")
	s.authQOP = ""
	s.authNonceCount = 0
	s.mu.Unlock()
}

func (s *Service) buildDeregisterMessage(ctx context.Context, verify *security.Param, realm, nonce, qop string) (sip.Message, error) {
	auth, err := s.buildRegisterAuthorization(ctx, realm, nonce, qop)
	if err != nil {
		return sip.Message{}, fmt.Errorf("deregistering IMS: %w", err)
	}
	return s.buildDeregister(auth, verify), nil
}

func (s *Service) handleDeregisterResponse(resp sip.Message, challenged *bool, realm, nonce, qop *string) (bool, error) {
	switch resp.StatusCode() {
	case 200:
		return true, nil
	case 401:
		if *challenged {
			return false, errors.New("deregistering IMS: repeated 401 response")
		}
		var challenge security.Challenge
		if err := challenge.UnmarshalText([]byte(resp.Header("WWW-Authenticate"))); err != nil {
			return false, fmt.Errorf("deregistering IMS: %w", err)
		}
		if _, err := challenge.SelectedQOP(); err != nil {
			return false, fmt.Errorf("deregistering IMS: %w", err)
		}
		s.storeAuthChallenge(challenge)
		*realm = challenge.Realm
		*nonce = challenge.Nonce
		*qop = challenge.QOP
		*challenged = true
		return false, nil
	default:
		return false, fmt.Errorf("deregistering IMS: unexpected status %d", resp.StatusCode())
	}
}

func (s *Service) upgradeSecureTransport(ctx context.Context) error {
	verify := s.currentSecurityVerify()
	if verify == nil {
		return nil
	}
	flow := s.CurrentFlow()
	var (
		secureTransport session.Transport
		err             error
	)
	switch sip.TransportToken(s.sess.LocalAddr()) {
	case "TCP":
		if s.cfg.DialSecureTCP == nil {
			return nil
		}
		secureTransport, err = s.cfg.DialSecureTCP(ctx, s.secureTransportConfig(verify, flow.SecurityClient.PortC, verify.PortS, verify.SPIS, flow.SecurityClient.SPIC))
		if err != nil {
			return fmt.Errorf("dialing secure IMS transport: %w", err)
		}
	default:
		if s.cfg.DialSecureUDP == nil {
			return nil
		}
		secureTransport, err = s.cfg.DialSecureUDP(ctx, s.secureDatagramTransportConfig(verify, flow.SecurityClient.PortC, verify.PortS, verify.SPIS, flow.SecurityClient.SPIC))
		if err != nil {
			return fmt.Errorf("dialing secure IMS datagram transport: %w", err)
		}
	}
	if err := s.sess.ReplacePrimary(secureTransport); err != nil {
		return fmt.Errorf("replacing secure IMS transport: %w", err)
	}
	if err := s.startSecureServerTransports(ctx, verify); err != nil {
		return err
	}
	return nil
}

func (s *Service) secureTransportConfig(verify *security.Param, localPort, remotePort int, outboundSPI, inboundSPI uint32) session.SecureTCPConfig {
	return session.SecureTCPConfig{
		LocalPort:     localPort,
		RemotePort:    remotePort,
		OutboundSPI:   outboundSPI,
		InboundSPI:    inboundSPI,
		Encryption:    verify.EAlg,
		EncryptionKey: append([]byte(nil), s.authCK...),
		Integrity:     verify.Alg,
		IntegrityKey:  append([]byte(nil), s.authIK...),
	}
}

func (s *Service) secureDatagramTransportConfig(verify *security.Param, localPort, remotePort int, outboundSPI, inboundSPI uint32) session.SecureUDPConfig {
	return session.SecureUDPConfig{
		LocalPort:     localPort,
		RemotePort:    remotePort,
		OutboundSPI:   outboundSPI,
		InboundSPI:    inboundSPI,
		Encryption:    verify.EAlg,
		EncryptionKey: append([]byte(nil), s.authCK...),
		Integrity:     verify.Alg,
		IntegrityKey:  append([]byte(nil), s.authIK...),
	}
}

func (s *Service) startSecureServerTransports(ctx context.Context, verify *security.Param) error {
	flow := s.CurrentFlow()
	if s.cfg.ListenSecureTCP != nil {
		serverTransport, err := s.cfg.ListenSecureTCP(ctx, s.secureTransportConfig(verify, flow.SecurityClient.PortS, verify.PortC, verify.SPIC, flow.SecurityClient.SPIS))
		if err != nil {
			return fmt.Errorf("listening secure IMS transport: %w", err)
		}
		if _, err := s.sess.AddTransport(serverTransport); err != nil {
			return fmt.Errorf("adding secure IMS transport: %w", err)
		}
	}
	if s.cfg.ListenSecureUDP != nil {
		serverDatagramTransport, err := s.cfg.ListenSecureUDP(ctx, s.secureDatagramTransportConfig(verify, flow.SecurityClient.PortS, verify.PortC, verify.SPIC, flow.SecurityClient.SPIS))
		if err != nil {
			return fmt.Errorf("listening secure IMS datagram transport: %w", err)
		}
		if _, err := s.sess.AddTransport(serverDatagramTransport); err != nil {
			return fmt.Errorf("adding secure IMS datagram transport: %w", err)
		}
	}
	return nil
}

func (s *Service) buildRegister(auth *security.Authorization, verify *security.Param) sip.Message {
	port := s.State().RegisterPort
	if verify != nil || auth != nil {
		port = s.State().SecurityClient.PortS
	}
	legacyAuthorization := ""
	if auth == nil {
		legacyAuthorization = s.legacyEmptyAuthorizationValue()
	}
	return s.buildRegisterRequest(auth, legacyAuthorization, verify, s.registerContactValue(port), s.registerExpiresSeconds(), port)
}

func (s *Service) buildDeregister(auth *security.Authorization, verify *security.Param) sip.Message {
	port := s.State().RegisterPort
	if verify != nil || auth != nil {
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

func (s *Service) legacyEmptyAuthorizationValue() string {
	text, _ := (security.Authorization{
		Nonce:              "",
		URI:                s.State().RegisterURI,
		Response:           "",
		Username:           s.State().PrivateIdentity,
		Realm:              s.registerRealm(nil),
		IntegrityProtected: "no",
	}).MarshalText()
	return string(text)
}

func (s *Service) buildRegisterRequest(auth *security.Authorization, legacyAuthorization string, verify *security.Param, contact string, expiresSeconds, port int) sip.Message {
	_, _, _, branch := sip.NewTransaction()
	state := s.State()
	msg := sip.NewRequest("REGISTER", state.RegisterURI)
	msg.Headers.Add("To", fmt.Sprintf("<%s>", state.PublicIdentity))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", state.PublicIdentity, s.tag))
	msg.Headers.Add("Expires", strconv.Itoa(expiresSeconds))
	verifyValue := s.securityVerifyValue(verify)
	sip.SecurityAgreement{Verify: verifyValue, Required: true}.Apply(&msg)
	msg.Headers.Add("Security-Client", state.SecurityClient.String())
	msg.Headers.Add("Call-ID", s.callID)
	msg.Headers.Add("Session-ID", s.sessionID)
	msg.Headers.Add("Contact", contact)
	if auth != nil {
		msg.Headers.Add("Authorization", auth.String())
	} else if legacyAuthorization != "" {
		msg.Headers.Add("Authorization", legacyAuthorization)
	}
	msg.Headers.Add("CSeq", fmt.Sprintf("%d REGISTER", atomic.AddInt64(&s.cseq, 1)))
	transport := sip.TransportToken(s.sess.LocalAddr())
	msg.Headers.Add("Via", sip.BuildViaWithOptions(transport, state.ContactHost, port, branch, sip.ViaOptions{
		Keep: strings.EqualFold(transport, "UDP"),
	}))
	sip.ClientRequestPolicy{
		UserAgent:         state.UserAgent,
		AccessNetworkInfo: state.AccessNetworkInfo,
	}.Apply(&msg)
	return msg
}

func (s *Service) buildSubscribe() sip.Message {
	state := s.State()
	publicID := subscribePublicIdentity(state)
	callID, sessionID, tag, branch := sip.NewTransaction()
	msg := sip.NewRequest("SUBSCRIBE", publicID)
	msg.Headers.Add("Expires", strconv.Itoa(s.registerExpiresSeconds()))
	msg.Headers.Add("Event", "reg")
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", publicID, tag))
	msg.Headers.Add("To", fmt.Sprintf("<%s>", publicID))
	msg.Headers.Add("Call-ID", callID)
	msg.Headers.Add("Session-ID", sessionID)
	msg.Headers.Add("Contact", s.subscribeContactValue(s.messagePort()))
	msg.Headers.Add("CSeq", fmt.Sprintf("%d SUBSCRIBE", atomic.AddInt64(&s.cseq, 1)))
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(s.sess.LocalAddr()), state.ContactHost, s.messagePort(), branch))
	s.RequestPolicy().Apply(&msg)
	return msg
}

func subscribePublicIdentity(state State) string {
	if state.DefaultPublicID != "" {
		return state.DefaultPublicID
	}
	return state.PublicIdentity
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
	if s.cfg.IMEI != "" {
		params = append([]string{fmt.Sprintf(`+sip.instance="<urn:gsma:imei:%s>"`, s.cfg.IMEI)}, params...)
	}
	return fmt.Sprintf("<%s>;%s", contactURI(s.State().ContactHost, port), strings.Join(params, ";"))
}

func (s *Service) registerContactValue(port int) string {
	params := []string{
		`+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`,
		`+g.3gpp.mid-call`,
		`+g.3gpp.nw-init-ussi`,
		`+g.3gpp.ps2cs-srvcc-orig-pre-alerting`,
		`+g.3gpp.smsip`,
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

func normalizeConfig(cfg Config) Config {
	cfg.PrivateIdentity = strings.TrimSpace(cfg.PrivateIdentity)
	cfg.PublicIdentity = strings.TrimSpace(cfg.PublicIdentity)
	cfg.HomeDomain = strings.TrimSpace(cfg.HomeDomain)
	cfg.UserAgent = strings.TrimSpace(cfg.UserAgent)
	cfg.AccessNetworkInfo = strings.TrimSpace(cfg.AccessNetworkInfo)
	cfg.WLANNodeID = strings.TrimSpace(cfg.WLANNodeID)
	cfg.IMEI = strings.TrimSpace(cfg.IMEI)
	if cfg.UserAgent == "" {
		cfg.UserAgent = defaultUserAgent
	}
	if cfg.RegisterExpires == 0 {
		cfg.RegisterExpires = 600000 * time.Second
	}
	return cfg
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
		SPIC:      sip.RandomUint32(),
		SPIS:      sip.RandomUint32(),
	}
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

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
