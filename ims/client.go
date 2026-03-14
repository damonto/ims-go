package ims

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/damonto/ims-client/usim"
)

type Transport interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	WritePacket(ctx context.Context, data []byte) error
	ReadPacket(ctx context.Context) ([]byte, net.Addr, error)
	Close() error
}

type SecureTCPConfig struct {
	LocalPort    int
	RemotePort   int
	OutboundSPI  uint32
	InboundSPI   uint32
	Integrity    string
	IntegrityKey []byte
}

type SecureUDPConfig = SecureTCPConfig

type Config struct {
	ProxyAddr         string
	Transport         string
	PublicIdentity    string
	HomeDomain        string
	Country           string
	USSDLanguage      string
	UserAgent         string
	AccessNetworkInfo string
	WLANNodeID        string
	RegisterExpires   time.Duration
	SMSC              string
	IMEI              string
	Logger            *slog.Logger
	OnSMS             func(IncomingSMS)
	OnSMSStatusReport func(SMSStatusReport)
	OnUSSD            func(*USSDSession, USSDMessage)
	OnError           func(error)
	DialSecureTCP     func(ctx context.Context, cfg SecureTCPConfig) (Transport, error)
	ListenSecureTCP   func(ctx context.Context, cfg SecureTCPConfig) (Transport, error)
	ListenSecureUDP   func(ctx context.Context, cfg SecureUDPConfig) (Transport, error)
}

type cardProvider interface {
	IMSI() string
	MCC() string
	MNC() string
	SMSC() string
	AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error)
}

type identityProvider interface {
	PrivateIdentity() string
	PublicIdentity() string
	HomeDomain() string
}

const (
	concatSMSRetention  = 10 * time.Minute
	defaultCloseTimeout = 5 * time.Second
	smsSubmitRetention  = 5 * time.Minute
)

var smsSubmitReportTimeoutNanos atomic.Int64

func init() {
	setSMSSubmitReportTimeout(40 * time.Second)
}

func currentSMSSubmitReportTimeout() time.Duration {
	return time.Duration(smsSubmitReportTimeoutNanos.Load())
}

func setSMSSubmitReportTimeout(timeout time.Duration) {
	smsSubmitReportTimeoutNanos.Store(int64(timeout))
}

type concatSMSState struct {
	total     int
	parts     map[int]string
	updatedAt time.Time
}

func newConcatSMSState(total int) concatSMSState {
	return concatSMSState{total: total, parts: make(map[int]string, max(total, 0))}
}

func (state concatSMSState) expired(now time.Time) bool {
	return now.Sub(state.updatedAt) > concatSMSRetention
}

func (state *concatSMSState) reset(total int) {
	*state = newConcatSMSState(total)
}

func (state *concatSMSState) addPart(sequence int, text string, now time.Time) {
	if state.parts == nil {
		state.parts = make(map[int]string, max(state.total, 0))
	}
	state.parts[sequence] = text
	state.updatedAt = now
}

func (state concatSMSState) joinedText() (string, bool) {
	if state.total <= 0 || len(state.parts) < state.total {
		return "", false
	}
	parts := make([]string, state.total)
	for i := 1; i <= state.total; i++ {
		part, ok := state.parts[i]
		if !ok {
			return "", false
		}
		parts[i-1] = part
	}
	return strings.Join(parts, ""), true
}

type clientIdentity struct {
	realm           string
	privateIdentity string
	publicIdentity  string
}

type Client struct {
	cfg                     Config
	transport               Transport
	serverTransport         Transport
	serverDatagramTransport Transport
	card                    cardProvider
	onSMS                   func(IncomingSMS)
	onSMSStatusReport       func(SMSStatusReport)
	onUSSD                  func(*USSDSession, USSDMessage)
	onError                 func(error)
	logger                  *slog.Logger

	privateIdentity   string
	registerURI       string
	contactHost       string
	registerPort      int
	viaHostPort       string
	securityClient    SecurityParam
	securityVerify    *SecurityParam
	securityVerifyRaw string
	serviceRoutes     []string

	callID          string
	sessionID       string
	tag             string
	cseq            int64
	rpRef           uint32
	telPublicID     string
	authIK          []byte
	authNonce       string
	authRealm       string
	authQOP         string
	authNonceCount  uint32
	registerExpires time.Duration

	backgroundCtx    context.Context
	backgroundCancel context.CancelFunc

	mu           sync.Mutex
	sendMu       sync.Mutex
	readWG       sync.WaitGroup
	backgroundWG sync.WaitGroup
	pending      map[string]chan Message
	smsRefs      map[byte]struct{}
	smsPending   map[string]smsPendingEntry
	smsSubmitted map[string]smsSubmittedEntry
	recentSMS    map[string]time.Time
	concatSMS    map[string]concatSMSState
	ussd         map[string]*USSDSession
	registered   bool
	closed       bool
}

type smsPendingEntry struct {
	rpRef     byte
	reportCh  chan rpMessage
	segment   outboundSMSSegment
	response  smsSubmitResponse
	expiresAt time.Time
	async     bool
}

type smsSubmittedEntry struct {
	rpRef     byte
	expiresAt time.Time
	segment   outboundSMSSegment
	response  smsSubmitResponse
	completed bool
}

type smsSubmitResponse struct {
	statusCode   int
	reasonPhrase string
}

func validateNewClientInput(transport Transport, card cardProvider) error {
	if transport == nil {
		return fmt.Errorf("transport is nil")
	}
	if card == nil {
		return fmt.Errorf("card is nil")
	}
	return nil
}

func resolveClientIdentity(cfg Config, card cardProvider) clientIdentity {
	identity := clientIdentity{realm: cfg.HomeDomain, publicIdentity: cfg.PublicIdentity}
	if idp, ok := card.(identityProvider); ok {
		if identity.realm == "" {
			identity.realm = strings.TrimSpace(idp.HomeDomain())
		}
		identity.privateIdentity = strings.TrimSpace(idp.PrivateIdentity())
		if identity.publicIdentity == "" {
			identity.publicIdentity = strings.TrimSpace(idp.PublicIdentity())
		}
	}
	if identity.realm == "" {
		identity.realm = fmt.Sprintf("ims.mnc%s.mcc%s.3gppnetwork.org", card.MNC(), card.MCC())
	}
	if identity.privateIdentity == "" {
		identity.privateIdentity = fmt.Sprintf("%s@%s", card.IMSI(), identity.realm)
	}
	if identity.publicIdentity == "" {
		identity.publicIdentity = "sip:" + identity.privateIdentity
	}
	return identity
}

func resolveClientLocalAddr(transport Transport) (string, int, error) {
	localAddr := transport.LocalAddr()
	if localAddr == nil {
		return "", 0, fmt.Errorf("transport has no local address")
	}
	host, portStr, err := net.SplitHostPort(localAddr.String())
	if err != nil {
		return "", 0, fmt.Errorf("parsing local address %q: %w", localAddr.String(), err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("parsing local port %q: %w", portStr, err)
	}
	return sanitizeHost(host), port, nil
}

func newSecurityClient(registerPort int) SecurityParam {
	clientPort := randomIMSPort()
	serverPort := randomIMSPort()
	for serverPort == clientPort || serverPort == registerPort {
		serverPort = randomIMSPort()
	}
	return SecurityParam{
		Mechanism: "ipsec-3gpp",
		Alg:       "hmac-md5-96",
		EAlg:      "null",
		Mod:       "trans",
		PortC:     clientPort,
		PortS:     serverPort,
		Prot:      "esp",
		SPIC:      randomUint32(),
		SPIS:      randomUint32(),
	}
}

func NewClient(cfg Config, transport Transport, card cardProvider) (*Client, error) {
	if err := validateNewClientInput(transport, card); err != nil {
		return nil, fmt.Errorf("creating IMS client: %w", err)
	}
	var err error
	cfg, err = cfg.Normalized()
	if err != nil {
		return nil, fmt.Errorf("creating IMS client: %w", err)
	}
	identity := resolveClientIdentity(cfg, card)
	cfg.PublicIdentity = identity.publicIdentity
	host, port, err := resolveClientLocalAddr(transport)
	if err != nil {
		return nil, fmt.Errorf("creating IMS client: %w", err)
	}
	callID, sessionID, tag, _ := newTransaction()
	backgroundCtx, backgroundCancel := context.WithCancel(context.Background())
	client := &Client{
		cfg:               cfg,
		transport:         transport,
		card:              card,
		onSMS:             cfg.OnSMS,
		onSMSStatusReport: cfg.OnSMSStatusReport,
		onUSSD:            cfg.OnUSSD,
		onError:           cfg.OnError,
		logger:            cfg.Logger.With("component", "ims"),
		privateIdentity:   identity.privateIdentity,
		registerURI:       "sip:" + identity.realm,
		contactHost:       host,
		registerPort:      port,
		viaHostPort:       net.JoinHostPort(host, strconv.Itoa(port)),
		callID:            callID,
		sessionID:         sessionID,
		tag:               tag,
		pending:           make(map[string]chan Message),
		recentSMS:         make(map[string]time.Time),
		concatSMS:         make(map[string]concatSMSState),
		ussd:              make(map[string]*USSDSession),
		smsRefs:           make(map[byte]struct{}),
		smsPending:        make(map[string]smsPendingEntry),
		smsSubmitted:      make(map[string]smsSubmittedEntry),
		registerExpires:   cfg.RegisterExpires,
		securityClient:    newSecurityClient(port),
		backgroundCtx:     backgroundCtx,
		backgroundCancel:  backgroundCancel,
	}
	client.startBackgroundTask(client.runSMSSubmitCleanup)
	client.logger.Debug("initialized IMS client", "private_identity", identity.privateIdentity, "public_identity", cfg.PublicIdentity, "realm", identity.realm, "transport_protocol", cfg.Transport)
	return client, nil
}

func (c *Client) Register(ctx context.Context) error {
	challengeMsg, err := c.awaitRegisterChallenge(ctx)
	if err != nil {
		return err
	}
	challenge, err := c.applyRegisterChallenge(challengeMsg)
	if err != nil {
		return fmt.Errorf("registering IMS: %w", err)
	}
	initialAuth, err := c.buildRegisterAuthorization(ctx, challenge.Realm, challenge.Nonce, challenge.QOP)
	if err != nil {
		return fmt.Errorf("registering IMS: %w", err)
	}
	if err := c.upgradeSecureTransport(ctx); err != nil {
		return fmt.Errorf("registering IMS: %w", err)
	}
	if err := c.completeRegistration(ctx, challenge, initialAuth); err != nil {
		return err
	}
	return c.Subscribe(ctx)
}

func (c *Client) awaitRegisterChallenge(ctx context.Context) (Message, error) {
	adjustedExpires := false
	for {
		resp, err := c.exchange(ctx, c.buildRegister(nil, nil))
		if err != nil {
			return Message{}, fmt.Errorf("registering IMS: %w", err)
		}
		if resp.StatusCode() == 423 {
			if err := c.adjustRegisterExpiresFrom423("registering IMS", resp, &adjustedExpires); err != nil {
				return Message{}, err
			}
			continue
		}
		if resp.StatusCode() != 401 {
			return Message{}, fmt.Errorf("registering IMS: expected 401, got %d", resp.StatusCode())
		}
		return resp, nil
	}
}

func (c *Client) completeRegistration(ctx context.Context, challenge AuthChallenge, initialAuth *digestAuthorization) error {
	adjustedExpires := false
	auth := initialAuth
	for {
		if auth == nil {
			var err error
			auth, err = c.buildRegisterAuthorization(ctx, challenge.Realm, challenge.Nonce, challenge.QOP)
			if err != nil {
				return fmt.Errorf("registering IMS: %w", err)
			}
		}
		resp, err := c.exchange(ctx, c.buildRegister(auth, c.currentSecurityVerify()))
		if err != nil {
			return fmt.Errorf("registering IMS: %w", err)
		}
		if resp.StatusCode() == 423 {
			if err := c.adjustRegisterExpiresFrom423("registering IMS", resp, &adjustedExpires); err != nil {
				return err
			}
			auth = nil
			continue
		}
		if resp.StatusCode() != 200 {
			return fmt.Errorf("registering IMS: expected 200, got %d", resp.StatusCode())
		}
		c.applyRegisterSuccess(resp)
		return nil
	}
}

func (c *Client) applyAssociatedURI(msg Message) {
	updated := false
	for _, value := range msg.HeadersByName("P-Associated-URI") {
		trimmed := strings.TrimSpace(value)
		trimmed = strings.TrimPrefix(trimmed, "<")
		trimmed = strings.TrimSuffix(trimmed, ">")
		if strings.HasPrefix(strings.ToLower(trimmed), "tel:") {
			c.telPublicID = trimmed
			c.logger.Debug("updated associated tel identity", "public_identity", trimmed)
			updated = true
			continue
		}
		if !strings.HasPrefix(strings.ToLower(trimmed), "sip:") {
			continue
		}
		c.cfg.PublicIdentity = trimmed
		c.logger.Debug("updated associated public identity", "public_identity", trimmed)
		updated = true
	}
	if updated {
		return
	}
}

func (c *Client) applyServiceRoutes(msg Message) {
	routes := msg.HeadersByName("Service-Route")
	if len(routes) == 0 {
		return
	}
	c.serviceRoutes = append(c.serviceRoutes[:0], routes...)
	c.logger.Debug("stored service routes", "route_count", len(c.serviceRoutes), "routes", c.serviceRoutes)
}

func (c *Client) currentRegisterExpires() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.registerExpires > 0 {
		return c.registerExpires
	}
	return c.cfg.RegisterExpires
}

func (c *Client) setRegisterExpires(expires time.Duration) {
	if expires <= 0 {
		return
	}
	c.mu.Lock()
	c.registerExpires = expires
	c.mu.Unlock()
}

func (c *Client) registerExpiresSeconds() int {
	seconds := int(c.currentRegisterExpires() / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

func (c *Client) refreshInterval() time.Duration {
	interval := c.currentRegisterExpires() / 2
	if interval < time.Second {
		return time.Second
	}
	return interval
}

func (c *Client) maybeAddAccessNetworkInfo(msg *Message) {
	c.addAccessNetworkInfo(msg)
}

func (c *Client) currentSecurityVerify() *SecurityParam {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.securityVerify == nil {
		return nil
	}
	param := *c.securityVerify
	return &param
}

func (c *Client) securityVerifyValue(verify *SecurityParam) string {
	if verify == nil {
		return ""
	}
	c.mu.Lock()
	raw := c.securityVerifyRaw
	c.mu.Unlock()
	if raw != "" {
		return raw
	}
	return verify.String()
}

func (c *Client) addSecurityVerifyHeader(msg *Message, verify *SecurityParam) bool {
	if verify == nil {
		return false
	}
	msg.AddHeader("Security-Verify", c.securityVerifyValue(verify))
	return true
}

func normalizeIntegrityAlg(alg string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(alg)) {
	case "hmac-md5-96":
		return "hmac-md5-96", true
	case "hmac-sha-1-96", "hmac-sha1-96":
		return "hmac-sha1-96", true
	case "hmac-sha-256-128", "hmac-sha256-128":
		return "hmac-sha256-128", true
	default:
		return "", false
	}
}

func normalizeSecurityParam(param SecurityParam) (SecurityParam, bool) {
	if !strings.EqualFold(param.Mechanism, "ipsec-3gpp") {
		return SecurityParam{}, false
	}
	if param.Mod == "" {
		param.Mod = "trans"
	}
	if param.Prot == "" {
		param.Prot = "esp"
	}
	if !strings.EqualFold(param.EAlg, "null") || !strings.EqualFold(param.Mod, "trans") || !strings.EqualFold(param.Prot, "esp") {
		return SecurityParam{}, false
	}
	alg, ok := normalizeIntegrityAlg(param.Alg)
	if !ok || param.PortC == 0 || param.PortS == 0 || param.SPIC == 0 || param.SPIS == 0 {
		return SecurityParam{}, false
	}
	param.Alg = alg
	return param, true
}

func (c *Client) applySecurityServer(headerValue string) error {
	headerValue = strings.TrimSpace(headerValue)
	if headerValue == "" {
		return fmt.Errorf("applying Security-Server: header is empty")
	}
	var params SecurityParams
	if err := params.UnmarshalText([]byte(headerValue)); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.securityVerifyRaw = ""
	c.securityVerify = nil
	for _, param := range params {
		if normalized, ok := normalizeSecurityParam(param); ok {
			paramCopy := normalized
			c.securityVerifyRaw = headerValue
			c.securityVerify = &paramCopy
			return nil
		}
	}
	return fmt.Errorf("applying Security-Server: no compatible ipsec-3gpp security mechanism")
}

func (c *Client) applyAuthenticationInfo(msg Message) {
	var info AuthInfo
	if err := info.UnmarshalText([]byte(msg.Header("Authentication-Info"))); err != nil || info.NextNonce == "" {
		return
	}
	c.mu.Lock()
	c.authNonce = info.NextNonce
	c.authNonceCount = 0
	c.mu.Unlock()
}

func (c *Client) applyRegisterExpires(msg Message) {
	headerValue := strings.TrimSpace(msg.Header("Expires"))
	if headerValue == "" {
		return
	}
	seconds, err := strconv.Atoi(headerValue)
	if err != nil || seconds <= 0 {
		return
	}
	c.setRegisterExpires(time.Duration(seconds) * time.Second)
}

func (c *Client) applyRegisterSuccess(msg Message) {
	c.applyAssociatedURI(msg)
	c.applyServiceRoutes(msg)
	c.applyAuthenticationInfo(msg)
	c.applyRegisterExpires(msg)
	c.setRegistered(true)
}

func (c *Client) storeAuthChallenge(challenge AuthChallenge) {
	realm := strings.TrimSpace(challenge.Realm)
	if realm == "" {
		realm = strings.TrimPrefix(c.registerURI, "sip:")
	}
	c.mu.Lock()
	c.authRealm = realm
	c.authNonce = challenge.Nonce
	c.authQOP = challenge.QOP
	c.authNonceCount = 0
	c.mu.Unlock()
}

func (c *Client) currentAuthState() (string, string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	realm := c.authRealm
	if realm == "" {
		realm = strings.TrimPrefix(c.registerURI, "sip:")
	}
	return realm, c.authNonce, c.authQOP
}

func (c *Client) nextAuthNonceCount() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authNonceCount++
	return fmt.Sprintf("%08x", c.authNonceCount)
}

func (c *Client) setRegistered(registered bool) {
	c.mu.Lock()
	c.registered = registered
	c.mu.Unlock()
}

func (c *Client) isRegistered() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.registered
}

func (c *Client) computeAKAResponseWithKeys(ctx context.Context, realm, nonce, challengeQOP string) (*digestAuthorization, []byte, error) {
	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding auth nonce: %w", err)
	}
	if len(nonceBytes) < 32 {
		return nil, nil, fmt.Errorf("decoding auth nonce: expected at least 32 bytes")
	}
	aka, err := c.card.AKA(ctx, nonceBytes[:16], nonceBytes[16:32])
	if err != nil {
		return nil, nil, fmt.Errorf("calculating AKA response: %w", err)
	}
	if strings.TrimSpace(realm) == "" {
		realm = strings.TrimPrefix(c.registerURI, "sip:")
	}
	auth := &digestAuthorization{
		Nonce:    nonce,
		URI:      c.registerURI,
		Username: c.privateIdentity,
		Realm:    realm,
	}
	qop, err := (AuthChallenge{QOP: challengeQOP}).SelectedQOP()
	if err != nil {
		return nil, nil, err
	}
	if qop != "" {
		auth.QOP = qop
		auth.NonceCount = c.nextAuthNonceCount()
		auth.CNonce = randomHex(16)
	}
	response, err := computeAKAResponse(c.privateIdentity, realm, c.registerURI, nonce, aka, auth.QOP, auth.CNonce, auth.NonceCount)
	if err != nil {
		return nil, nil, err
	}
	auth.Response = response
	return auth, append([]byte(nil), aka.IK...), nil
}

func (c *Client) buildRegisterAuthorization(ctx context.Context, realm, nonce, qop string) (*digestAuthorization, error) {
	if nonce == "" {
		return nil, nil
	}
	auth, authIK, err := c.computeAKAResponseWithKeys(ctx, realm, nonce, qop)
	if err != nil {
		return nil, err
	}
	if len(authIK) != 0 {
		c.authIK = authIK
	}
	return auth, nil
}

func isProvisionalResponse(msg Message) bool {
	status := msg.StatusCode()
	return status >= 100 && status < 200
}

func (c *Client) logSIPMessage(direction string, msg Message) {
	c.logger.Debug("sip message", "direction", direction, "start_line", msg.StartLine, "sip_message", string(msg.Bytes()))
}

func (c *Client) writeRequest(ctx context.Context, transport Transport, req Message) error {
	c.logSIPMessage("send", req)
	if err := c.writePacket(ctx, transport, req.Bytes()); err != nil {
		return fmt.Errorf("sending %s: %w", req.Method(), err)
	}
	return nil
}

func awaitPendingFinalResponse(ctx context.Context, respCh <-chan Message) (Message, error) {
	for {
		select {
		case <-ctx.Done():
			return Message{}, ctx.Err()
		case resp := <-respCh:
			if isProvisionalResponse(resp) {
				continue
			}
			return resp, nil
		}
	}
}

func (c *Client) readFinalTransportResponse(ctx context.Context, transport Transport) (Message, error) {
	for {
		inbound, err := readTransportMessage(ctx, transport)
		if err != nil {
			return Message{}, err
		}
		if inbound.msg.IsRequest() {
			continue
		}
		c.logSIPMessage("recv", inbound.msg)
		if isProvisionalResponse(inbound.msg) {
			continue
		}
		return inbound.msg, nil
	}
}

func (c *Client) sendPending(ctx context.Context, req Message) (Message, error) {
	respCh := c.registerPending(req)
	defer c.removePending(req)
	if err := c.writeRequest(ctx, c.transport, req); err != nil {
		return Message{}, err
	}
	return awaitPendingFinalResponse(ctx, respCh)
}

type refreshRegisterState struct {
	adjustedExpires bool
	challenged      bool
	restarted       bool
}

func (c *Client) applyRegisterChallenge(resp Message) (AuthChallenge, error) {
	var challenge AuthChallenge
	err := challenge.UnmarshalText([]byte(resp.Header("WWW-Authenticate")))
	if err != nil {
		return AuthChallenge{}, err
	}
	if _, err := challenge.SelectedQOP(); err != nil {
		return AuthChallenge{}, err
	}
	if err := c.applySecurityServer(resp.Header("Security-Server")); err != nil {
		return AuthChallenge{}, err
	}
	c.storeAuthChallenge(challenge)
	return challenge, nil
}

func (c *Client) adjustRegisterExpiresFrom423(action string, resp Message, adjusted *bool) error {
	if *adjusted {
		return fmt.Errorf("%s: repeated 423 response", action)
	}
	minExpires, err := minExpiresSeconds(resp.Header("Min-Expires"))
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	c.setRegisterExpires(max(c.currentRegisterExpires(), time.Duration(minExpires)*time.Second))
	*adjusted = true
	return nil
}

func (c *Client) registerAuthorization(ctx context.Context, realm, nonce, qop string) (*digestAuthorization, error) {
	return c.buildRegisterAuthorization(ctx, realm, nonce, qop)
}

func (c *Client) buildRefreshRegister(ctx context.Context) (Message, error) {
	realm, nonce, qop := c.currentAuthState()
	auth, err := c.registerAuthorization(ctx, realm, nonce, qop)
	if err != nil {
		return Message{}, err
	}
	return c.buildRegister(auth, c.currentSecurityVerify()), nil
}

func (c *Client) handleRefreshRegistration(resp Message, state *refreshRegisterState) (bool, error) {
	switch resp.StatusCode() {
	case 200:
		c.applyRegisterSuccess(resp)
		return true, nil
	case 401:
		if state.challenged {
			return false, fmt.Errorf("refreshing IMS registration: repeated 401 response")
		}
		if _, err := c.applyRegisterChallenge(resp); err != nil {
			return false, fmt.Errorf("refreshing IMS registration: %w", err)
		}
		state.challenged = true
		return false, nil
	case 423:
		if err := c.adjustRegisterExpiresFrom423("refreshing IMS registration", resp, &state.adjustedExpires); err != nil {
			return false, err
		}
		return false, nil
	case 403, 408, 500, 504:
		if state.restarted {
			return false, fmt.Errorf("refreshing IMS registration: repeated restart status %d", resp.StatusCode())
		}
		c.resetAuthStateForRefresh()
		state.challenged = false
		state.adjustedExpires = false
		state.restarted = true
		return false, nil
	default:
		return false, fmt.Errorf("refreshing IMS registration: unexpected status %d", resp.StatusCode())
	}
}

func (c *Client) resetAuthStateForRefresh() {
	c.mu.Lock()
	c.authNonce = ""
	c.authRealm = strings.TrimPrefix(c.registerURI, "sip:")
	c.authQOP = ""
	c.authNonceCount = 0
	c.mu.Unlock()
}

func (c *Client) refreshRegistration(ctx context.Context) error {
	state := refreshRegisterState{}
	for range 6 {
		req, err := c.buildRefreshRegister(ctx)
		if err != nil {
			return err
		}
		resp, err := c.sendPending(ctx, req)
		if err != nil {
			return fmt.Errorf("refreshing IMS registration: %w", err)
		}
		done, err := c.handleRefreshRegistration(resp, &state)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return errors.New("refreshing IMS registration: exhausted retries")
}

func (c *Client) deregister(ctx context.Context) error {
	if !c.isRegistered() {
		return nil
	}
	verify := c.currentSecurityVerify()
	realm, nonce, qop := c.currentAuthState()
	challenged := false
	for range 2 {
		req, err := c.buildDeregisterMessage(ctx, verify, realm, nonce, qop)
		if err != nil {
			return err
		}
		resp, err := c.exchange(ctx, req)
		if err != nil {
			return fmt.Errorf("deregistering IMS: %w", err)
		}
		done, err := c.handleDeregisterResponse(resp, &challenged, &realm, &nonce, &qop)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return errors.New("deregistering IMS: exhausted retries")
}

func (c *Client) buildDeregisterMessage(ctx context.Context, verify *SecurityParam, realm, nonce, qop string) (Message, error) {
	auth, err := c.registerAuthorization(ctx, realm, nonce, qop)
	if err != nil {
		return Message{}, fmt.Errorf("deregistering IMS: %w", err)
	}
	return c.buildDeregister(auth, verify), nil
}

func (c *Client) handleDeregisterResponse(resp Message, challenged *bool, realm, nonce, qop *string) (bool, error) {
	switch resp.StatusCode() {
	case 200:
		return true, nil
	case 401:
		if *challenged {
			return false, fmt.Errorf("deregistering IMS: repeated 401 response")
		}
		var challenge AuthChallenge
		err := challenge.UnmarshalText([]byte(resp.Header("WWW-Authenticate")))
		if err != nil {
			return false, fmt.Errorf("deregistering IMS: %w", err)
		}
		if _, err := challenge.SelectedQOP(); err != nil {
			return false, fmt.Errorf("deregistering IMS: %w", err)
		}
		c.storeAuthChallenge(challenge)
		*realm = challenge.Realm
		*nonce = challenge.Nonce
		*qop = challenge.QOP
		*challenged = true
		return false, nil
	default:
		return false, fmt.Errorf("deregistering IMS: unexpected status %d", resp.StatusCode())
	}
}

func (c *Client) reserveSMSReference() (byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for range 256 {
		ref := byte(atomic.AddUint32(&c.rpRef, 1))
		if _, exists := c.smsRefs[ref]; exists {
			continue
		}
		c.smsRefs[ref] = struct{}{}
		return ref, nil
	}
	return 0, errors.New("sending SMS: no free RP reference")
}

func (c *Client) releaseSMSReference(ref byte) {
	c.mu.Lock()
	delete(c.smsRefs, ref)
	c.mu.Unlock()
}

func (c *Client) registerSMSPending(callID string, rpRef byte) (<-chan rpMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if callID == "" {
		return nil, errors.New("sending SMS: call id is empty")
	}
	if _, exists := c.smsPending[callID]; exists {
		return nil, fmt.Errorf("sending SMS: duplicate Call-ID %q", callID)
	}
	ch := make(chan rpMessage, 1)
	c.smsPending[callID] = smsPendingEntry{rpRef: rpRef, reportCh: ch}
	return ch, nil
}

func (c *Client) removeSMSPending(callID string) {
	c.mu.Lock()
	delete(c.smsPending, callID)
	c.mu.Unlock()
}

func (c *Client) markSMSSubmitted(segment outboundSMSSegment, response smsSubmitResponse, now time.Time) {
	if segment.callID == "" {
		return
	}
	c.mu.Lock()
	c.smsSubmitted[segment.callID] = smsSubmittedEntry{
		rpRef:     segment.rpRef,
		expiresAt: now.Add(smsSubmitRetention),
		segment:   segment,
		response:  response,
	}
	c.mu.Unlock()
}

func (c *Client) completeSMSSubmitted(callID string) {
	if callID == "" {
		return
	}
	c.mu.Lock()
	entry, ok := c.smsSubmitted[callID]
	if ok {
		entry.segment = outboundSMSSegment{}
		entry.response = smsSubmitResponse{}
		entry.completed = true
		c.smsSubmitted[callID] = entry
	}
	c.mu.Unlock()
}

func smsSubmitSweepInterval() time.Duration {
	interval := currentSMSSubmitReportTimeout() / 4
	if interval < 10*time.Millisecond {
		return 10 * time.Millisecond
	}
	if interval > time.Second {
		return time.Second
	}
	return interval
}

func (c *Client) runSMSSubmitCleanup() {
	baseCtx := c.backgroundCtx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	timer := time.NewTimer(smsSubmitSweepInterval())
	defer timer.Stop()

	for {
		select {
		case <-baseCtx.Done():
			return
		case <-timer.C:
			c.expireSMSSubmitState(time.Now())
			timer.Reset(smsSubmitSweepInterval())
		}
	}
}

func (c *Client) expireSMSSubmitState(now time.Time) {
	var expired []smsPendingEntry

	c.mu.Lock()
	for callID, entry := range c.smsSubmitted {
		if !entry.expiresAt.After(now) {
			delete(c.smsSubmitted, callID)
		}
	}
	for callID, entry := range c.smsPending {
		if !entry.async || entry.expiresAt.IsZero() || entry.expiresAt.After(now) {
			continue
		}
		delete(c.smsPending, callID)
		expired = append(expired, entry)
	}
	c.mu.Unlock()

	for _, entry := range expired {
		c.logger.Debug("submit report not received", "to", entry.segment.to, "smsc", entry.segment.smsc, "call_id", entry.segment.msg.Header("Call-ID"), "cseq", entry.segment.msg.Header("CSeq"), "rp_ref", entry.segment.rpRef, "status_code", entry.response.statusCode)
	}
}

func smsSubmitResponseFromMessage(resp Message) smsSubmitResponse {
	statusCode := resp.StatusCode()
	return smsSubmitResponse{
		statusCode:   statusCode,
		reasonPhrase: strings.TrimSpace(strings.TrimPrefix(resp.StartLine, fmt.Sprintf("SIP/2.0 %d", statusCode))),
	}
}

func (c *Client) activateSMSPendingAsync(segment outboundSMSSegment, response smsSubmitResponse, now time.Time) (rpMessage, bool) {
	c.mu.Lock()
	entry, ok := c.smsPending[segment.callID]
	if !ok {
		c.mu.Unlock()
		return rpMessage{}, false
	}
	entry.segment = segment
	entry.response = response
	entry.expiresAt = now.Add(currentSMSSubmitReportTimeout())
	entry.async = true
	c.smsPending[segment.callID] = entry
	select {
	case report := <-entry.reportCh:
		delete(c.smsPending, segment.callID)
		c.mu.Unlock()
		return report, true
	default:
		c.mu.Unlock()
		return rpMessage{}, false
	}
}

func (c *Client) completeSMSPending(msg Message, report rpMessage) bool {
	callID := strings.TrimSpace(msg.Header("In-Reply-To"))
	if callID == "" {
		c.logger.Debug("submit report missing In-Reply-To", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", report.Reference)
		return false
	}
	now := time.Now()
	c.mu.Lock()
	entry, ok := c.smsPending[callID]
	if ok {
		if entry.rpRef != report.Reference {
			c.mu.Unlock()
			c.handleUnexpectedSMSSubmitReference(msg, report, entry.rpRef)
			return true
		}
		if entry.async {
			delete(c.smsPending, callID)
			c.mu.Unlock()
			if err := c.handleSMSSegmentReport(entry.segment, entry.response, report); err != nil {
				c.logger.Warn("submit report", "to", entry.segment.to, "smsc", entry.segment.smsc, "call_id", entry.segment.msg.Header("Call-ID"), "cseq", entry.segment.msg.Header("CSeq"), "rp_ref", entry.segment.rpRef, "err", err)
				c.emitAsyncError(err)
			}
			c.completeSMSSubmitted(callID)
			return true
		}
		select {
		case entry.reportCh <- report:
		default:
		}
		c.mu.Unlock()
		return true
	}

	submitted, ok := c.smsSubmitted[callID]
	if ok && !submitted.expiresAt.After(now) {
		delete(c.smsSubmitted, callID)
		ok = false
	}
	c.mu.Unlock()
	if ok {
		if submitted.rpRef != report.Reference {
			c.handleUnexpectedSMSSubmitReference(msg, report, submitted.rpRef)
			return true
		}
		if submitted.completed {
			return true
		}
		if err := c.handleSMSSegmentReport(submitted.segment, submitted.response, report); err != nil {
			c.logger.Warn("submit report", "to", submitted.segment.to, "smsc", submitted.segment.smsc, "call_id", submitted.segment.msg.Header("Call-ID"), "cseq", submitted.segment.msg.Header("CSeq"), "rp_ref", submitted.segment.rpRef, "err", err)
			c.emitAsyncError(err)
		}
		c.completeSMSSubmitted(callID)
		return true
	}
	c.logger.Debug("submit report not matched", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", callID, "rp_ref", report.Reference)
	return false
}

func (c *Client) handleUnexpectedSMSSubmitReference(msg Message, report rpMessage, expected byte) {
	c.logger.Debug("submit report reference mismatch", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", msg.Header("In-Reply-To"), "rp_ref", report.Reference, "expected_rp_ref", expected)
	if report.Type == rpAckNetworkToMS {
		c.sendInboundSMSDeliveryReport(msg, newRPErrorMessage(report.Reference, rpCauseInvalidShortMessageTransferReference))
	}
}

func (c *Client) knowsSMSSubmit(callID string, now time.Time) bool {
	if callID == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.smsPending[callID]; ok {
		return true
	}
	submitted, ok := c.smsSubmitted[callID]
	if !ok {
		return false
	}
	if !submitted.expiresAt.After(now) {
		delete(c.smsSubmitted, callID)
		return false
	}
	return true
}

func malformedNetworkSMSSubmitReport(body []byte) (rpMessage, bool) {
	if len(body) < 2 {
		return rpMessage{}, false
	}
	switch body[0] {
	case rpAckNetworkToMS:
		return rpMessage{Type: rpAckNetworkToMS, Reference: body[1]}, true
	case rpErrorNetworkToMS:
		return rpMessage{Type: rpErrorNetworkToMS, Reference: body[1], Cause: rpCauseProtocolErrorUnspecified, HasCause: true}, true
	default:
		return rpMessage{}, false
	}
}

func (c *Client) smsReportTarget(msg Message) string {
	for _, candidate := range []string{
		addressURI(msg.Header("P-Asserted-Identity")),
		addressURI(msg.Header("From")),
	} {
		if target := sipMessageTarget(candidate); target != "" {
			return target
		}
	}
	return viaMessageTarget(msg)
}

func sipMessageTarget(uri string) string {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return ""
	}
	lower := strings.ToLower(uri)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") {
		return uri
	}
	return ""
}

func viaMessageTarget(msg Message) string {
	var last string
	for _, value := range msg.HeadersByName("Via") {
		for part := range strings.SplitSeq(value, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				last = trimmed
			}
		}
	}
	if last == "" {
		return ""
	}
	fields := strings.Fields(last)
	if len(fields) < 2 {
		return ""
	}
	sentBy, _, _ := strings.Cut(fields[1], ";")
	sentBy = strings.TrimSpace(sentBy)
	if sentBy == "" {
		return ""
	}
	return "sip:" + sentBy
}

func (c *Client) upgradeSecureTransport(ctx context.Context) error {
	verify := c.currentSecurityVerify()
	if !c.shouldUpgradeSecureTransport(verify) {
		return nil
	}
	if err := c.transport.Close(); err != nil {
		return fmt.Errorf("closing initial IMS transport: %w", err)
	}
	secureTransport, err := c.cfg.DialSecureTCP(ctx, c.secureTransportConfig(verify, c.securityClient.PortC, verify.PortS, verify.SPIS, c.securityClient.SPIC))
	if err != nil {
		return fmt.Errorf("dialing secure IMS transport: %w", err)
	}
	c.transport = secureTransport
	if err := c.startSecureServerTransports(ctx, verify); err != nil {
		return err
	}
	c.logger.Debug("upgraded IMS transport", "local_addr", secureTransport.LocalAddr(), "remote_addr", secureTransport.RemoteAddr(), "advertised_server_port", c.securityClient.PortS)
	return nil
}

func (c *Client) shouldUpgradeSecureTransport(verify *SecurityParam) bool {
	return strings.EqualFold(c.cfg.Transport, "tcp") && verify != nil && c.cfg.DialSecureTCP != nil
}

func (c *Client) secureTransportConfig(verify *SecurityParam, localPort, remotePort int, outboundSPI, inboundSPI uint32) SecureTCPConfig {
	return SecureTCPConfig{
		LocalPort:    localPort,
		RemotePort:   remotePort,
		OutboundSPI:  outboundSPI,
		InboundSPI:   inboundSPI,
		Integrity:    verify.Alg,
		IntegrityKey: append([]byte(nil), c.authIK...),
	}
}

func (c *Client) startSecureServerTransports(ctx context.Context, verify *SecurityParam) error {
	if c.cfg.ListenSecureTCP != nil {
		serverTransport, err := c.cfg.ListenSecureTCP(ctx, c.secureTransportConfig(verify, c.securityClient.PortS, verify.PortC, verify.SPIC, c.securityClient.SPIS))
		if err != nil {
			return fmt.Errorf("listening secure IMS transport: %w", err)
		}
		c.serverTransport = serverTransport
	}
	if c.cfg.ListenSecureUDP != nil {
		serverDatagramTransport, err := c.cfg.ListenSecureUDP(ctx, c.secureTransportConfig(verify, c.securityClient.PortS, verify.PortC, verify.SPIC, c.securityClient.SPIS))
		if err != nil {
			return fmt.Errorf("listening secure IMS datagram transport: %w", err)
		}
		c.serverDatagramTransport = serverDatagramTransport
	}
	return nil
}

func (c *Client) Subscribe(ctx context.Context) error {
	msg := c.buildSubscribe()
	resp, err := c.exchange(ctx, msg)
	if err != nil {
		return fmt.Errorf("subscribing IMS registration: %w", err)
	}
	if resp.StatusCode() != 200 {
		return fmt.Errorf("subscribing IMS registration: expected 200, got %d", resp.StatusCode())
	}
	return nil
}

func (c *Client) Run(ctx context.Context) error {
	refresh := time.NewTimer(c.refreshInterval())
	defer refresh.Stop()
	inboundCh := make(chan inboundMessage, 16)
	c.startReadLoops(ctx, inboundCh)
	var refreshCh <-chan error
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-refresh.C:
			refreshCh = c.startRefresh(ctx, refreshCh)
		case err := <-refreshCh:
			refreshCh = nil
			if err := c.finishRefresh(refresh, err); err != nil {
				return err
			}
		case inbound := <-inboundCh:
			if err := c.handleRunInbound(ctx, inbound); err != nil {
				return err
			}
		}
	}
}

func (c *Client) closeTransport(transport Transport) error {
	if transport == nil {
		return nil
	}
	return transport.Close()
}

func (c *Client) startBackgroundTask(task func()) bool {
	done, ok := c.reserveBackgroundTask()
	if !ok {
		return false
	}
	go func() {
		defer done()
		task()
	}()
	return true
}

func (c *Client) reserveBackgroundTask() (func(), bool) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, false
	}
	c.backgroundWG.Add(1)
	c.mu.Unlock()
	return func() {
		c.backgroundWG.Done()
	}, true
}

func (c *Client) startReadLoops(ctx context.Context, inboundCh chan<- inboundMessage) {
	c.readWG.Add(1)
	go func() {
		defer c.readWG.Done()
		c.readTransport(ctx, c.transport, inboundCh)
	}()
	if c.serverTransport != nil {
		c.readWG.Add(1)
		go func() {
			defer c.readWG.Done()
			c.readTransport(ctx, c.serverTransport, inboundCh)
		}()
	}
	if c.serverDatagramTransport != nil {
		c.readWG.Add(1)
		go func() {
			defer c.readWG.Done()
			c.readTransport(ctx, c.serverDatagramTransport, inboundCh)
		}()
	}
}

func (c *Client) startRefresh(ctx context.Context, refreshCh <-chan error) <-chan error {
	if refreshCh != nil {
		return refreshCh
	}
	done := make(chan error, 1)
	go func() {
		done <- c.refreshRegistration(ctx)
	}()
	return done
}

func (c *Client) finishRefresh(refresh *time.Timer, err error) error {
	if err != nil {
		return err
	}
	refresh.Reset(c.refreshInterval())
	return nil
}

func (c *Client) handleRunInbound(ctx context.Context, inbound inboundMessage) error {
	if inbound.err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return inbound.err
	}
	if inbound.msg.IsRequest() {
		return c.handleRunRequest(ctx, inbound)
	}
	c.logSIPMessage("recv", inbound.msg)
	c.dispatchResponse(inbound.msg)
	return nil
}

func (c *Client) handleRunRequest(ctx context.Context, inbound inboundMessage) error {
	msg := inbound.msg
	c.logSIPMessage("recv", msg)
	return c.handleRequest(ctx, inbound.transport, msg)
}

type inboundMessage struct {
	msg       Message
	transport Transport
	err       error
}

func readTransportMessage(ctx context.Context, transport Transport) (inboundMessage, error) {
	packet, _, err := transport.ReadPacket(ctx)
	if err != nil {
		return inboundMessage{}, err
	}
	msg, err := ParseMessage(packet)
	if err != nil {
		return inboundMessage{}, err
	}
	return inboundMessage{msg: msg, transport: transport}, nil
}

func sendInboundMessage(ctx context.Context, out chan<- inboundMessage, inbound inboundMessage) bool {
	select {
	case out <- inbound:
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *Client) readTransport(ctx context.Context, transport Transport, out chan<- inboundMessage) {
	for {
		inbound, err := readTransportMessage(ctx, transport)
		if err != nil {
			_ = sendInboundMessage(ctx, out, inboundMessage{err: err})
			return
		}
		if !sendInboundMessage(ctx, out, inbound) {
			return
		}
	}
}

type outboundSMSSegment struct {
	index    int
	count    int
	to       string
	smsc     string
	rpRef    byte
	tpRef    byte
	callID   string
	msg      Message
	reportCh <-chan rpMessage
}

func (c *Client) SendSMS(ctx context.Context, to, text string) error {
	smsc, err := c.resolveSMSC()
	if err != nil {
		return err
	}
	parts, err := buildSMSUserDataParts(text)
	if err != nil {
		return err
	}
	for i, part := range parts {
		segment, err := c.newOutboundSMSSegment(to, smsc, part, i, len(parts))
		if err != nil {
			return err
		}
		if err := c.sendSMSSegment(ctx, segment); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) resolveSMSC() (string, error) {
	smsc := c.cfg.SMSC
	if smsc == "" {
		smsc = c.card.SMSC()
	}
	if smsc == "" {
		return "", fmt.Errorf("sending SMS: SMSC is empty")
	}
	return smsc, nil
}

func (c *Client) newOutboundSMSSegment(to, smsc string, part smsUserDataPart, index, count int) (outboundSMSSegment, error) {
	rpRef, err := c.reserveSMSReference()
	if err != nil {
		return outboundSMSSegment{}, err
	}
	tpRef := rpRef
	tpdu, err := newSMSSubmitTPDU(tpRef, to, part).MarshalBinary()
	if err != nil {
		c.releaseSMSReference(rpRef)
		return outboundSMSSegment{}, fmt.Errorf("sending SMS: %w", err)
	}
	rpdu, err := newRPDataMessage(rpRef, smsc, tpdu).MarshalBinary()
	if err != nil {
		c.releaseSMSReference(rpRef)
		return outboundSMSSegment{}, fmt.Errorf("sending SMS: %w", err)
	}
	msg := c.buildMessage("tel:"+smsc, rpdu, "")
	callID := msg.Header("Call-ID")
	reportCh, err := c.registerSMSPending(callID, rpRef)
	if err != nil {
		c.releaseSMSReference(rpRef)
		return outboundSMSSegment{}, err
	}
	return outboundSMSSegment{
		index:    index,
		count:    count,
		to:       to,
		smsc:     smsc,
		rpRef:    rpRef,
		tpRef:    tpRef,
		callID:   callID,
		msg:      msg,
		reportCh: reportCh,
	}, nil
}

func (c *Client) sendSMSSegment(ctx context.Context, segment outboundSMSSegment) error {
	resp, err := c.sendPending(ctx, segment.msg)
	if err != nil {
		c.removeSMSPending(segment.callID)
		c.releaseSMSReference(segment.rpRef)
		return err
	}
	if status := resp.StatusCode(); status != 200 && status != 202 {
		c.removeSMSPending(segment.callID)
		c.releaseSMSReference(segment.rpRef)
		return fmt.Errorf("sending SMS: unexpected status %d (%s)", status, strings.TrimSpace(resp.StartLine))
	}
	return c.trackSMSSegmentReport(segment, smsSubmitResponseFromMessage(resp))
}

func (c *Client) trackSMSSegmentReport(segment outboundSMSSegment, response smsSubmitResponse) error {
	c.markSMSSubmitted(segment, response, time.Now())
	select {
	case report := <-segment.reportCh:
		c.removeSMSPending(segment.callID)
		c.releaseSMSReference(segment.rpRef)
		err := c.handleSMSSegmentReport(segment, response, report)
		c.completeSMSSubmitted(segment.callID)
		return err
	default:
	}
	c.releaseSMSReference(segment.rpRef)
	if report, ok := c.activateSMSPendingAsync(segment, response, time.Now()); ok {
		err := c.handleSMSSegmentReport(segment, response, report)
		c.completeSMSSubmitted(segment.callID)
		return err
	}
	return nil
}

func (c *Client) handleSMSSegmentReport(segment outboundSMSSegment, response smsSubmitResponse, report rpMessage) error {
	if report.Reference != segment.rpRef {
		return fmt.Errorf("sending SMS segment %d/%d: unexpected rp reference %d", segment.index+1, segment.count, report.Reference)
	}
	switch report.Type {
	case rpAckNetworkToMS:
		c.logger.Debug("sms segment accepted", "segment_index", segment.index+1, "segment_count", segment.count, "to", segment.to, "smsc", segment.smsc, "call_id", segment.msg.Header("Call-ID"), "cseq", segment.msg.Header("CSeq"), "rp_ref", segment.rpRef, "tp_ref", segment.tpRef, "status_code", response.statusCode, "reason_phrase", response.reasonPhrase)
		return nil
	case rpErrorNetworkToMS:
		return fmt.Errorf("sending SMS segment %d/%d: %w", segment.index+1, segment.count, &RPError{Cause: report.Cause})
	default:
		return fmt.Errorf("sending SMS segment %d/%d: unexpected rp type 0x%02X", segment.index+1, segment.count, report.Type)
	}
}

func (c *Client) emitAsyncError(err error) {
	if err == nil || c.onError == nil {
		return
	}
	c.onError(err)
}

func (c *Client) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultCloseTimeout)
	defer cancel()
	return c.CloseContext(ctx)
}

func (c *Client) CloseContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	defer c.setRegistered(false)
	if c.backgroundCancel != nil {
		c.backgroundCancel()
	}

	err := errors.Join(c.closeUSSDSessions(ctx), c.deregister(ctx))
	err = errors.Join(err, c.closeTransport(c.transport), c.closeTransport(c.serverTransport), c.closeTransport(c.serverDatagramTransport))
	c.backgroundWG.Wait()
	c.readWG.Wait()
	return err
}

func (c *Client) exchange(ctx context.Context, req Message) (Message, error) {
	if err := c.writeRequest(ctx, c.transport, req); err != nil {
		return Message{}, err
	}
	resp, err := c.readFinalTransportResponse(ctx, c.transport)
	if err != nil {
		return Message{}, fmt.Errorf("receiving %s response: %w", req.Method(), err)
	}
	return resp, nil
}

func (c *Client) handleRequest(ctx context.Context, transport Transport, msg Message) error {
	if strings.EqualFold(msg.Method(), "NOTIFY") {
		return c.writeStatus(ctx, transport, msg, 200, "OK")
	}
	if handled, err := c.handleUSSDRequest(ctx, transport, msg); handled || err != nil {
		return err
	}
	if strings.EqualFold(msg.Method(), "ACK") {
		return nil
	}
	if !strings.EqualFold(msg.Method(), "MESSAGE") {
		return c.writeStatus(ctx, transport, msg, 405, "Method Not Allowed")
	}
	return c.handleMessageRequest(ctx, transport, msg)
}

func (c *Client) writeStatus(ctx context.Context, transport Transport, req Message, code int, reason string) error {
	resp := NewResponse(code, reason)
	resp.Headers = responseHeaders(req, code)
	return c.writeResponsePacket(ctx, transport, req, resp.Bytes())
}

type targetedPacketWriter interface {
	WritePacketTo(ctx context.Context, data []byte, addr net.Addr) error
}

func (c *Client) writePacket(ctx context.Context, transport Transport, data []byte) error {
	return c.writePacketTo(ctx, transport, data, nil)
}

func (c *Client) writePacketTo(ctx context.Context, transport Transport, data []byte, addr net.Addr) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if addr == nil {
		return transport.WritePacket(ctx, data)
	}
	writer, ok := transport.(targetedPacketWriter)
	if !ok {
		return transport.WritePacket(ctx, data)
	}
	return writer.WritePacketTo(ctx, data, addr)
}

func (c *Client) writeResponsePacket(ctx context.Context, transport Transport, req Message, data []byte) error {
	return c.writePacketTo(ctx, transport, data, responseDestination(transport.RemoteAddr(), req.Header("Via")))
}

func responseDestination(remote net.Addr, _ string) net.Addr {
	udpRemote, ok := remote.(*net.UDPAddr)
	if !ok || udpRemote == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), udpRemote.IP...), Port: udpRemote.Port, Zone: udpRemote.Zone}
}

func (c *Client) handleMessageRequest(ctx context.Context, transport Transport, msg Message) error {
	var rp rpMessage
	if err := rp.UnmarshalBinary(msg.Body); err != nil {
		if report, ok := malformedNetworkSMSSubmitReport(msg.Body); ok {
			callID := strings.TrimSpace(msg.Header("In-Reply-To"))
			if !c.knowsSMSSubmit(callID, time.Now()) {
				c.logger.Debug("submit report not matched", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", callID, "rp_ref", report.Reference, "err", err)
				return c.writeMessageStatus(ctx, transport, msg, 488, "Not Acceptable Here")
			}
			if err := c.writeMessageStatus(ctx, transport, msg, 200, "OK"); err != nil {
				return err
			}
			switch report.Type {
			case rpAckNetworkToMS:
				c.logger.Debug("submit report invalid mandatory information", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", callID, "rp_ref", report.Reference, "err", err)
				c.sendInboundSMSDeliveryReport(msg, newRPErrorMessage(report.Reference, rpCauseInvalidMandatoryInformation))
			case rpErrorNetworkToMS:
				c.logger.Debug("submit report protocol error", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", callID, "rp_ref", report.Reference, "cause", rpCauseProtocolErrorUnspecified, "err", err)
				c.completeSMSPending(msg, report)
			}
			return nil
		}
		if err := c.writeMessageStatus(ctx, transport, msg, 200, "OK"); err != nil {
			return err
		}
		if len(msg.Body) >= 2 && msg.Body[0] == rpDataNetworkToMS {
			c.sendInboundSMSDeliveryReport(msg, newRPErrorMessage(msg.Body[1], rpCauseInvalidMandatoryInformation))
		}
		c.logger.Debug("ignoring malformed sms message", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "err", err)
		return nil
	}
	if isSMSReport(rp) {
		if c.completeSMSPending(msg, rp) {
			return c.writeMessageStatus(ctx, transport, msg, 200, "OK")
		}
		return c.writeMessageStatus(ctx, transport, msg, 488, "Not Acceptable Here")
	}
	if err := c.writeMessageStatus(ctx, transport, msg, 200, "OK"); err != nil {
		return err
	}
	return c.handleInboundRP(msg, rp)
}

func (c *Client) writeMessageStatus(ctx context.Context, transport Transport, msg Message, code int, reason string) error {
	responseAddr := responseDestination(transport.RemoteAddr(), msg.Header("Via"))
	if responseAddr == nil {
		responseAddr = transport.RemoteAddr()
	}
	c.logger.Debug("sending MESSAGE response", "status_code", code, "reason", reason, "target_addr", responseAddr, "transport_remote_addr", transport.RemoteAddr(), "via", msg.Header("Via"), "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"))
	return c.writeStatus(ctx, transport, msg, code, reason)
}

func (c *Client) handleInboundRP(msg Message, rp rpMessage) error {
	mti, err := smsTPDUMessageType(rp.TPDU)
	if err != nil {
		c.sendInboundSMSDeliveryReport(msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation))
		return nil
	}
	switch mti {
	case tpduMTISMSDeliver, tpduMTIReserved:
		var tpdu smsDeliverTPDU
		if err := tpdu.UnmarshalBinary(rp.TPDU); err != nil {
			c.logger.Debug("rejecting inbound sms deliver", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference, "err", err)
			c.sendInboundSMSDeliveryReport(msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation))
			return nil
		}
		if !c.sendInboundSMSDeliveryReport(msg, newRPAckDeliverReportMessage(rp.Reference)) {
			return nil
		}
		c.deliverIncomingSMS(msg, rp, tpdu)
	case tpduMTISMSStatusReport:
		var tpdu smsStatusReportTPDU
		if err := tpdu.UnmarshalBinary(rp.TPDU); err != nil {
			c.logger.Debug("rejecting inbound sms status report", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference, "err", err)
			c.sendInboundSMSDeliveryReport(msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation))
			return nil
		}
		if !c.sendInboundSMSDeliveryReport(msg, newRPAckDeliverReportMessage(rp.Reference)) {
			return nil
		}
		c.deliverIncomingSMSStatusReport(msg, rp, tpdu.Message)
	default:
		c.sendInboundSMSDeliveryReport(msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation))
	}
	return nil
}

func isSMSReport(rp rpMessage) bool {
	return rp.Type == rpAckNetworkToMS || rp.Type == rpErrorNetworkToMS
}

func (c *Client) sendInboundSMSDeliveryReport(msg Message, report rpMessage) bool {
	if !c.markSMSDeliveryReportSent(msg) {
		return true
	}
	if err := c.sendSMSDeliveryReport(msg, report); err != nil {
		c.clearSMSDeliveryReportSent(msg)
		c.logger.Warn("sending inbound sms delivery report", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "err", err)
		return false
	}
	return true
}

func (c *Client) sendSMSDeliveryReport(msg Message, report rpMessage) error {
	target := c.smsReportTarget(msg)
	if target == "" {
		return errors.New("delivery report target is empty")
	}
	reportPayload, err := report.MarshalBinary()
	if err != nil {
		return fmt.Errorf("building sms delivery report: %w", err)
	}
	reportMsg := c.buildMessage(target, reportPayload, msg.Header("Call-ID"))
	c.logger.Debug("sending sms delivery report", "target", target, "call_id", reportMsg.Header("Call-ID"), "in_reply_to", reportMsg.Header("In-Reply-To"))
	baseCtx := c.backgroundCtx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, 10*time.Second)
	respCh := c.registerPending(reportMsg)
	done, ok := c.reserveBackgroundTask()
	if !ok {
		c.removePending(reportMsg)
		cancel()
		return errors.New("client is closed")
	}
	if err := c.writeRequest(ctx, c.transport, reportMsg); err != nil {
		c.removePending(reportMsg)
		cancel()
		done()
		return fmt.Errorf("sending sms delivery report: %w", err)
	}
	go func() {
		defer done()
		defer cancel()
		defer c.removePending(reportMsg)
		c.awaitSMSDeliveryReportResponse(ctx, reportMsg, respCh)
	}()
	return nil
}

func (c *Client) awaitSMSDeliveryReportResponse(ctx context.Context, req Message, respCh <-chan Message) {
	resp, err := awaitPendingFinalResponse(ctx, respCh)
	if err != nil {
		c.logger.Debug("sending sms delivery report failed", "call_id", req.Header("Call-ID"), "in_reply_to", req.Header("In-Reply-To"), "err", err)
		return
	}
	if status := resp.StatusCode(); status != 200 && status != 202 {
		c.logger.Debug("sms delivery report rejected", "call_id", req.Header("Call-ID"), "in_reply_to", req.Header("In-Reply-To"), "status_code", status)
		return
	}
	c.logger.Debug("sms delivery report accepted", "call_id", req.Header("Call-ID"), "in_reply_to", req.Header("In-Reply-To"), "status_code", resp.StatusCode())
}

func (c *Client) deliverIncomingSMS(msg Message, rp rpMessage, tpdu smsDeliverTPDU) {
	incoming := tpdu.Message
	incoming.To = incomingSMSRecipient(msg)
	incoming.ServiceCenter = rp.Originator
	if tpdu.Concat != nil {
		c.deliverConcatSMS(incoming, *tpdu.Concat)
		return
	}
	c.deliverSingleSMS(msg, incoming)
}

func (c *Client) deliverIncomingSMSStatusReport(msg Message, rp rpMessage, report SMSStatusReport) {
	if c.onSMSStatusReport == nil {
		return
	}
	report.ServiceCenter = rp.Originator
	if c.markSMSSeen(msg) {
		c.onSMSStatusReport(report)
		return
	}
	c.logger.Debug("suppressing duplicate sms status report", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "message_reference", report.MessageReference, "status", report.Status)
}

func incomingSMSRecipient(msg Message) string {
	for _, candidate := range []string{msg.Header("To"), requestURI(msg)} {
		if target := smsEnvelopeAddress(candidate); target != "" {
			return target
		}
	}
	return ""
}

func smsEnvelopeAddress(value string) string {
	uri := addressURI(value)
	if uri == "" {
		return ""
	}
	switch lower := strings.ToLower(uri); {
	case strings.HasPrefix(lower, "tel:"):
		return uri[len("tel:"):]
	case strings.HasPrefix(lower, "sip:"), strings.HasPrefix(lower, "sips:"):
		return uri
	default:
		return uri
	}
}

func (c *Client) deliverConcatSMS(msg IncomingSMS, concat smsConcatInfo) {
	if c.onSMS == nil {
		return
	}
	incoming, complete, concatKey := c.appendConcatSMS(msg, concat)
	if !complete {
		return
	}
	if c.markConcatSMSSeen(concatKey) {
		c.onSMS(incoming)
	}
}

func (c *Client) deliverSingleSMS(msg Message, incoming IncomingSMS) {
	if c.onSMS == nil {
		return
	}
	if c.markSMSSeen(msg) {
		c.onSMS(incoming)
		return
	}
	c.logger.Debug("suppressing duplicate sms", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "from", incoming.From, "text", incoming.Text)
}

func (c *Client) buildRegister(auth *digestAuthorization, verify *SecurityParam) Message {
	port := c.registerPort
	if verify != nil || auth != nil {
		port = c.securityClient.PortS
	}
	legacyAuthorization := ""
	if auth == nil {
		legacyAuthorization = c.legacyEmptyAuthorizationValue()
	}
	return c.buildRegisterRequest(auth, legacyAuthorization, verify, c.registerContactValue(port), c.registerExpiresSeconds(), port)
}

func (c *Client) buildDeregister(auth *digestAuthorization, verify *SecurityParam) Message {
	port := c.registerPort
	if verify != nil || auth != nil {
		port = c.securityClient.PortS
	}
	return c.buildRegisterRequest(auth, "", verify, "*", 0, port)
}

func (c *Client) registerRealm(auth *digestAuthorization) string {
	realm := strings.TrimPrefix(c.registerURI, "sip:")
	if auth == nil || strings.TrimSpace(auth.Realm) == "" {
		return realm
	}
	return auth.Realm
}

func (c *Client) addClientRequestHeaders(msg *Message) {
	msg.AddHeader("Allow", "ACK,BYE,CANCEL,INFO,INVITE,MESSAGE,NOTIFY,OPTIONS,PRACK,REFER,UPDATE")
	msg.AddHeader("Max-Forwards", "70")
	msg.AddHeader("Supported", "100rel,path,replaces")
	msg.AddHeader("User-Agent", c.cfg.UserAgent)
	c.maybeAddAccessNetworkInfo(msg)
}

func (c *Client) addSecurityRequirements(msg *Message) {
	msg.AddHeader("Require", "sec-agree")
	msg.AddHeader("Proxy-Require", "sec-agree")
}

func (c *Client) addServiceRoutes(msg *Message) {
	for _, route := range c.serviceRoutes {
		msg.AddHeader("Route", route)
	}
}

func (c *Client) legacyEmptyAuthorizationValue() string {
	return (&digestAuthorization{
		Nonce:    "",
		URI:      c.registerURI,
		Response: "",
		Username: c.privateIdentity,
		Realm:    c.registerRealm(nil),
	}).HeaderValue()
}

func (c *Client) buildRegisterRequest(auth *digestAuthorization, legacyAuthorization string, verify *SecurityParam, contact string, expiresSeconds, port int) Message {
	realm := c.registerRealm(auth)
	branch := randomAlphaNum(15)
	msg := NewRequest("REGISTER", c.registerURI)
	msg.AddHeader("To", fmt.Sprintf("<%s>", c.cfg.PublicIdentity))
	msg.AddHeader("From", fmt.Sprintf("<%s>;tag=%s", c.cfg.PublicIdentity, c.tag))
	msg.AddHeader("Expires", strconv.Itoa(expiresSeconds))
	c.addSecurityRequirements(&msg)
	msg.AddHeader("Security-Client", c.securityClient.String())
	msg.AddHeader("Call-ID", c.callID)
	msg.AddHeader("Session-ID", c.sessionID)
	msg.AddHeader("Geolocation", fmt.Sprintf("<cid:%s@%s>", c.card.IMSI(), realm))
	msg.AddHeader("Geolocation-Routing", "yes")
	msg.AddHeader("Contact", contact)
	if auth != nil {
		msg.AddHeader("Authorization", auth.HeaderValue())
	} else if legacyAuthorization != "" {
		msg.AddHeader("Authorization", legacyAuthorization)
	}
	msg.AddHeader("CSeq", fmt.Sprintf("%d REGISTER", atomic.AddInt64(&c.cseq, 1)))
	msg.AddHeader("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=z9hG4bK%s;rport", c.transportToken(), net.JoinHostPort(c.contactHost, strconv.Itoa(port)), branch))
	c.addClientRequestHeaders(&msg)
	c.addSecurityVerifyHeader(&msg, verify)
	msg.AddHeader("Content-Type", "application/pidf+xml")
	msg.Body = []byte(c.registerPIDFBody())
	return msg
}

func (c *Client) buildSubscribe() Message {
	callID, sessionID, tag, branch := newTransaction()
	msg := NewRequest("SUBSCRIBE", c.cfg.PublicIdentity)
	msg.AddHeader("Expires", strconv.Itoa(c.registerExpiresSeconds()))
	msg.AddHeader("Event", "reg")
	msg.AddHeader("From", fmt.Sprintf("<%s>;tag=%s", c.cfg.PublicIdentity, tag))
	msg.AddHeader("To", fmt.Sprintf("<%s>", c.cfg.PublicIdentity))
	msg.AddHeader("Call-ID", callID)
	msg.AddHeader("Session-ID", sessionID)
	msg.AddHeader("Contact", c.subscribeContactValue(c.messageViaPort()))
	msg.AddHeader("CSeq", fmt.Sprintf("%d SUBSCRIBE", atomic.AddInt64(&c.cseq, 1)))
	msg.AddHeader("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=z9hG4bK%s;rport", c.transportToken(), net.JoinHostPort(c.contactHost, strconv.Itoa(c.messageViaPort())), branch))
	c.addClientRequestHeaders(&msg)
	c.addServiceRoutes(&msg)
	c.addSecurityVerifyHeader(&msg, c.currentSecurityVerify())
	c.addSecurityRequirements(&msg)
	return msg
}

func newTransaction() (callID, sessionID, tag, branch string) {
	return randomAlphaNum(24), randomHex(32), randomAlphaNum(10), randomAlphaNum(15)
}

func (c *Client) buildMessage(target string, body []byte, inReplyTo string) Message {
	if target == "" {
		target = "tel:" + c.card.SMSC()
	}
	callID, _, tag, branch := newTransaction()
	senderIdentity := c.smsPreferredIdentity()
	msg := NewRequest("MESSAGE", target)
	msg.AddHeader("Call-ID", callID)
	msg.AddHeader("From", fmt.Sprintf("<%s>;tag=%s", senderIdentity, tag))
	msg.AddHeader("To", fmt.Sprintf("<%s>", target))
	msg.AddHeader("Request-Disposition", "no-fork")
	msg.AddHeader("Accept-Contact", "*;+g.3gpp.smsip")
	msg.AddHeader("CSeq", fmt.Sprintf("%d MESSAGE", atomic.AddInt64(&c.cseq, 1)))
	msg.AddHeader("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=z9hG4bK%s;rport", c.transportToken(), net.JoinHostPort(c.contactHost, strconv.Itoa(c.messageViaPort())), branch))
	msg.AddHeader("P-Preferred-Identity", fmt.Sprintf("<%s>", senderIdentity))
	c.addClientRequestHeaders(&msg)
	c.addServiceRoutes(&msg)
	c.addSecurityVerifyHeader(&msg, c.currentSecurityVerify())
	c.addSecurityRequirements(&msg)
	msg.AddHeader("Content-Type", "application/vnd.3gpp.sms")
	msg.AddHeader("Content-Transfer-Encoding", "binary")
	if inReplyTo != "" {
		msg.AddHeader("In-Reply-To", inReplyTo)
	}
	msg.Body = body
	return msg
}

func (c *Client) smsPreferredIdentity() string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(c.telPublicID)), "tel:") {
		return c.telPublicID
	}
	return c.cfg.PublicIdentity
}

func (c *Client) registerPending(msg Message) <-chan Message {
	key := pendingKey(msg)
	ch := make(chan Message, 4)
	c.mu.Lock()
	c.pending[key] = ch
	c.mu.Unlock()
	return ch
}

func (c *Client) removePending(msg Message) {
	key := pendingKey(msg)
	c.mu.Lock()
	delete(c.pending, key)
	c.mu.Unlock()
}

func (c *Client) markRecentSMSKey(key string, ttl time.Duration) bool {
	if key == "" {
		return true
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for seenKey, seenAt := range c.recentSMS {
		if now.Sub(seenAt) > ttl {
			delete(c.recentSMS, seenKey)
		}
	}
	if seenAt, exists := c.recentSMS[key]; exists && now.Sub(seenAt) <= ttl {
		return false
	}
	c.recentSMS[key] = now
	return true
}

func (c *Client) clearRecentSMSKey(key string) {
	if key == "" {
		return
	}
	c.mu.Lock()
	delete(c.recentSMS, key)
	c.mu.Unlock()
}

func (c *Client) markConcatSMSSeen(key string) bool {
	return c.markRecentSMSKey("concat|"+key, concatSMSRetention)
}

func (c *Client) concatSMSKey(msg IncomingSMS, concat smsConcatInfo) string {
	return fmt.Sprintf("%t|%d|%s|%s", concat.SixteenBit, concat.Reference, msg.From, msg.ServiceCenter)
}

func (c *Client) evictExpiredConcatSMS(now time.Time) {
	for cacheKey, state := range c.concatSMS {
		if state.expired(now) {
			delete(c.concatSMS, cacheKey)
		}
	}
}

func (c *Client) appendConcatSMS(msg IncomingSMS, concat smsConcatInfo) (IncomingSMS, bool, string) {
	key := c.concatSMSKey(msg, concat)
	now := time.Now()
	c.mu.Lock()
	c.evictExpiredConcatSMS(now)
	state := c.concatSMS[key]
	if state.parts == nil || state.total != int(concat.Total) {
		state.reset(int(concat.Total))
	}
	state.addPart(int(concat.Sequence), msg.Text, now)
	text, ok := state.joinedText()
	if !ok {
		c.concatSMS[key] = state
		c.mu.Unlock()
		return IncomingSMS{}, false, key
	}
	delete(c.concatSMS, key)
	c.mu.Unlock()
	msg.Text = text
	return msg, true, key
}

func (c *Client) markSMSSeen(msg Message) bool {
	key, ok := smsSeenKey(msg)
	if !ok {
		return true
	}
	return c.markRecentSMSKey("sip|"+key, 2*time.Minute)
}

func (c *Client) markSMSDeliveryReportSent(msg Message) bool {
	key, ok := smsSeenKey(msg)
	if !ok {
		return true
	}
	return c.markRecentSMSKey("report|"+key, 2*time.Minute)
}

func (c *Client) clearSMSDeliveryReportSent(msg Message) {
	key, ok := smsSeenKey(msg)
	if !ok {
		return
	}
	c.clearRecentSMSKey("report|" + key)
}

func smsSeenKey(msg Message) (string, bool) {
	callID := strings.TrimSpace(msg.Header("Call-ID"))
	cseq := strings.TrimSpace(msg.Header("CSeq"))
	if callID == "" || cseq == "" {
		return "", false
	}
	return callID + "|" + cseq, true
}

func (c *Client) dispatchResponse(msg Message) bool {
	key := pendingKey(msg)
	c.mu.Lock()
	ch, ok := c.pending[key]
	c.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- msg:
	default:
	}
	return true
}

func pendingKey(msg Message) string {
	return msg.Header("Call-ID") + "|" + msg.Header("CSeq")
}

func responseHeaders(req Message, code int) []Header {
	to := req.Header("To")
	if code != 100 && to != "" {
		to = withTag(to, "", responseTag(req))
	}
	return []Header{
		{Name: "Via", Value: req.Header("Via")},
		{Name: "From", Value: req.Header("From")},
		{Name: "To", Value: to},
		{Name: "Call-ID", Value: req.Header("Call-ID")},
		{Name: "CSeq", Value: req.Header("CSeq")},
	}
}

func responseTag(req Message) string {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(req.Method()))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(req.Header("Via")))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(req.Header("Call-ID")))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(req.Header("CSeq")))
	return fmt.Sprintf("%016x", hash.Sum64())
}

func randomAlphaNum(length int) string {
	return randomString(length, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

func randomHex(length int) string {
	return randomString(length, "0123456789abcdef")
}

func randomString(length int, alphabet string) string {
	buf := make([]byte, length)
	rnd := make([]byte, length)
	_, _ = rand.Read(rnd)
	for i, b := range rnd {
		buf[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(buf)
}

func randomIMSPort() int {
	const base = 10000
	const span = 55535
	return base + int(randomUint32()%span)
}

func randomUint32() uint32 {
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	return binary.BigEndian.Uint32(buf[:])
}

func (c *Client) transportToken() string {
	switch strings.ToLower(strings.TrimSpace(c.cfg.Transport)) {
	case "tcp":
		return "TCP"
	default:
		return "UDP"
	}
}

func (c *Client) messageViaPort() int {
	if c.currentSecurityVerify() != nil && c.securityClient.PortS != 0 {
		return c.securityClient.PortS
	}
	return c.registerPort
}

func (c *Client) subscribeContactValue(port int) string {
	params := []string{"text"}
	if c.cfg.IMEI != "" {
		params = append([]string{fmt.Sprintf(`+sip.instance="<urn:gsma:imei:%s>"`, c.cfg.IMEI)}, params...)
	}
	contactURI := fmt.Sprintf("sip:%s:%d", c.contactHost, port)
	return fmt.Sprintf("<%s>;%s", contactURI, strings.Join(params, ";"))
}

func (c *Client) registerPIDFBody() string {
	return fmt.Sprintf(`<?xml version="1.0"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf" xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model" xmlns:gp="urn:ietf:params:xml:ns:pidf:geopriv10" xmlns:gml="http://www.opengis.net/gml" xmlns:gs="http://www.opengis.net/pidflo/1.0" xmlns:cl="urn:ietf:params:xml:ns:pidf:geopriv10:civicAddr" entity="%s">
<dm:device id="Wifi">
<gp:geopriv>
<gp:location-info>
<cl:civicAddress>
<cl:country>%s</cl:country>
</cl:civicAddress>
</gp:location-info>
<gp:usage-rules/>
</gp:geopriv>
<dm:timestamp>%s</dm:timestamp>
</dm:device>
</presence>`, c.cfg.PublicIdentity, c.cfg.Country, time.Now().UTC().Format(time.RFC3339))
}

func (c *Client) registerContactValue(port int) string {
	params := []string{
		`+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`,
		`+g.3gpp.mid-call`,
		`+g.3gpp.nw-init-ussi`,
		`+g.3gpp.ps2cs-srvcc-orig-pre-alerting`,
		`+g.3gpp.smsip`,
		`+g.3gpp.srvcc-alerting`,
	}
	if c.cfg.IMEI != "" {
		params = append(params, fmt.Sprintf(`+sip.instance="<urn:gsma:imei:%s>"`, c.cfg.IMEI))
	}
	params = append(params, "text")
	contactURI := fmt.Sprintf("sip:%s:%d", c.contactHost, port)
	return fmt.Sprintf("<%s>;%s", contactURI, strings.Join(params, ";"))
}

func sanitizeHost(host string) string {
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	if host == "" || host == "::" || host == "0.0.0.0" {
		return "127.0.0.1"
	}
	return host
}
