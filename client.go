package imsclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/damonto/ims-client/apdu"
	"github.com/damonto/ims-client/ims"
	"github.com/damonto/ims-client/swu"
	"github.com/damonto/ims-client/usim"
)

type Config struct {
	IMEI            string
	EPDGAddress     string
	PCSCFAddress    string
	UserAgent       string
	RegisterExpires time.Duration
	Logger          *slog.Logger
	Tunnel          swu.Config
	IMS             ims.Config
}

type Card interface {
	ICCID() string
	IMSI() string
	MCC() string
	MNC() string
	SMSC() string
	AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error)
}

type RegistrationState string

const (
	StateConnecting     RegistrationState = "connecting"
	StateAuthenticating RegistrationState = "authenticating"
	StateRegistered     RegistrationState = "registered"
	StateClosed         RegistrationState = "closed"
	StateFailed         RegistrationState = "failed"
)

type IncomingSMS struct {
	From          string
	To            string
	ServiceCenter string
	Text          string
	ReceivedAt    time.Time
}

type IncomingUSSD struct {
	Session    *USSDSession
	Message    USSDMessage
	ReceivedAt time.Time
}

type USSDMessage = ims.USSDMessage

type USSDSession = ims.USSDSession

type Events struct {
	SMS    <-chan IncomingSMS
	USSD   <-chan IncomingUSSD
	State  <-chan RegistrationState
	Errors <-chan error
}

type Client struct {
	cfg    Config
	card   Card
	logger *slog.Logger

	mu      sync.Mutex
	closed  bool
	active  *activeConn
	bus     eventBus
	sms     SMSService
	closeWG sync.WaitGroup
	close   sync.Once
}

type SMSService struct {
	client *Client
}

type USSDService struct {
	client *Client
}

type eventBus struct {
	sms    chan IncomingSMS
	ussd   chan IncomingUSSD
	state  chan RegistrationState
	errors chan error
}

type activeConn struct {
	cancel  context.CancelFunc
	session *swu.Session
	ims     *ims.Client
}

type connectSetup struct {
	runCtx    context.Context
	cancel    context.CancelFunc
	tunnelCfg swu.Config
	imsCfg    ims.Config
	proxyAddr string
	useSWu    bool
	session   *swu.Session
	imsClient *ims.Client
}

type cardCloser interface {
	io.Closer
}

const defaultCloseTimeout = 5 * time.Second

func NewClient(ctx context.Context, cfg Config, drv apdu.Driver) (*Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized, err := cfg.normalized()
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}
	card, err := usim.Load(ctx, drv, normalized.Logger)
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}
	return newClient(normalized, card)
}

func newClient(cfg Config, card Card) (*Client, error) {
	if card == nil {
		return nil, fmt.Errorf("creating client: card is nil")
	}
	normalized, err := cfg.normalized()
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}
	bus := eventBus{
		sms:    make(chan IncomingSMS, 16),
		ussd:   make(chan IncomingUSSD, 16),
		state:  make(chan RegistrationState, 16),
		errors: make(chan error, 16),
	}
	client := &Client{cfg: normalized, card: card, logger: normalized.Logger.With("component", "ims-client"), bus: bus}
	client.sms.client = client
	return client, nil
}

func (c *Client) Connect(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	setup, err := c.prepareConnect(ctx)
	if err != nil {
		return err
	}
	defer setup.rollback()

	c.emitState(StateConnecting)
	tunnelInfo, err := c.openTunnel(setup)
	if err != nil {
		c.emitError(err)
		c.emitState(StateFailed)
		return err
	}

	imsCfg, transport, err := c.buildIMSTransport(setup, tunnelInfo)
	if err != nil {
		c.emitError(err)
		c.emitState(StateFailed)
		return err
	}

	imsCfg.OnSMS = c.handleSMS
	imsCfg.OnUSSD = c.handleUSSD
	imsCfg.OnError = c.emitError
	imsClient, err := ims.NewClient(imsCfg, transport, c.card)
	if err != nil {
		wrapped := fmt.Errorf("creating IMS client: %w", err)
		c.emitError(wrapped)
		c.emitState(StateFailed)
		return wrapped
	}
	setup.imsClient = imsClient

	c.logger.Debug("registering IMS", "proxy_addr", imsCfg.ProxyAddr)
	if err := imsClient.Register(setup.runCtx); err != nil {
		wrapped := fmt.Errorf("registering IMS: %w", err)
		c.emitError(wrapped)
		c.emitState(StateFailed)
		return wrapped
	}

	active, err := c.commitConnect(setup)
	if err != nil {
		c.emitError(err)
		c.emitState(StateFailed)
		return err
	}
	go c.runIMS(setup.runCtx, active)

	c.logger.Debug("ims registered")
	c.emitState(StateRegistered)
	return nil
}

func (c *Client) prepareConnect(ctx context.Context) (*connectSetup, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, fmt.Errorf("connecting client: already closed")
	}
	if c.active != nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("connecting client: already connected")
	}
	c.mu.Unlock()

	runCtx, cancel := context.WithCancel(ctx)
	proxyAddr := c.cfg.PCSCFAddress
	if proxyAddr == "" {
		proxyAddr = c.cfg.IMS.ProxyAddr
	}

	tunnelCfg := c.cfg.Tunnel
	useSWu := c.cfg.EPDGAddress != "" || (tunnelCfg.RemoteAddr != "" && tunnelCfg.RemoteAddr != proxyAddr)
	if tunnelCfg.RemoteAddr == "" {
		if useSWu {
			tunnelCfg.RemoteAddr = c.cfg.EPDGAddress
		} else {
			tunnelCfg.RemoteAddr = proxyAddr
		}
	}
	tunnelCfg, err := tunnelCfg.Normalized()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("preparing connect: %w", err)
	}
	if tunnelCfg.RemoteAddr == "" {
		cancel()
		return nil, fmt.Errorf("preparing connect: tunnel remote address is empty")
	}

	imsCfg := c.cfg.IMS
	if imsCfg.ProxyAddr == "" {
		imsCfg.ProxyAddr = proxyAddr
	}
	imsCfg, err = imsCfg.Normalized()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("preparing connect: %w", err)
	}

	return &connectSetup{
		runCtx:    runCtx,
		cancel:    cancel,
		tunnelCfg: tunnelCfg,
		imsCfg:    imsCfg,
		proxyAddr: proxyAddr,
		useSWu:    useSWu,
	}, nil
}

func (c *Client) openTunnel(setup *connectSetup) (swu.TunnelInfo, error) {
	session, err := swu.Dial(setup.runCtx, setup.tunnelCfg)
	if err != nil {
		return swu.TunnelInfo{}, fmt.Errorf("dialing tunnel: %w", err)
	}
	setup.session = session

	c.emitState(StateAuthenticating)
	c.logger.Debug("starting client connection", "use_swu", setup.useSWu, "tunnel_remote_addr", setup.tunnelCfg.RemoteAddr, "proxy_addr", setup.proxyAddr)

	tunnelInfo := swu.TunnelInfo{}
	if !setup.useSWu {
		return tunnelInfo, nil
	}
	if err := session.Connect(setup.runCtx, c.cfg.IMEI, c.card); err != nil {
		return swu.TunnelInfo{}, fmt.Errorf("connecting swu: %w", err)
	}
	tunnelInfo = session.Tunnel()
	c.logger.Debug("swu tunnel established", "inner_ip", tunnelInfo.InnerIP, "pcscf_ip", tunnelInfo.PCSCFIP, "esp_initiator_spi", tunnelInfo.ESPInitiatorSPI, "esp_responder_spi", tunnelInfo.ESPResponderSPI)
	return tunnelInfo, nil
}

func (c *Client) buildIMSTransport(setup *connectSetup, tunnelInfo swu.TunnelInfo) (ims.Config, ims.Transport, error) {
	imsCfg := setup.imsCfg
	if imsCfg.ProxyAddr == "" {
		imsCfg.ProxyAddr = resolveIMSProxyAddr(setup.proxyAddr, setup.tunnelCfg, tunnelInfo)
	}
	if imsCfg.ProxyAddr == "" {
		return ims.Config{}, nil, fmt.Errorf("preparing ims config: proxy address is empty")
	}

	var transport ims.Transport = setup.session
	if imsCfg.Transport != "tcp" {
		return imsCfg, transport, nil
	}

	tcpTransport, err := setup.session.DialTCP(setup.runCtx, setup.tunnelCfg.LocalSIPPort, setup.tunnelCfg.SIPPort)
	if err != nil {
		return ims.Config{}, nil, fmt.Errorf("dialing ims tcp transport: %w", err)
	}
	transport = tcpTransport
	imsCfg.DialSecureTCP = func(ctx context.Context, cfg ims.SecureTCPConfig) (ims.Transport, error) {
		return setup.session.DialSecureTCP(ctx, swu.SecureTCPConfig{
			LocalPort:    cfg.LocalPort,
			RemotePort:   cfg.RemotePort,
			OutboundSPI:  cfg.OutboundSPI,
			InboundSPI:   cfg.InboundSPI,
			Integrity:    cfg.Integrity,
			IntegrityKey: cfg.IntegrityKey,
		})
	}
	imsCfg.ListenSecureTCP = func(ctx context.Context, cfg ims.SecureTCPConfig) (ims.Transport, error) {
		return setup.session.ListenSecureTCP(swu.SecureTCPConfig{
			LocalPort:    cfg.LocalPort,
			RemotePort:   cfg.RemotePort,
			OutboundSPI:  cfg.OutboundSPI,
			InboundSPI:   cfg.InboundSPI,
			Integrity:    cfg.Integrity,
			IntegrityKey: cfg.IntegrityKey,
		})
	}
	imsCfg.ListenSecureUDP = func(ctx context.Context, cfg ims.SecureUDPConfig) (ims.Transport, error) {
		return setup.session.ListenSecureUDP(swu.SecureUDPConfig{
			LocalPort:    cfg.LocalPort,
			RemotePort:   cfg.RemotePort,
			OutboundSPI:  cfg.OutboundSPI,
			InboundSPI:   cfg.InboundSPI,
			Integrity:    cfg.Integrity,
			IntegrityKey: cfg.IntegrityKey,
		})
	}
	return imsCfg, transport, nil
}

func (c *Client) commitConnect(setup *connectSetup) (*activeConn, error) {
	active := &activeConn{cancel: setup.cancel, session: setup.session, ims: setup.imsClient}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, fmt.Errorf("connecting client: client closed during setup")
	}
	if c.active != nil {
		return nil, fmt.Errorf("connecting client: already connected")
	}
	c.active = active
	c.closeWG.Add(1)
	setup.cancel = nil
	setup.session = nil
	setup.imsClient = nil
	return active, nil
}

func (s *connectSetup) rollback() {
	if s.cancel == nil {
		return
	}
	s.cancel()
	if s.imsClient != nil {
		_ = s.imsClient.Close()
	}
	if s.session != nil {
		_ = s.session.Close()
	}
}

func (c *Client) runIMS(runCtx context.Context, active *activeConn) {
	defer c.closeWG.Done()
	if err := active.ims.Run(runCtx); err != nil && runCtx.Err() == nil {
		active.cancel()

		c.mu.Lock()
		sameConn := c.active == active && !c.closed
		if sameConn {
			c.active = nil
		}
		c.mu.Unlock()

		if sameConn {
			_ = active.ims.Close()
			_ = active.session.Close()
		}

		c.emitError(fmt.Errorf("running IMS loop: %w", err))
		c.emitState(StateFailed)
	}
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

	var err error
	c.close.Do(func() {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		c.closed = true
		active := c.active
		card := c.card
		c.active = nil
		c.mu.Unlock()

		if active != nil && active.cancel != nil {
			active.cancel()
		}
		c.closeWG.Wait()
		if active != nil && active.ims != nil {
			err = errors.Join(err, wrapCloseError("closing IMS client", normalizeCloseError(active.ims.CloseContext(ctx))))
		}
		if active != nil && active.session != nil {
			err = errors.Join(err, wrapCloseError("closing session", active.session.CloseContext(ctx)))
		}
		if closer, ok := card.(cardCloser); ok {
			err = errors.Join(err, wrapCloseError("closing card", closer.Close()))
		}
		c.emitState(StateClosed)
		close(c.bus.sms)
		close(c.bus.ussd)
		close(c.bus.state)
		close(c.bus.errors)
	})
	return err
}

func normalizeCloseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

func wrapCloseError(action string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", action, err)
}

func (c *Client) Events() Events {
	return Events{SMS: c.bus.sms, USSD: c.bus.ussd, State: c.bus.state, Errors: c.bus.errors}
}

func (c *Client) Tunnel() swu.TunnelInfo {
	c.mu.Lock()
	active := c.active
	c.mu.Unlock()
	if active == nil || active.session == nil {
		return swu.TunnelInfo{}
	}
	return active.session.Tunnel()
}

func resolveIMSProxyAddr(explicit string, tunnelCfg swu.Config, tunnel swu.TunnelInfo) string {
	if explicit != "" {
		return explicit
	}
	if len(tunnel.PCSCFIP) == 0 {
		return ""
	}
	port := tunnelCfg.SIPPort
	if port == 0 {
		port = 5060
	}
	return net.JoinHostPort(tunnel.PCSCFIP.String(), strconv.Itoa(port))
}

func (c *Client) SMS() *SMSService {
	return &c.sms
}

func (c *Client) USSD() *USSDService {
	return &USSDService{client: c}
}

func (c *Client) SendSMS(ctx context.Context, to, text string) error {
	c.mu.Lock()
	active := c.active
	c.mu.Unlock()
	if active == nil || active.ims == nil {
		return fmt.Errorf("sending SMS: client is not connected")
	}
	return active.ims.SendSMS(ctx, to, text)
}

func (s *SMSService) Send(ctx context.Context, to, text string) error {
	return s.client.SendSMS(ctx, to, text)
}

func (c *Client) StartUSSD(ctx context.Context, code string) (*USSDSession, error) {
	c.mu.Lock()
	active := c.active
	c.mu.Unlock()
	if active == nil || active.ims == nil {
		return nil, fmt.Errorf("starting USSD: client is not connected")
	}
	return active.ims.StartUSSD(ctx, code)
}

func (s *USSDService) Dial(ctx context.Context, code string) (*USSDSession, error) {
	return s.client.StartUSSD(ctx, code)
}

func (c *Client) handleSMS(msg ims.IncomingSMS) {
	event := IncomingSMS{From: msg.From, To: msg.To, ServiceCenter: msg.ServiceCenter, Text: msg.Text, ReceivedAt: time.Now()}
	select {
	case c.bus.sms <- event:
	default:
		c.logger.Debug("dropping sms event", "from", event.From, "to", event.To, "service_center", event.ServiceCenter)
	}
}

func (c *Client) handleUSSD(session *ims.USSDSession, msg ims.USSDMessage) {
	event := IncomingUSSD{Session: session, Message: msg, ReceivedAt: time.Now()}
	select {
	case c.bus.ussd <- event:
	default:
		c.logger.Debug("dropping ussd event", "text", msg.Text, "request", msg.Request, "notify", msg.Notify, "final", msg.Final)
	}
}

func (c *Client) emitState(state RegistrationState) {
	select {
	case c.bus.state <- state:
	default:
		c.logger.Debug("dropping state event", "state", state)
	}
}

func (c *Client) emitError(err error) {
	select {
	case c.bus.errors <- err:
	default:
		c.logger.Debug("dropping error event", "err", err)
	}
}
