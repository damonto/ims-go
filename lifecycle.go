package imsclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/damonto/ims-client/ims/registration"
	imssession "github.com/damonto/ims-client/ims/session"
	imssms "github.com/damonto/ims-client/ims/sms"
	imsussd "github.com/damonto/ims-client/ims/ussd"
	swutransport "github.com/damonto/ims-client/swu/transport"
	swutunnel "github.com/damonto/ims-client/swu/tunnel"
)

type activeConn struct {
	runCtx     context.Context
	cancel     context.CancelFunc
	session    *swutunnel.Session
	imsSession *imssession.Session
	reg        *registration.Service
	sms        *imssms.Service
	ussd       *imsussd.Service
}

type connectSetup struct {
	client     *Client
	setupCtx   context.Context
	setupStop  context.CancelFunc
	runCtx     context.Context
	cancel     context.CancelFunc
	tunnelCfg  swutunnel.Config
	imsCfg     IMSConfig
	session    *swutunnel.Session
	imsSession *imssession.Session
	reg        *registration.Service
	sms        *imssms.Service
	ussd       *imsussd.Service
}

type cardCloser interface {
	io.Closer
}

const defaultCloseTimeout = 5 * time.Second
const defaultReconnectDelay = 3 * time.Second

var reconnectAttemptTimeout = 30 * time.Second

func (c *Client) Connect(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	done, ok := c.reserveCloseTask()
	if !ok {
		return fmt.Errorf("connecting client: %w", ErrClientClosed)
	}

	active, err := c.connectOnce(ctx, false)
	if err != nil {
		done()
		return err
	}

	runDone := c.startIMSRunner(active, done)
	if err := active.imsSession.WaitStarted(ctx); err != nil {
		wrapped := fmt.Errorf("connecting client: waiting for IMS session start: %w", err)
		c.abortConnectStart(active, runDone)
		c.emitConnectFailure(ctx, wrapped)
		return wrapped
	}
	return nil
}

func (c *Client) Tunnel() swutunnel.Info {
	c.mu.Lock()
	active := c.active
	c.mu.Unlock()
	if active == nil || active.session == nil {
		return swutunnel.Info{}
	}
	return active.session.Info()
}

func (c *Client) connectOnce(ctx context.Context, internal bool) (*activeConn, error) {
	setup, err := c.prepareConnect(ctx, internal)
	if err != nil {
		return nil, err
	}
	defer setup.rollback()

	c.emitState(StateConnecting)
	tunnelInfo, err := c.openTunnel(setup)
	if err != nil {
		c.emitConnectFailure(ctx, err)
		return nil, err
	}

	transport, err := c.buildIMSTransport(setup, tunnelInfo)
	if err != nil {
		c.emitConnectFailure(ctx, err)
		return nil, err
	}

	imsSession, err := imssession.Open(imssession.Config{
		Transport: setup.imsCfg.Transport,
		Logger:    c.logger,
	}, transport)
	if err != nil {
		wrapped := fmt.Errorf("opening IMS session: %w", err)
		c.emitConnectFailure(ctx, wrapped)
		return nil, wrapped
	}
	setup.imsSession = imsSession

	reg, err := registration.New(c.buildRegistrationConfig(setup.imsCfg), imsSession, c.card)
	if err != nil {
		wrapped := fmt.Errorf("creating registration service: %w", err)
		c.emitConnectFailure(ctx, wrapped)
		return nil, wrapped
	}
	setup.reg = reg

	c.logger.Debug("registering IMS")
	if err := reg.Establish(setup.setupCtx); err != nil {
		wrapped := fmt.Errorf("establishing IMS registration: %w", err)
		c.emitConnectFailure(ctx, wrapped)
		return nil, wrapped
	}

	sms, err := imssms.New(imssms.Config{
		ServiceCenter:  setup.imsCfg.ServiceCenter,
		OnIncoming:     c.handleSMS,
		OnStatusReport: c.handleSMSStatusReport,
		OnError:        c.emitError,
	}, imsSession, reg, c.card)
	if err != nil {
		wrapped := fmt.Errorf("creating SMS service: %w", err)
		c.emitConnectFailure(ctx, wrapped)
		return nil, wrapped
	}
	setup.sms = sms

	ussd, err := imsussd.New(imsussd.Config{
		Language:   setup.imsCfg.USSDLanguage,
		OnIncoming: c.handleUSSD,
	}, imsSession, reg)
	if err != nil {
		wrapped := fmt.Errorf("creating USSD service: %w", err)
		c.emitConnectFailure(ctx, wrapped)
		return nil, wrapped
	}
	setup.ussd = ussd

	active, err := c.commitConnect(setup)
	if err != nil {
		c.emitConnectFailure(ctx, err)
		return nil, err
	}

	c.logger.Debug("ims registered")
	c.emitState(StateRegistered)
	return active, nil
}

func (c *Client) prepareConnect(ctx context.Context, internal bool) (*connectSetup, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, fmt.Errorf("connecting client: %w", ErrClientClosed)
	}
	if c.active != nil {
		c.mu.Unlock()
		return nil, errors.New("connecting client: already connected")
	}
	if c.connecting || (!internal && c.reconnecting) {
		c.mu.Unlock()
		return nil, errors.New("connecting client: connection in progress")
	}
	c.connecting = true
	c.mu.Unlock()

	setupCtx, setupStop := c.newSetupContext(ctx, internal)

	// The setup context may time out, but a successful registration should keep running
	// until the client is closed or the active connection is canceled.
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))

	tunnelCfg := c.cfg.Tunnel
	tunnelCfg.RemoteAddr = c.cfg.EPDG

	tunnelCfg, err := tunnelCfg.Normalized()
	if err != nil {
		if setupStop != nil {
			setupStop()
		}
		cancel()
		c.finishConnectAttempt()
		return nil, fmt.Errorf("preparing connect: %w", err)
	}
	if tunnelCfg.RemoteAddr == "" {
		if setupStop != nil {
			setupStop()
		}
		cancel()
		c.finishConnectAttempt()
		return nil, errors.New("preparing connect: tunnel remote address is empty")
	}

	imsCfg := c.cfg.IMS
	imsCfg, err = imsCfg.Normalized()
	if err != nil {
		if setupStop != nil {
			setupStop()
		}
		cancel()
		c.finishConnectAttempt()
		return nil, fmt.Errorf("preparing connect: %w", err)
	}

	return &connectSetup{
		client:    c,
		setupCtx:  setupCtx,
		setupStop: setupStop,
		runCtx:    runCtx,
		cancel:    cancel,
		tunnelCfg: tunnelCfg,
		imsCfg:    imsCfg,
	}, nil
}

func (c *Client) openTunnel(setup *connectSetup) (swutunnel.Info, error) {
	session, err := swutunnel.Dial(setup.setupCtx, setup.tunnelCfg)
	if err != nil {
		return swutunnel.Info{}, fmt.Errorf("dialing tunnel: %w", err)
	}
	setup.session = session

	c.emitState(StateAuthenticating)
	c.logger.Debug("starting client connection", "tunnel_remote_addr", setup.tunnelCfg.RemoteAddr)

	if err := session.Connect(setup.setupCtx, c.cfg.IMEI, c.card); err != nil {
		return swutunnel.Info{}, fmt.Errorf("connecting swu: %w", err)
	}
	tunnelInfo := session.Info()
	c.logger.Debug("swu tunnel established", "inner_ip", tunnelInfo.InnerIP, "pcscf_ip", tunnelInfo.PCSCFIP, "esp_initiator_spi", tunnelInfo.ESPInitiatorSPI, "esp_responder_spi", tunnelInfo.ESPResponderSPI)
	return tunnelInfo, nil
}

func (c *Client) buildIMSTransport(setup *connectSetup, _ swutunnel.Info) (imssession.Transport, error) {
	setup.imsCfg.dialSecureTCP = nil
	setup.imsCfg.listenSecureTCP = nil
	setup.imsCfg.listenSecureUDP = nil

	var transport imssession.Transport = setup.session
	if setup.imsCfg.Transport != "tcp" {
		return transport, nil
	}

	tcpTransport, err := swutransport.DialTCP(setup.setupCtx, setup.session, swutransport.TCPConfig{
		LocalPort:  setup.tunnelCfg.LocalSIPPort,
		RemotePort: setup.tunnelCfg.SIPPort,
	})
	if err != nil {
		return nil, fmt.Errorf("dialing ims tcp transport: %w", err)
	}
	transport = tcpTransport
	setup.imsCfg.dialSecureTCP = func(ctx context.Context, cfg imssession.SecureTCPConfig) (imssession.Transport, error) {
		return swutransport.DialSecureTCP(ctx, setup.session, swutransport.SecureTCPConfig{
			TCPConfig: swutransport.TCPConfig{
				LocalPort:  cfg.LocalPort,
				RemotePort: cfg.RemotePort,
			},
			OutboundSPI:  cfg.OutboundSPI,
			InboundSPI:   cfg.InboundSPI,
			Integrity:    cfg.Integrity,
			IntegrityKey: cfg.IntegrityKey,
		})
	}
	setup.imsCfg.listenSecureTCP = func(ctx context.Context, cfg imssession.SecureTCPConfig) (imssession.Transport, error) {
		_ = ctx
		return swutransport.ListenSecureTCP(setup.session, swutransport.SecureTCPConfig{
			TCPConfig: swutransport.TCPConfig{
				LocalPort:  cfg.LocalPort,
				RemotePort: cfg.RemotePort,
			},
			OutboundSPI:  cfg.OutboundSPI,
			InboundSPI:   cfg.InboundSPI,
			Integrity:    cfg.Integrity,
			IntegrityKey: cfg.IntegrityKey,
		})
	}
	setup.imsCfg.listenSecureUDP = func(ctx context.Context, cfg imssession.SecureUDPConfig) (imssession.Transport, error) {
		_ = ctx
		return swutransport.ListenSecureUDP(setup.session, swutransport.SecureUDPConfig{
			TCPConfig: swutransport.TCPConfig{
				LocalPort:  cfg.LocalPort,
				RemotePort: cfg.RemotePort,
			},
			OutboundSPI:  cfg.OutboundSPI,
			InboundSPI:   cfg.InboundSPI,
			Integrity:    cfg.Integrity,
			IntegrityKey: cfg.IntegrityKey,
		})
	}
	return transport, nil
}

func (c *Client) buildRegistrationConfig(cfg IMSConfig) registration.Config {
	return registration.Config{
		PublicIdentity:    cfg.PublicIdentity,
		HomeDomain:        cfg.HomeDomain,
		Country:           cfg.Country,
		UserAgent:         cfg.UserAgent,
		AccessNetworkInfo: cfg.AccessNetworkInfo,
		WLANNodeID:        cfg.WLANNodeID,
		RegisterExpires:   cfg.RegisterExpires,
		IMEI:              cfg.IMEI,
		DialSecureTCP:     cfg.dialSecureTCP,
		ListenSecureTCP:   cfg.listenSecureTCP,
		ListenSecureUDP:   cfg.listenSecureUDP,
	}
}

func (c *Client) commitConnect(setup *connectSetup) (*activeConn, error) {
	active := &activeConn{
		runCtx:     setup.runCtx,
		cancel:     setup.cancel,
		session:    setup.session,
		imsSession: setup.imsSession,
		reg:        setup.reg,
		sms:        setup.sms,
		ussd:       setup.ussd,
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("connecting client: client closed during setup")
	}
	if c.active != nil {
		return nil, errors.New("connecting client: already connected")
	}
	c.active = active
	c.connecting = false
	c.ussdSessions = make(map[*imsussd.Session]*Session)
	if setup.setupStop != nil {
		setup.setupStop()
		setup.setupStop = nil
	}
	setup.client = nil
	setup.cancel = nil
	setup.session = nil
	setup.imsSession = nil
	setup.reg = nil
	setup.sms = nil
	setup.ussd = nil
	return active, nil
}

func (s *connectSetup) rollback() {
	if s.client != nil {
		s.client.finishConnectAttempt()
	}
	if s.setupStop != nil {
		s.setupStop()
	}
	if s.cancel == nil {
		return
	}
	s.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), defaultCloseTimeout)
	defer cancel()
	if s.ussd != nil {
		_ = s.ussd.CloseContext(ctx)
	}
	if s.sms != nil {
		_ = s.sms.Close()
	}
	if s.reg != nil {
		_ = s.reg.CloseContext(ctx)
	}
	if s.imsSession != nil {
		_ = s.imsSession.CloseContext(ctx)
	}
	if s.session != nil {
		_ = s.session.CloseContext(ctx)
	}
}

func (c *Client) finishConnectAttempt() {
	c.mu.Lock()
	c.connecting = false
	c.mu.Unlock()
}

func (c *Client) reserveCloseTask() (func(), bool) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, false
	}
	c.closeWG.Add(1)
	c.mu.Unlock()
	return func() {
		c.closeWG.Done()
	}, true
}

func (c *Client) newSetupContext(ctx context.Context, internal bool) (context.Context, context.CancelFunc) {
	setupCtx, setupCancel := context.WithCancel(ctx)
	stopLifecycle := context.AfterFunc(c.lifecycleCtx, setupCancel)
	stop := func() {
		stopLifecycle()
		setupCancel()
	}
	if !internal || reconnectAttemptTimeout <= 0 {
		return setupCtx, stop
	}
	timeoutCtx, timeoutCancel := context.WithTimeout(setupCtx, reconnectAttemptTimeout)
	return timeoutCtx, func() {
		timeoutCancel()
		stop()
	}
}

func (c *Client) emitConnectFailure(ctx context.Context, err error) {
	if err == nil || ctx.Err() != nil || c.isClosed() {
		return
	}
	c.emitError(err)
	c.emitState(StateFailed)
}

func (c *Client) abortConnectStart(active *activeConn, runDone <-chan struct{}) {
	if active == nil || active.cancel == nil {
		return
	}
	active.cancel()
	if !c.detachActive(active) {
		return
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), defaultCloseTimeout)
	defer cancel()
	if c.waitIMSRunnerStop(closeCtx, runDone) {
		_ = c.closeActive(closeCtx, active)
		return
	}
	_ = c.closeActiveRuntime(closeCtx, active)
}

func (c *Client) waitIMSRunnerStop(ctx context.Context, runDone <-chan struct{}) bool {
	if runDone == nil {
		return true
	}
	select {
	case <-runDone:
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *Client) runIMS(active *activeConn, done func()) {
	c.runIMSLoop(active, done)
}

func (c *Client) startIMSRunner(active *activeConn, done func()) <-chan struct{} {
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		c.runIMS(active, done)
	}()
	return runDone
}

func (c *Client) runIMSLoop(active *activeConn, done func()) {
	defer done()
	for {
		err := active.imsSession.Run(active.runCtx)
		if err == nil || active.runCtx.Err() != nil {
			return
		}

		active.cancel()
		if !c.detachActive(active) {
			return
		}

		closeCtx, cancel := context.WithTimeout(context.Background(), defaultCloseTimeout)
		_ = c.closeActive(closeCtx, active)
		cancel()
		c.emitError(fmt.Errorf("running IMS loop: %w", err))
		c.emitState(StateFailed)

		if !c.startReconnect() {
			return
		}
		next, reconnectErr := c.reconnect()
		c.finishReconnect()
		if reconnectErr != nil {
			return
		}
		active = next
	}
}

func (c *Client) detachActive(active *activeConn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.active != active {
		return false
	}
	c.active = nil
	return true
}

func (c *Client) startReconnect() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.reconnecting {
		return false
	}
	c.reconnecting = true
	return true
}

func (c *Client) finishReconnect() {
	c.mu.Lock()
	c.reconnecting = false
	c.mu.Unlock()
}

func (c *Client) reconnect() (*activeConn, error) {
	if err := sleepContext(c.lifecycleCtx, c.cfg.ReconnectDelay); err != nil {
		return nil, err
	}
	for {
		active, err := c.connectOnce(c.lifecycleCtx, true)
		if err == nil {
			return active, nil
		}
		if c.lifecycleCtx.Err() != nil {
			return nil, c.lifecycleCtx.Err()
		}
		if err := sleepContext(c.lifecycleCtx, c.cfg.ReconnectDelay); err != nil {
			return nil, err
		}
	}
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) isClosed() bool {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	return closed
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
		c.connecting = false
		c.reconnecting = false
		active := c.active
		card := c.card
		c.active = nil
		c.mu.Unlock()

		if c.lifecycleCancel != nil {
			c.lifecycleCancel()
		}
		if active != nil && active.cancel != nil {
			active.cancel()
		}
		c.closeWG.Wait()
		err = errors.Join(err, c.closeActive(ctx, active))
		if closer, ok := card.(cardCloser); ok {
			err = errors.Join(err, wrapCloseError("closing card", closer.Close()))
		}
		c.emitState(StateClosed)
		c.events.close()
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

func (c *Client) closeActive(ctx context.Context, active *activeConn) error {
	if active == nil {
		return nil
	}
	c.clearUSSDSessionBindings()

	var err error
	if active.ussd != nil {
		err = errors.Join(err, wrapCloseError("closing USSD service", normalizeCloseError(active.ussd.CloseContext(ctx))))
	}
	if active.sms != nil {
		err = errors.Join(err, wrapCloseError("closing SMS service", active.sms.Close()))
	}
	if active.reg != nil {
		err = errors.Join(err, wrapCloseError("closing registration service", normalizeCloseError(active.reg.CloseContext(ctx))))
	}
	if active.imsSession != nil {
		err = errors.Join(err, wrapCloseError("closing IMS session", normalizeCloseError(active.imsSession.CloseContext(ctx))))
	}
	if active.session != nil {
		err = errors.Join(err, wrapCloseError("closing session", normalizeCloseError(active.session.CloseContext(ctx))))
	}
	return err
}

func (c *Client) closeActiveRuntime(ctx context.Context, active *activeConn) error {
	if active == nil {
		return nil
	}
	c.clearUSSDSessionBindings()

	var err error
	if active.sms != nil {
		err = errors.Join(err, wrapCloseError("closing SMS service", active.sms.Close()))
	}
	if active.imsSession != nil {
		err = errors.Join(err, wrapCloseError("closing IMS session", normalizeCloseError(active.imsSession.CloseContext(ctx))))
	}
	if active.session != nil {
		err = errors.Join(err, wrapCloseError("closing session", normalizeCloseError(active.session.CloseContext(ctx))))
	}
	return err
}
