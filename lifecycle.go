package vowifi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/damonto/vowifi-go/ims/registration"
	imssession "github.com/damonto/vowifi-go/ims/session"
	imssms "github.com/damonto/vowifi-go/ims/sms"
	imsussd "github.com/damonto/vowifi-go/ims/ussd"
	imsvoice "github.com/damonto/vowifi-go/ims/voice"
	swutransport "github.com/damonto/vowifi-go/swu/transport"
	swutunnel "github.com/damonto/vowifi-go/swu/tunnel"
	"github.com/damonto/vowifi-go/usim"
)

type activeConn struct {
	runCtx     context.Context
	cancel     context.CancelFunc
	session    *swutunnel.Session
	imsSession *imssession.Session
	reg        *registration.Service
	sms        *imssms.Service
	ussd       *imsussd.Service
	voice      *imsvoice.Service
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
	voice      *imsvoice.Service
}

type tunnelDatagramTransport struct {
	session *swutunnel.Session
}

func (t tunnelDatagramTransport) LocalAddr() net.Addr {
	return t.session.LocalAddr()
}

func (t tunnelDatagramTransport) RemoteAddr() net.Addr {
	return t.session.RemoteAddr()
}

func (t tunnelDatagramTransport) WritePacket(ctx context.Context, data []byte) error {
	return t.session.WritePacket(ctx, data)
}

func (t tunnelDatagramTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	return t.session.ReadPacket(ctx)
}

func (t tunnelDatagramTransport) Close() error {
	return nil
}

const defaultCloseTimeout = 5 * time.Second
const defaultReconnectDelay = 3 * time.Second
const defaultReconnectMaxDelay = time.Minute
const defaultIMSRegistrationRetryBase = 120 * time.Second
const defaultIMSRegistrationRetryMax = 300 * time.Second

var reconnectAttemptTimeout = 30 * time.Second

func (c *Client) Connect(ctx context.Context) error {
	done, ok := c.reserveCloseTask()
	if !ok {
		return fmt.Errorf("connecting client: %w", ErrClientClosed)
	}

	c.logger.Info("connecting client")
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
		c.recordSWUBackoff(err, time.Now())
		c.emitConnectFailure(ctx, err)
		return nil, err
	}
	c.clearCurrentSWUBackoff()

	if err := c.openIMSRuntime(setup, tunnelInfo); err != nil {
		c.emitConnectFailure(ctx, err)
		return nil, err
	}

	active, err := c.commitConnect(setup)
	if err != nil {
		c.emitConnectFailure(ctx, err)
		return nil, err
	}

	c.logger.Info("IMS registered")
	c.emitState(StateRegistered)
	return active, nil
}

func (c *Client) openIMSRuntime(setup *connectSetup, tunnelInfo swutunnel.Info) error {
	transport, err := c.buildIMSTransport(setup, tunnelInfo)
	if err != nil {
		return err
	}

	imsSession, err := imssession.Open(imssession.Config{
		Transport:         setup.imsCfg.Transport,
		Logger:            c.cfg.Logger,
		TransactionTimers: setup.imsCfg.SIPTimers,
	}, transport)
	if err != nil {
		return fmt.Errorf("opening IMS session: %w", err)
	}
	setup.imsSession = imsSession

	reg, err := registration.New(c.buildRegistrationConfig(setup.imsCfg), imsSession, c.card)
	if err != nil {
		return fmt.Errorf("creating registration service: %w", err)
	}
	setup.reg = reg

	c.logger.Info("registering IMS")
	if err := reg.Establish(setup.setupCtx); err != nil {
		return fmt.Errorf("establishing IMS registration: %w", err)
	}
	if err := reg.Subscribe(setup.setupCtx); err != nil {
		return fmt.Errorf("subscribing IMS registration: %w", err)
	}

	sms, err := imssms.New(imssms.Config{
		ServiceCenter:         setup.imsCfg.ServiceCenter,
		SubmitReportTimeout:   setup.imsCfg.SMSSubmitReportTimeout,
		DeliveryReportTimeout: setup.imsCfg.SMSDeliveryReportTimeout,
		RequestStatusReport:   c.cfg.smsRequestStatusReport,
		OnIncoming:            c.handleSMS,
		OnStatusReport:        c.handleSMSStatusReport,
		OnError:               c.emitError,
		Logger:                c.cfg.Logger,
	}, imsSession, reg, c.card)
	if err != nil {
		return fmt.Errorf("creating SMS service: %w", err)
	}
	setup.sms = sms

	ussd, err := imsussd.New(imsussd.Config{
		Language:           setup.imsCfg.USSDLanguage,
		PhoneContextDomain: setup.imsCfg.PhoneContextDomain,
		OnIncoming:         c.handleUSSD,
		Logger:             c.cfg.Logger,
	}, imsSession, reg)
	if err != nil {
		return fmt.Errorf("creating USSD service: %w", err)
	}
	setup.ussd = ussd

	voiceCfg := setup.imsCfg.Voice
	if voiceCfg.PrepareMedia == nil {
		voiceCfg.PrepareMedia = openMediaTransport(setup.session)
	}
	if voiceCfg.OpenMedia == nil {
		voiceCfg.OpenMedia = openMediaTransport(setup.session)
	}
	voiceCfg.OnIncomingCall = c.handleIncomingVoice
	voiceCfg.OnCallEvent = c.handleVoiceEvent
	voiceCfg.OnError = c.emitError
	voiceCfg.Logger = c.cfg.Logger
	voice, err := imsvoice.New(voiceCfg, imsSession, reg)
	if err != nil {
		return fmt.Errorf("creating voice service: %w", err)
	}
	setup.voice = voice
	return nil
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

	if err := c.ensureReady(setupCtx); err != nil {
		setupStop()
		c.finishConnectAttempt()
		return nil, err
	}
	if err := c.waitSWUBackoff(setupCtx); err != nil {
		setupStop()
		c.finishConnectAttempt()
		return nil, err
	}

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

func (c *Client) ensureReady(ctx context.Context) error {
	c.mu.Lock()
	if c.card != nil {
		c.mu.Unlock()
		return nil
	}
	reader := c.reader
	cfg := c.cfg
	c.mu.Unlock()

	card, err := usim.Load(ctx, reader, cfg.Logger)
	if err != nil {
		return fmt.Errorf("loading USIM: %w", err)
	}
	normalized, err := cfg.normalized(card)
	if err != nil {
		return fmt.Errorf("normalizing client config: %w", err)
	}
	if err := c.checkWFCEntitlement(ctx, &normalized, card); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return fmt.Errorf("connecting client: %w", ErrClientClosed)
	}
	if c.card == nil {
		c.card = card
		c.cfg = normalized
		c.logger = normalized.Logger.With("component", "vowifi-go")
	}
	return nil
}

func (c *Client) openTunnel(setup *connectSetup) (swutunnel.Info, error) {
	session, err := swutunnel.Dial(setup.setupCtx, setup.tunnelCfg)
	if err != nil {
		return swutunnel.Info{}, fmt.Errorf("dialing tunnel: %w", err)
	}
	setup.session = session

	c.emitState(StateAuthenticating)
	c.logger.Info("connecting SWu tunnel", "tunnel_remote_addr", setup.tunnelCfg.RemoteAddr)

	if err := session.Connect(setup.setupCtx, c.cfg.Terminal.ID, c.card); err != nil {
		return swutunnel.Info{}, fmt.Errorf("connecting swu: %w", err)
	}
	tunnelInfo := session.Info()
	c.logger.Info("SWu tunnel established", "inner_ip", tunnelInfo.InnerIP, "pcscf_ip", tunnelInfo.PCSCFIP, "pcscf_ips", tunnelInfo.PCSCFIPs, "esp_initiator_spi", tunnelInfo.ESPInitiatorSPI, "esp_responder_spi", tunnelInfo.ESPResponderSPI)
	return tunnelInfo, nil
}

func (c *Client) buildIMSTransport(setup *connectSetup, tunnelInfo swutunnel.Info) (imssession.Transport, error) {
	setup.imsCfg.dialSecureTCP = nil
	setup.imsCfg.dialSecureUDP = nil
	setup.imsCfg.listenSecureTCP = nil
	setup.imsCfg.listenSecureUDP = nil

	pcscfIPs := pcscfCandidateIPs(tunnelInfo)
	selectedPCSCF := firstPCSCFIP(pcscfIPs)
	associations := swutransport.NewSecurityAssociations()
	var transport imssession.Transport = tunnelDatagramTransport{session: setup.session}
	if setup.imsCfg.Transport != "tcp" {
		setup.imsCfg.dialSecureUDP = func(ctx context.Context, cfg imssession.SecureUDPConfig) (imssession.Transport, error) {
			return swutransport.DialSecureUDP(ctx, setup.session, swutransport.SecureUDPConfig{
				TCPConfig: swutransport.TCPConfig{
					LocalPort:  cfg.LocalPort,
					RemotePort: cfg.RemotePort,
					RemoteIP:   selectedPCSCF,
				},
				OutboundSPI:   cfg.OutboundSPI,
				InboundSPI:    cfg.InboundSPI,
				Encryption:    cfg.Encryption,
				EncryptionKey: cfg.EncryptionKey,
				Integrity:     cfg.Integrity,
				IntegrityKey:  cfg.IntegrityKey,
				Associations:  associations,
			})
		}
		setup.imsCfg.listenSecureUDP = func(ctx context.Context, cfg imssession.SecureUDPConfig) (imssession.Transport, error) {
			_ = ctx
			return swutransport.ListenSecureUDP(setup.session, swutransport.SecureUDPConfig{
				TCPConfig: swutransport.TCPConfig{
					LocalPort:  cfg.LocalPort,
					RemotePort: cfg.RemotePort,
					RemoteIP:   selectedPCSCF,
				},
				OutboundSPI:   cfg.OutboundSPI,
				InboundSPI:    cfg.InboundSPI,
				Encryption:    cfg.Encryption,
				EncryptionKey: cfg.EncryptionKey,
				Integrity:     cfg.Integrity,
				IntegrityKey:  cfg.IntegrityKey,
				Associations:  associations,
			})
		}
		return transport, nil
	}

	tcpTransport, selectedIP, err := c.dialPCSCFTCP(setup, pcscfIPs)
	if err != nil {
		return nil, fmt.Errorf("dialing ims tcp transport: %w", err)
	}
	transport = tcpTransport
	selectedPCSCF = selectedIP
	setup.imsCfg.dialSecureTCP = func(ctx context.Context, cfg imssession.SecureTCPConfig) (imssession.Transport, error) {
		return swutransport.DialSecureTCP(ctx, setup.session, swutransport.SecureTCPConfig{
			TCPConfig: swutransport.TCPConfig{
				LocalPort:  cfg.LocalPort,
				RemotePort: cfg.RemotePort,
				RemoteIP:   selectedPCSCF,
			},
			OutboundSPI:   cfg.OutboundSPI,
			InboundSPI:    cfg.InboundSPI,
			Encryption:    cfg.Encryption,
			EncryptionKey: cfg.EncryptionKey,
			Integrity:     cfg.Integrity,
			IntegrityKey:  cfg.IntegrityKey,
			Associations:  associations,
		})
	}
	setup.imsCfg.listenSecureTCP = func(ctx context.Context, cfg imssession.SecureTCPConfig) (imssession.Transport, error) {
		_ = ctx
		return swutransport.ListenSecureTCP(setup.session, swutransport.SecureTCPConfig{
			TCPConfig: swutransport.TCPConfig{
				LocalPort:  cfg.LocalPort,
				RemotePort: cfg.RemotePort,
				RemoteIP:   selectedPCSCF,
			},
			OutboundSPI:   cfg.OutboundSPI,
			InboundSPI:    cfg.InboundSPI,
			Encryption:    cfg.Encryption,
			EncryptionKey: cfg.EncryptionKey,
			Integrity:     cfg.Integrity,
			IntegrityKey:  cfg.IntegrityKey,
			Associations:  associations,
		})
	}
	setup.imsCfg.listenSecureUDP = func(ctx context.Context, cfg imssession.SecureUDPConfig) (imssession.Transport, error) {
		_ = ctx
		return swutransport.ListenSecureUDP(setup.session, swutransport.SecureUDPConfig{
			TCPConfig: swutransport.TCPConfig{
				LocalPort:  cfg.LocalPort,
				RemotePort: cfg.RemotePort,
				RemoteIP:   selectedPCSCF,
			},
			OutboundSPI:   cfg.OutboundSPI,
			InboundSPI:    cfg.InboundSPI,
			Encryption:    cfg.Encryption,
			EncryptionKey: cfg.EncryptionKey,
			Integrity:     cfg.Integrity,
			IntegrityKey:  cfg.IntegrityKey,
			Associations:  associations,
		})
	}
	return transport, nil
}

func (c *Client) dialPCSCFTCP(setup *connectSetup, pcscfIPs []net.IP) (*swutransport.TCPConn, net.IP, error) {
	candidates := pcscfIPs
	if len(candidates) == 0 {
		candidates = []net.IP{nil}
	}
	var errs error
	for _, ip := range candidates {
		tcpTransport, err := swutransport.DialTCP(setup.setupCtx, setup.session, swutransport.TCPConfig{
			RemotePort: setup.tunnelCfg.SIPPort,
			RemoteIP:   ip,
		})
		if err == nil {
			return tcpTransport, tcpRemoteIP(tcpTransport), nil
		}
		errs = errors.Join(errs, fmt.Errorf("dialing P-CSCF %s: %w", ipLabel(ip), err))
	}
	return nil, nil, errs
}

func pcscfCandidateIPs(info swutunnel.Info) []net.IP {
	candidates := info.PCSCFIPs
	if len(candidates) == 0 && len(info.PCSCFIP) != 0 {
		candidates = []net.IP{append(net.IP(nil), info.PCSCFIP...)}
	}
	return uniqueIPs(candidates)
}

func firstPCSCFIP(ips []net.IP) net.IP {
	if len(ips) == 0 {
		return nil
	}
	return append(net.IP(nil), ips[0]...)
}

func tcpRemoteIP(conn *swutransport.TCPConn) net.IP {
	remote := conn.RemoteAddr().(*net.TCPAddr)
	return append(net.IP(nil), remote.IP...)
}

func uniqueIPs(ips []net.IP) []net.IP {
	unique := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if len(ip) == 0 {
			continue
		}
		seen := false
		for _, existing := range unique {
			if existing.Equal(ip) {
				seen = true
				break
			}
		}
		if !seen {
			unique = append(unique, append(net.IP(nil), ip...))
		}
	}
	return unique
}

func ipLabel(ip net.IP) string {
	if len(ip) == 0 {
		return "default"
	}
	return ip.String()
}

func (c *Client) buildRegistrationConfig(cfg IMSConfig) registration.Config {
	return registration.Config{
		PrivateIdentity:         cfg.PrivateIdentity,
		PublicIdentity:          cfg.PublicIdentity,
		HomeDomain:              cfg.HomeDomain,
		UserAgent:               cfg.UserAgent,
		AccessNetworkInfo:       cfg.AccessNetworkInfo,
		WLANNodeID:              cfg.WLANNodeID,
		RegisterExpires:         cfg.RegisterExpires,
		IMEI:                    cfg.IMEI,
		AuthAlgorithm:           cfg.AuthAlgorithm,
		GeolocationPIDFRegister: cfg.GeolocationPIDFRegister,
		GeolocationCountry:      cfg.GeolocationCountry,
		UseTelURIForPIDFXML:     cfg.UseTelURIForPIDFXML,
		Logger:                  c.cfg.Logger,
		DialSecureTCP:           cfg.dialSecureTCP,
		DialSecureUDP:           cfg.dialSecureUDP,
		ListenSecureTCP:         cfg.listenSecureTCP,
		ListenSecureUDP:         cfg.listenSecureUDP,
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
		voice:      setup.voice,
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
	setup.voice = nil
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
	if s.voice != nil {
		_ = s.voice.Close()
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
		err := runActiveIMS(active)
		if err == nil || active.runCtx.Err() != nil {
			return
		}

		if swutunnel.PCSCFReselectionRequested(err) {
			next, restoreErr := c.restoreIMSAfterPCSCFReselection(active, err)
			if restoreErr == nil {
				c.logger.Info("IMS restored after P-CSCF reselection")
				active = next
				continue
			}
			err = fmt.Errorf("restoring IMS after P-CSCF reselection: %w", restoreErr)
		}

		active.cancel()
		if !c.detachActive(active) {
			return
		}

		closeCtx, cancel := context.WithTimeout(context.Background(), defaultCloseTimeout)
		_ = c.closeActiveRuntime(closeCtx, active)
		cancel()
		c.emitError(fmt.Errorf("running IMS loop: %w", err))
		c.emitState(StateFailed)

		if !c.startReconnect() {
			return
		}
		c.logger.Info("reconnecting client", "cause", err)
		next, reconnectErr := c.reconnectFn(err)
		c.finishReconnect()
		if reconnectErr != nil {
			if !errors.Is(reconnectErr, context.Canceled) {
				c.logger.Error("reconnecting client", "err", reconnectErr)
			}
			return
		}
		c.logger.Info("client reconnected")
		active = next
	}
}

func (c *Client) restoreIMSAfterPCSCFReselection(active *activeConn, cause error) (*activeConn, error) {
	if active.session == nil {
		return nil, errors.New("restoring IMS after P-CSCF reselection: session is missing")
	}
	tunnelInfo, ok := swutunnel.PCSCFReselectionInfo(cause)
	if !ok {
		tunnelInfo = active.session.Info()
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), defaultCloseTimeout)
	closeErr := c.closeIMSRuntime(closeCtx, active)
	closeCancel()
	if closeErr != nil {
		return nil, closeErr
	}

	setupCtx, setupStop := c.newIMSRestoreContext(active.runCtx)
	defer setupStop()

	tunnelCfg := c.cfg.Tunnel
	tunnelCfg.RemoteAddr = c.cfg.EPDG
	tunnelCfg, err := tunnelCfg.Normalized()
	if err != nil {
		return nil, fmt.Errorf("normalizing tunnel config: %w", err)
	}
	imsCfg, err := c.cfg.IMS.Normalized()
	if err != nil {
		return nil, fmt.Errorf("normalizing IMS config: %w", err)
	}

	setup := &connectSetup{
		setupCtx:  setupCtx,
		setupStop: setupStop,
		runCtx:    active.runCtx,
		cancel:    active.cancel,
		tunnelCfg: tunnelCfg,
		imsCfg:    imsCfg,
		session:   active.session,
	}
	if err := c.openIMSRuntime(setup, tunnelInfo); err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), defaultCloseTimeout)
		_ = setup.closeIMSRuntime(ctx)
		cancel()
		return nil, err
	}
	if err := c.commitIMSRestore(active, setup); err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), defaultCloseTimeout)
		_ = setup.closeIMSRuntime(ctx)
		cancel()
		return nil, err
	}
	c.emitState(StateRegistered)
	return active, nil
}

func (c *Client) commitIMSRestore(active *activeConn, setup *connectSetup) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return fmt.Errorf("connecting client: %w", ErrClientClosed)
	}
	if c.active != active {
		return errors.New("restoring IMS after P-CSCF reselection: active connection changed")
	}
	active.imsSession = setup.imsSession
	active.reg = setup.reg
	active.sms = setup.sms
	active.ussd = setup.ussd
	active.voice = setup.voice
	setup.imsSession = nil
	setup.reg = nil
	setup.sms = nil
	setup.ussd = nil
	setup.voice = nil
	c.ussdSessions = make(map[*imsussd.Session]*Session)
	return nil
}

func (c *Client) newIMSRestoreContext(parent context.Context) (context.Context, context.CancelFunc) {
	setupCtx, setupCancel := context.WithCancel(parent)
	stopLifecycle := context.AfterFunc(c.lifecycleCtx, setupCancel)
	stop := func() {
		stopLifecycle()
		setupCancel()
	}
	if reconnectAttemptTimeout <= 0 {
		return setupCtx, stop
	}
	timeoutCtx, timeoutCancel := context.WithTimeout(setupCtx, reconnectAttemptTimeout)
	return timeoutCtx, func() {
		timeoutCancel()
		stop()
	}
}

type imsRuntimeResult struct {
	action string
	err    error
}

func runActiveIMS(active *activeConn) error {
	runCtx, cancel := context.WithCancel(active.runCtx)
	defer cancel()

	results := make(chan imsRuntimeResult, 2)
	go func() {
		results <- imsRuntimeResult{action: "running IMS session", err: active.imsSession.Run(runCtx)}
	}()
	go func() {
		results <- imsRuntimeResult{action: "maintaining IMS registration", err: active.reg.Maintain(runCtx)}
	}()

	first := <-results
	cancel()
	second := <-results

	for _, result := range []imsRuntimeResult{first, second} {
		if result.err != nil && !errors.Is(result.err, context.Canceled) {
			return fmt.Errorf("%s: %w", result.action, result.err)
		}
	}
	return nil
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

func (c *Client) reconnect(cause error) (*activeConn, error) {
	c.recordSWUBackoff(cause, time.Now())
	if terminalReconnectError(cause) {
		return nil, cause
	}
	backoff := newReconnectBackoff(c.cfg.ReconnectDelay, c.cfg.ReconnectMaxDelay)
	registrationBackoff := newReconnectBackoff(c.cfg.IMS.RegistrationRetryBase, c.cfg.IMS.RegistrationRetryMax)
	if err := sleepContext(c.lifecycleCtx, c.reconnectDelay(cause, backoff, registrationBackoff)); err != nil {
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
		if terminalReconnectError(err) {
			return nil, err
		}
		nextDelay := c.reconnectDelay(err, backoff, registrationBackoff)
		c.logger.Warn("reconnect attempt", "err", err, "next_delay", nextDelay)
		if err := sleepContext(c.lifecycleCtx, nextDelay); err != nil {
			return nil, err
		}
	}
}

func terminalReconnectError(err error) bool {
	return swutunnel.AccessRejected(err) || swutunnel.BackoffDeactivated(err) || errors.Is(err, errSWUBackoffDeactivated)
}

func (c *Client) reconnectDelay(err error, backoff, registrationBackoff *reconnectBackoff) time.Duration {
	if swutunnel.ReactivationRequested(err) || swutunnel.PCSCFReselectionRequested(err) {
		return 0
	}
	if registration.InitialRegistrationRequired(err) {
		delay := registrationBackoff.Next()
		if retryAfter, ok := registration.RetryAfterDelay(err); ok {
			delay = max(delay, retryAfter)
		}
		if tunnelBackoff, ok := swutunnel.BackoffDelay(err); ok {
			delay = max(delay, tunnelBackoff)
		}
		return delay
	}
	delay := backoff.Next()
	if retryAfter, ok := registration.RetryAfterDelay(err); ok {
		delay = max(delay, retryAfter)
	}
	if tunnelBackoff, ok := swutunnel.BackoffDelay(err); ok {
		delay = max(delay, tunnelBackoff)
	}
	return delay
}

type reconnectBackoff struct {
	next time.Duration
	max  time.Duration
}

func newReconnectBackoff(first, maxDelay time.Duration) *reconnectBackoff {
	return &reconnectBackoff{next: first, max: maxDelay}
}

func (b *reconnectBackoff) Next() time.Duration {
	delay := b.next
	if delay <= 0 {
		return 0
	}
	next := delay * 2
	if next < delay || next > b.max {
		next = b.max
	}
	b.next = next
	return delay
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
		reader := c.reader
		c.active = nil
		c.reader = nil
		c.mu.Unlock()

		if c.lifecycleCancel != nil {
			c.lifecycleCancel()
		}
		if active != nil && active.cancel != nil {
			active.cancel()
		}
		if c.waitCloseTasks(ctx) {
			err = errors.Join(err, c.closeActive(ctx, active))
		} else {
			err = errors.Join(err, ctx.Err())
			err = errors.Join(err, c.closeActiveRuntime(ctx, active))
			if active != nil && active.session != nil {
				err = errors.Join(err, wrapCloseError("closing session", normalizeCloseError(active.session.CloseContext(ctx))))
			}
		}
		if reader != nil {
			err = errors.Join(err, wrapCloseError("closing reader", reader.Close()))
		}
		if err != nil {
			c.logger.Error("closing client", "err", err)
		}
		c.emitState(StateClosed)
		c.events.close()
	})
	return err
}

func (c *Client) waitCloseTasks(ctx context.Context) bool {
	done := make(chan struct{})
	go func() {
		c.closeWG.Wait()
		close(done)
	}()

	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
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
	if active.voice != nil {
		err = errors.Join(err, wrapCloseError("closing voice service", active.voice.Close()))
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
	err := c.closeIMSRuntime(ctx, active)
	if active.session != nil {
		err = errors.Join(err, wrapCloseError("closing session", normalizeCloseError(active.session.CloseContext(ctx))))
	}
	return err
}

func (c *Client) closeIMSRuntime(ctx context.Context, active *activeConn) error {
	c.clearUSSDSessionBindings()

	var err error
	if active.ussd != nil {
		active.ussd.Abort()
	}
	if active.voice != nil {
		err = errors.Join(err, wrapCloseError("closing voice service", active.voice.Close()))
	}
	if active.sms != nil {
		err = errors.Join(err, wrapCloseError("closing SMS service", active.sms.Close()))
	}
	if active.reg != nil {
		active.reg.Abort()
	}
	if active.imsSession != nil {
		err = errors.Join(err, wrapCloseError("closing IMS session", normalizeCloseError(active.imsSession.CloseContext(ctx))))
	}
	return err
}

func (s *connectSetup) closeIMSRuntime(ctx context.Context) error {
	var err error
	if s.ussd != nil {
		s.ussd.Abort()
	}
	if s.voice != nil {
		err = errors.Join(err, wrapCloseError("closing voice service", s.voice.Close()))
	}
	if s.sms != nil {
		err = errors.Join(err, wrapCloseError("closing SMS service", s.sms.Close()))
	}
	if s.reg != nil {
		s.reg.Abort()
	}
	if s.imsSession != nil {
		err = errors.Join(err, wrapCloseError("closing IMS session", normalizeCloseError(s.imsSession.CloseContext(ctx))))
	}
	return err
}
