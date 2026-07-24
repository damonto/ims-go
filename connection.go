package ims

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/damonto/ims-go/ims/registration"
	imssession "github.com/damonto/ims-go/ims/session"
	imssms "github.com/damonto/ims-go/ims/sms"
	imsussd "github.com/damonto/ims-go/ims/ussd"
	imsvoice "github.com/damonto/ims-go/ims/voice"
	swutunnel "github.com/damonto/ims-go/swu/tunnel"
	usim "github.com/damonto/wwan-go/sim"
	usimcard "github.com/damonto/wwan-go/sim/card"
)

type connectionScope struct {
	done chan struct{}
	once sync.Once
}

type activeConn struct {
	scope  *connectionScope
	access accessSession
	tunnel *swutunnel.Session
	ims    imsStack
}

type connectSetup struct {
	client    *Client
	setupStop context.CancelFunc
	scope     *connectionScope
	access    accessSession
	tunnelCfg swutunnel.Config
	imsCfg    IMSConfig
	tunnel    *swutunnel.Session
	ims       imsStack
}

type imsStack struct {
	sip   *imssession.Session
	reg   *registration.Registrar
	sms   *imssms.Endpoint
	ussd  *imsussd.Endpoint
	voice *imsvoice.Endpoint
}

const defaultCloseTimeout = 5 * time.Second
const defaultReconnectDelay = 3 * time.Second
const defaultReconnectMaxDelay = time.Minute
const defaultIMSRegistrationRetryBase = 120 * time.Second
const defaultIMSRegistrationRetryMax = 300 * time.Second

var reconnectAttemptTimeout = 30 * time.Second

func newConnectionScope() *connectionScope {
	return &connectionScope{done: make(chan struct{})}
}

func (r *connectionScope) stop() {
	r.once.Do(func() {
		close(r.done)
	})
}

func (r *connectionScope) stopped() bool {
	select {
	case <-r.done:
		return true
	default:
		return false
	}
}

func (r *connectionScope) context() (context.Context, context.CancelFunc) {
	return contextWithStop(context.Background(), r.done)
}

func contextWithStop(parent context.Context, stop <-chan struct{}) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-stop:
			cancel()
		case <-done:
		}
	}()
	return ctx, func() {
		once.Do(func() {
			close(done)
			cancel()
		})
	}
}

func (s *clientState) context(parent context.Context) (context.Context, context.CancelFunc) {
	return contextWithStop(parent, s.done)
}

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

	runDone := c.startConnectionRunner(active, done)
	if err := active.ims.sip.WaitStarted(ctx); err != nil {
		wrapped := fmt.Errorf("connecting client: waiting for IMS session start: %w", err)
		c.cancelConnectStart(active, runDone)
		c.emitConnectFailure(ctx, wrapped)
		return wrapped
	}
	return nil
}

func (c *Client) Tunnel() swutunnel.Info {
	active, err := c.state.currentActive(c.cfg.Terminal.ID)
	if err != nil || active.tunnel == nil {
		return swutunnel.Info{}
	}
	return active.tunnel.Info()
}

func (c *Client) connectOnce(ctx context.Context, internal bool) (_ *activeConn, resultErr error) {
	setup, setupCtx, err := c.prepareConnect(ctx, internal)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := setup.rollback(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("rolling back connection setup: %w", err))
		}
		if resultErr != nil && !internal {
			c.emitConnectFailure(ctx, resultErr)
		}
	}()

	if !internal {
		c.emitStatus(StatusConnecting)
	}
	if err := c.openAccess(setupCtx, setup); err != nil {
		if c.cfg.usesVoWiFi() {
			c.recordSWUBackoff(err, time.Now())
		}
		return nil, err
	}
	if c.cfg.usesVoWiFi() {
		c.clearCurrentSWUBackoff()
	}

	if err := c.openIMSWithPCSCFFailover(setupCtx, setup); err != nil {
		return nil, err
	}

	active, err := c.commitConnect(setup)
	if err != nil {
		return nil, err
	}

	c.logger.Info("IMS registered")
	if !internal {
		c.emitStatus(StatusRegistered)
	}
	return active, nil
}

func (c *Client) openIMSWithPCSCFFailover(ctx context.Context, setup *connectSetup) error {
	reselector, ok := setup.access.(pcscfReselectingAccess)
	if !ok {
		return c.openIMS(ctx, setup)
	}
	return c.openIMSWithPCSCFFailoverAttempts(ctx, setup, reselector, max(reselector.PCSCFCandidateCount(), 1))
}

func (c *Client) openIMSWithPCSCFFailoverAttempts(ctx context.Context, setup *connectSetup, reselector pcscfReselectingAccess, attempts int) error {
	var errs error
	for attempt := range attempts {
		err := c.openIMS(ctx, setup)
		if err == nil {
			return nil
		}
		attemptErr := err
		if attempts > 1 {
			attemptErr = fmt.Errorf("connecting P-CSCF attempt %d: %w", attempt+1, err)
		}
		errs = errors.Join(errs, attemptErr)
		if closeErr := setup.closeIMS(); closeErr != nil {
			return errors.Join(errs, fmt.Errorf("closing failed IMS attempt: %w", closeErr))
		}
		if attempt+1 == attempts || ctx.Err() != nil || !pcscfFailoverRequired(err, setup.imsCfg.SIPTimers.TF) {
			return errs
		}
		if err := reselector.SelectNextPCSCF(); err != nil {
			return errors.Join(errs, err)
		}
	}
	return errs
}

func pcscfFailoverRequired(err error, timerF time.Duration) bool {
	if timerF <= 0 {
		timerF = imssession.DefaultTransactionTimers().TF
	}
	if registration.PCSCFFailoverRequired(err, timerF) ||
		imssession.TransactionTimerExpired(err, "B") ||
		imssession.TransactionTimerExpired(err, "F") ||
		imssession.TransportFailed(err) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (c *Client) prepareConnect(ctx context.Context, internal bool) (*connectSetup, context.Context, error) {
	if err := c.state.reserveConnect(internal); err != nil {
		return nil, nil, fmt.Errorf("connecting client: %w", err)
	}

	setupCtx, setupStop := c.newSetupContext(ctx, internal)

	if err := c.ensureReady(setupCtx); err != nil {
		setupStop()
		c.finishConnectAttempt()
		return nil, nil, err
	}
	if c.cfg.usesVoWiFi() {
		if err := c.waitSWUBackoff(setupCtx); err != nil {
			setupStop()
			c.finishConnectAttempt()
			return nil, nil, err
		}
	}

	scope := newConnectionScope()
	fail := func(err error) (*connectSetup, context.Context, error) {
		setupStop()
		scope.stop()
		c.finishConnectAttempt()
		return nil, nil, err
	}

	imsCfg := c.cfg.IMS
	var tunnelCfg swutunnel.Config
	if c.cfg.usesVoWiFi() {
		tunnelCfg = c.cfg.Access.VoWiFi.Tunnel
		tunnelCfg.RemoteAddr = c.cfg.Access.VoWiFi.EPDG
		c.applySWUPDNTypeRestriction(&tunnelCfg)

		if tunnelCfg.RemoteAddr == "" {
			return fail(errors.New("preparing connect: tunnel remote address is empty"))
		}
	}

	return &connectSetup{
		client:    c,
		setupStop: setupStop,
		scope:     scope,
		tunnelCfg: tunnelCfg,
		imsCfg:    imsCfg,
	}, setupCtx, nil
}

func (c *Client) ensureReady(ctx context.Context) error {
	var ready bool
	var reader usimcard.Reader
	var cfg Config
	c.withStateLock(func(s *clientState) {
		ready = c.card != nil
		if ready {
			return
		}
		reader = c.reader
		cfg = c.cfg
	})
	if ready {
		return nil
	}

	card, err := usim.New(ctx, reader, cfg.Logger)
	if err != nil {
		return fmt.Errorf("loading USIM: %w", err)
	}
	readyCfg, err := cfg.normalized(card)
	if err != nil {
		return fmt.Errorf("normalizing client config: %w", err)
	}
	if readyCfg.usesVoWiFi() {
		if err := c.checkWFCSetup(ctx, &readyCfg, card); err != nil {
			return err
		}
	}

	var closed bool
	c.withStateLock(func(s *clientState) {
		closed = s.closed
		if c.card == nil {
			c.card = card
			c.cfg = readyCfg
			c.logger = readyCfg.Logger.With("component", "ims-go")
		}
	})
	if closed {
		return fmt.Errorf("connecting client: %w", ErrClientClosed)
	}
	return nil
}

func (c *Client) openAccess(ctx context.Context, setup *connectSetup) error {
	var (
		access accessSession
		err    error
	)
	switch {
	case c.cfg.Access.VoWiFi != nil:
		access, err = c.openVoWiFiAccess(ctx, setup)
	case c.cfg.Access.VoLTE != nil:
		access, err = c.openVoLTEAccess(ctx, setup)
	default:
		err = errors.New("opening access: access config is empty")
	}
	if err != nil {
		return err
	}
	setup.access = access
	return nil
}

func (c *Client) commitConnect(setup *connectSetup) (*activeConn, error) {
	active := &activeConn{
		scope:  setup.scope,
		access: setup.access,
		tunnel: setup.tunnel,
		ims:    setup.ims,
	}

	if err := c.state.commitActive(active); err != nil {
		return nil, fmt.Errorf("connecting client: %w", err)
	}
	c.clearUSSDSessionBindings()
	if setup.setupStop != nil {
		setup.setupStop()
		setup.setupStop = nil
	}
	setup.client = nil
	setup.scope = nil
	setup.access = nil
	setup.tunnel = nil
	setup.ims = imsStack{}
	return active, nil
}

func (s *connectSetup) rollback() error {
	if s.client != nil {
		s.client.finishConnectAttempt()
	}
	if s.setupStop != nil {
		s.setupStop()
	}
	if s.scope == nil {
		return nil
	}
	s.scope.stop()
	err := s.closeIMS()
	if s.access != nil {
		err = errors.Join(err, wrapCloseError(closeActionAccess, normalizeCloseError(s.access.Close())))
	} else if s.tunnel != nil {
		err = errors.Join(err, wrapCloseError(closeActionTunnel, normalizeCloseError(s.tunnel.Close())))
	}
	return err
}

func (c *Client) finishConnectAttempt() {
	c.state.finishConnectAttempt()
}

func (c *Client) reserveCloseTask() (func(), bool) {
	return c.state.reserveCloseTask()
}

func (c *Client) newSetupContext(ctx context.Context, internal bool) (context.Context, context.CancelFunc) {
	setupCtx, stop := c.state.context(ctx)
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
	c.emitStatusError(StatusFailed, err)
}

func (c *Client) cancelConnectStart(active *activeConn, runDone <-chan struct{}) {
	if active == nil || active.scope == nil {
		return
	}
	active.scope.stop()
	if !c.detachActive(active) {
		return
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), defaultCloseTimeout)
	defer cancel()
	if c.waitIMSRunnerStop(closeCtx, runDone) {
		_ = c.closeActive(active)
		return
	}
	_ = c.closeActiveConnection(active)
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

func (c *Client) Close() error {
	var err error
	c.state.doClose(func() {
		active, ok := c.state.beginClose()
		if !ok {
			return
		}
		reader := c.reader
		c.reader = nil

		if active != nil && active.scope != nil {
			active.scope.stop()
		}
		if c.waitCloseTasks() {
			if c.cfg.IMS.RegistrationGroup != nil {
				err = errors.Join(err, c.deregisterActive(active))
			}
			err = errors.Join(err, c.closeActive(active))
		} else {
			err = errors.Join(err, context.DeadlineExceeded)
			err = errors.Join(err, c.closeActiveConnection(active))
		}
		if reader != nil {
			err = errors.Join(err, wrapCloseError(closeActionReader, reader.Close()))
		}
		c.emitStatus(StatusClosed)
		c.events.close()
	})
	return err
}

func (c *Client) waitCloseTasks() bool {
	return c.state.waitCloseTasks(defaultCloseTimeout)
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

type closeAction uint8

const (
	closeActionReader closeAction = iota
	closeActionAccess
	closeActionTunnel
	closeActionUSSDEndpoint
	closeActionVoiceEndpoint
	closeActionSMSEndpoint
	closeActionRegistrar
	closeActionIMSSession
)

func (a closeAction) String() string {
	switch a {
	case closeActionReader:
		return "closing reader"
	case closeActionAccess:
		return "closing access"
	case closeActionTunnel:
		return "closing tunnel"
	case closeActionUSSDEndpoint:
		return "closing USSD endpoint"
	case closeActionVoiceEndpoint:
		return "closing voice endpoint"
	case closeActionSMSEndpoint:
		return "closing SMS endpoint"
	case closeActionRegistrar:
		return "closing IMS registrar"
	case closeActionIMSSession:
		return "closing IMS session"
	default:
		return "closing resource"
	}
}

func wrapCloseError(action closeAction, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", action, err)
}

func (c *Client) closeActive(active *activeConn) error {
	if active == nil {
		return nil
	}
	c.clearUSSDSessionBindings()

	err := active.ims.close()
	if active.access != nil {
		err = errors.Join(err, wrapCloseError(closeActionAccess, normalizeCloseError(active.access.Close())))
	} else if active.tunnel != nil {
		err = errors.Join(err, wrapCloseError(closeActionTunnel, normalizeCloseError(active.tunnel.Close())))
	}
	return err
}

func (c *Client) deregisterActive(active *activeConn) error {
	if active == nil {
		return nil
	}
	return deregisterRegistrar(active.ims.reg)
}

func deregisterRegistrar(reg *registration.Registrar) error {
	if reg == nil || !reg.State().Registered {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultCloseTimeout)
	defer cancel()
	if err := reg.Deregister(ctx); err != nil {
		return fmt.Errorf("deregistering IMS before close: %w", err)
	}
	return nil
}

func (c *Client) closeActiveConnection(active *activeConn) error {
	if active == nil {
		return nil
	}
	err := c.closeIMS(active)
	if active.access != nil {
		err = errors.Join(err, wrapCloseError(closeActionAccess, normalizeCloseError(active.access.Close())))
	} else if active.tunnel != nil {
		err = errors.Join(err, wrapCloseError(closeActionTunnel, normalizeCloseError(active.tunnel.Close())))
	}
	return err
}

func (c *Client) closeIMS(active *activeConn) error {
	c.clearUSSDSessionBindings()
	return active.ims.close()
}

func (s *connectSetup) closeIMS() error {
	var err error
	if s.imsCfg.RegistrationGroup != nil {
		err = deregisterRegistrar(s.ims.reg)
	}
	return errors.Join(err, s.ims.close())
}

func (s *connectSetup) closeIMSAfterFailure(cause error) error {
	if err := s.closeIMS(); err != nil {
		return errors.Join(cause, fmt.Errorf("closing failed IMS setup: %w", err))
	}
	return cause
}

func (r *imsStack) close() error {
	var err error
	if r.ussd != nil {
		err = errors.Join(err, wrapCloseError(closeActionUSSDEndpoint, r.ussd.Close()))
	}
	if r.voice != nil {
		err = errors.Join(err, wrapCloseError(closeActionVoiceEndpoint, r.voice.Close()))
	}
	if r.sms != nil {
		err = errors.Join(err, wrapCloseError(closeActionSMSEndpoint, r.sms.Close()))
	}
	if r.reg != nil {
		err = errors.Join(err, wrapCloseError(closeActionRegistrar, r.reg.Close()))
	}
	if r.sip != nil {
		err = errors.Join(err, wrapCloseError(closeActionIMSSession, normalizeCloseError(r.sip.Close())))
	}
	*r = imsStack{}
	return err
}

func (c *Client) startReconnect() bool {
	return c.state.startReconnect()
}

func (c *Client) finishReconnect() {
	c.state.finishReconnect()
}

func (c *Client) reconnect(cause error) (*activeConn, error) {
	reconnectID := c.state.nextReconnectID()
	if c.cfg.usesVoWiFi() {
		c.recordSWUBackoff(cause, time.Now())
	}
	if terminalReconnectError(cause) {
		return nil, cause
	}

	backoff := newReconnectBackoff(c.cfg.ReconnectDelay, c.cfg.ReconnectMaxDelay)
	registrationBackoff := newReconnectBackoff(c.cfg.IMS.RegistrationRetryBase, c.cfg.IMS.RegistrationRetryMax)
	initialDelay := c.reconnectDelay(cause, backoff, registrationBackoff)
	c.logger.Info("reconnect scheduled", "reconnect_id", reconnectID, "delay", initialDelay, "cause", cause)
	clientCtx, stopClientCtx := c.state.context(context.Background())
	defer stopClientCtx()
	if err := sleepContext(clientCtx, initialDelay); err != nil {
		return nil, err
	}

	for attempt := 1; ; attempt++ {
		c.logger.Info("reconnect attempt started", "reconnect_id", reconnectID, "attempt", attempt)
		active, err := c.connectOnce(clientCtx, true)
		if err == nil {
			c.logger.Info("reconnect attempt succeeded", "reconnect_id", reconnectID, "attempt", attempt)
			return active, nil
		}
		if clientCtx.Err() != nil {
			return nil, clientCtx.Err()
		}
		if terminalReconnectError(err) {
			return nil, err
		}

		nextDelay := c.reconnectDelay(err, backoff, registrationBackoff)
		c.logger.Warn("reconnect attempt failed", "reconnect_id", reconnectID, "attempt", attempt, "err", err, "next_delay", nextDelay)
		if err := sleepContext(clientCtx, nextDelay); err != nil {
			return nil, err
		}
	}
}

func terminalReconnectError(err error) bool {
	return swutunnel.AccessRejected(err) || swutunnel.BackoffDeactivated(err) || errors.Is(err, errSWUBackoffDeactivated)
}

func (c *Client) reconnectDelay(err error, backoff, registrationBackoff *reconnectBackoff) time.Duration {
	useSWUBackoff := c.cfg.usesVoWiFi()
	if useSWUBackoff && (swutunnel.ReactivationRequested(err) || swutunnel.PCSCFReselectionRequested(err)) {
		return 0
	}
	if registration.InitialRegistrationRequired(err) {
		delay := registrationBackoff.Next()
		if retryAfter, ok := registration.RetryAfterDelay(err); ok {
			delay = max(delay, retryAfter)
		}
		if tunnelBackoff, ok := swutunnel.BackoffDelay(err); useSWUBackoff && ok {
			delay = max(delay, tunnelBackoff)
		}
		return delay
	}

	delay := backoff.Next()
	if retryAfter, ok := registration.RetryAfterDelay(err); ok {
		delay = max(delay, retryAfter)
	}
	if tunnelBackoff, ok := swutunnel.BackoffDelay(err); useSWUBackoff && ok {
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

type connectionRunner struct {
	client    *Client
	active    *activeConn
	done      func()
	reconnect func(error) (*activeConn, error)
}

func (c *Client) startConnectionRunner(active *activeConn, done func()) <-chan struct{} {
	runner := connectionRunner{
		client:    c,
		active:    active,
		done:      done,
		reconnect: c.reconnect,
	}
	return runner.start()
}

func (r connectionRunner) start() <-chan struct{} {
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		r.run()
	}()
	return runDone
}

func (r *connectionRunner) run() {
	defer r.done()
	for {
		if !r.runOnce() {
			return
		}
	}
}

func (r *connectionRunner) runOnce() bool {
	err := r.runIMS()
	if err == nil || r.active.scope.stopped() {
		return false
	}
	return r.recover(err)
}

func (r *connectionRunner) recover(cause error) bool {
	if restored, nextCause := r.restoreIMSAfterSWUPCSCF(cause); restored {
		return true
	} else {
		cause = nextCause
	}
	if restored, nextCause := r.restoreIMSAfterRegistrationPCSCF(cause); restored {
		return true
	} else {
		cause = nextCause
	}
	return r.reconnectAfterIMSFailure(cause)
}

func (r *connectionRunner) restoreIMSAfterSWUPCSCF(cause error) (bool, error) {
	if r.active == nil || r.active.tunnel == nil {
		return false, cause
	}
	if !swutunnel.PCSCFReselectionRequested(cause) {
		return false, cause
	}
	next, err := r.client.restoreIMSAfterPCSCFReselection(r.active, cause)
	if err != nil {
		return false, fmt.Errorf("restoring IMS after P-CSCF reselection: %w", err)
	}
	r.client.logger.Info("IMS restored after P-CSCF reselection")
	r.active = next
	return true, nil
}

func (r *connectionRunner) restoreIMSAfterRegistrationPCSCF(cause error) (bool, error) {
	if r.active == nil || !pcscfFailoverRequired(cause, r.client.cfg.IMS.SIPTimers.TF) {
		return false, cause
	}
	if r.active.tunnel != nil {
		next, err := r.client.restoreIMSAfterRegistrationPCSCFReselection(r.active)
		if err != nil {
			return false, fmt.Errorf("restoring IMS after registration P-CSCF reselection: %w", err)
		}
		r.client.logger.Info("IMS restored after registration P-CSCF reselection")
		r.active = next
		return true, nil
	}
	reselector, ok := r.active.access.(pcscfReselectingAccess)
	if !ok {
		return false, cause
	}
	next, err := r.client.restoreIMSWithNextLTEPCSCF(r.active, reselector)
	if err != nil {
		return false, fmt.Errorf("restoring IMS after registration P-CSCF reselection: %w", err)
	}
	r.client.logger.Info("IMS restored after registration P-CSCF reselection")
	r.active = next
	return true, nil
}

func (c *Client) restoreIMSWithNextLTEPCSCF(active *activeConn, access pcscfReselectingAccess) (*activeConn, error) {
	if err := c.closeIMS(active); err != nil {
		return nil, err
	}
	if err := access.SelectNextPCSCF(); err != nil {
		return nil, err
	}

	setupCtx, setupStop := c.newIMSRestoreContext(active.scope)
	defer setupStop()
	setup := &connectSetup{
		setupStop: setupStop,
		scope:     active.scope,
		access:    access,
		imsCfg:    c.cfg.IMS,
		tunnel:    active.tunnel,
	}
	// SelectNextPCSCF removes the failed address, so the reported count already
	// contains only candidates that still need to be attempted.
	remainingCandidates := max(access.PCSCFCandidateCount(), 1)
	if err := c.openIMSWithPCSCFFailoverAttempts(setupCtx, setup, access, remainingCandidates); err != nil {
		return nil, setup.closeIMSAfterFailure(err)
	}
	if err := c.commitIMSRestore(active, setup); err != nil {
		return nil, setup.closeIMSAfterFailure(err)
	}
	c.emitStatus(StatusRegistered)
	return active, nil
}

func (r *connectionRunner) reconnectAfterIMSFailure(cause error) bool {
	runErr := fmt.Errorf("running IMS loop: %w", cause)
	r.active.scope.stop()
	if !r.client.detachActive(r.active) {
		return false
	}

	_ = r.client.closeActiveConnection(r.active)
	if r.client.cfg.usesVoWiFi() {
		r.client.clearSWUPDNTypeRestrictionAfterDisconnect(cause)
	}

	if !r.client.startReconnect() {
		r.client.emitStatusError(StatusFailed, runErr)
		return false
	}
	r.client.emitStatusError(StatusReconnecting, runErr)
	r.client.logger.Info("reconnecting client", "cause", cause)

	next, err := r.reconnect(runErr)
	r.client.finishReconnect()
	if err != nil {
		r.client.handleReconnectError(err)
		return false
	}

	r.active = next
	r.client.emitStatus(StatusRegistered)
	r.client.logger.Info("client reconnected")
	return true
}

func (c *Client) handleReconnectError(err error) {
	if terminalReconnectError(err) {
		c.emitStatusError(StatusFailed, err)
	}
}

type imsRunResult struct {
	task imsTask
	err  error
}

type imsTask uint8

const (
	imsTaskRunSession imsTask = iota
	imsTaskMaintainRegistration
)

func (t imsTask) String() string {
	switch t {
	case imsTaskRunSession:
		return "running IMS session"
	case imsTaskMaintainRegistration:
		return "maintaining IMS registration"
	default:
		return "running IMS"
	}
}

func (r *connectionRunner) runIMS() error {
	runCtx, cancel := r.active.scope.context()
	defer cancel()

	results := make(chan imsRunResult, 2)
	go func() {
		results <- imsRunResult{task: imsTaskRunSession, err: r.active.ims.sip.Run(runCtx)}
	}()
	go func() {
		results <- imsRunResult{task: imsTaskMaintainRegistration, err: r.active.ims.reg.Maintain(runCtx)}
	}()

	first := <-results
	cancel()
	second := <-results

	for _, result := range []imsRunResult{first, second} {
		if result.err != nil && !errors.Is(result.err, context.Canceled) {
			return fmt.Errorf("%s: %w", result.task, result.err)
		}
	}
	return nil
}

func (c *Client) restoreIMSAfterPCSCFReselection(active *activeConn, cause error) (*activeConn, error) {
	if active.tunnel == nil {
		return nil, errors.New("restoring IMS after P-CSCF reselection: tunnel is missing")
	}
	tunnelInfo, ok := swutunnel.PCSCFReselectionInfo(cause)
	if !ok {
		tunnelInfo = active.tunnel.Info()
	}
	return c.restoreIMSWithTunnelInfo(active, tunnelInfo)
}

func (c *Client) restoreIMSAfterRegistrationPCSCFReselection(active *activeConn) (*activeConn, error) {
	if active.tunnel == nil {
		return nil, errors.New("restoring IMS after registration P-CSCF reselection: tunnel is missing")
	}
	tunnelInfo := active.tunnel.Info()
	if access, ok := active.access.(*voWiFiAccess); ok {
		tunnelInfo = access.pcscfInfo()
	}
	current := pcscfIPFromAddr(active.ims.sip.RemoteAddr())
	tunnelInfo, ok := nextPCSCFInfo(tunnelInfo, current)
	if !ok {
		return nil, errors.New("restoring IMS after registration P-CSCF reselection: no alternate P-CSCF")
	}
	return c.restoreIMSWithTunnelInfo(active, tunnelInfo)
}

func (c *Client) restoreIMSWithTunnelInfo(active *activeConn, tunnelInfo swutunnel.Info) (*activeConn, error) {
	wifiAccess, ok := active.access.(*voWiFiAccess)
	if !ok || wifiAccess.netstack == nil {
		return nil, errors.New("restoring IMS after P-CSCF reselection: VoWiFi userspace network stack is missing")
	}
	closeErr := c.closeIMS(active)
	if closeErr != nil {
		return nil, closeErr
	}

	setupCtx, setupStop := c.newIMSRestoreContext(active.scope)
	defer setupStop()

	tunnelCfg := c.cfg.Access.VoWiFi.Tunnel
	tunnelCfg.RemoteAddr = c.cfg.Access.VoWiFi.EPDG
	imsCfg := c.cfg.IMS

	setup := &connectSetup{
		setupStop: setupStop,
		scope:     active.scope,
		access: &voWiFiAccess{
			session:   active.tunnel,
			netstack:  wifiAccess.netstack,
			tunnelCfg: tunnelCfg,
			info:      tunnelInfo,
		},
		tunnelCfg: tunnelCfg,
		imsCfg:    imsCfg,
		tunnel:    active.tunnel,
	}
	if err := c.openIMSWithPCSCFFailover(setupCtx, setup); err != nil {
		return nil, setup.closeIMSAfterFailure(err)
	}
	if err := c.commitIMSRestore(active, setup); err != nil {
		return nil, setup.closeIMSAfterFailure(err)
	}
	c.emitStatus(StatusRegistered)
	return active, nil
}

func nextPCSCFInfo(info swutunnel.Info, current net.IP) (swutunnel.Info, bool) {
	ips := pcscfCandidateIPs(info)
	if len(ips) < 2 {
		return info, false
	}
	if len(current) == 0 {
		current = ips[0]
	}
	currentIndex := -1
	for i, ip := range ips {
		if ip.Equal(current) {
			currentIndex = i
			break
		}
	}
	if currentIndex < 0 {
		return info, false
	}
	remaining := make([]net.IP, 0, len(ips)-1)
	for offset := 1; offset < len(ips); offset++ {
		next := (currentIndex + offset) % len(ips)
		remaining = append(remaining, ips[next])
	}
	info.PCSCFIPs = remaining
	return info, true
}

func pcscfIPFromAddr(addr net.Addr) net.IP {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		return append(net.IP(nil), addr.IP...)
	case *net.UDPAddr:
		return append(net.IP(nil), addr.IP...)
	default:
		return nil
	}
}

func (c *Client) commitIMSRestore(active *activeConn, setup *connectSetup) error {
	if err := c.state.restoreIMS(active, setup.ims, setup.access); err != nil {
		return err
	}
	setup.ims = imsStack{}
	setup.access = nil
	c.clearUSSDSessionBindings()
	return nil
}

func (c *Client) newIMSRestoreContext(scope *connectionScope) (context.Context, context.CancelFunc) {
	setupCtx, stop := scope.context()
	if reconnectAttemptTimeout <= 0 {
		return setupCtx, stop
	}
	timeoutCtx, timeoutCancel := context.WithTimeout(setupCtx, reconnectAttemptTimeout)
	return timeoutCtx, func() {
		timeoutCancel()
		stop()
	}
}

func (c *Client) detachActive(active *activeConn) bool {
	return c.state.detachActive(active)
}

func (c *Client) isClosed() bool {
	return c.state.isClosed()
}
