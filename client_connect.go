package vowifi

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/damonto/vowifi-go/ims/registration"
	imssession "github.com/damonto/vowifi-go/ims/session"
	imssms "github.com/damonto/vowifi-go/ims/sms"
	imsussd "github.com/damonto/vowifi-go/ims/ussd"
	imsvoice "github.com/damonto/vowifi-go/ims/voice"
	swutunnel "github.com/damonto/vowifi-go/swu/tunnel"
	"github.com/damonto/vowifi-go/usim"
	usimreader "github.com/damonto/vowifi-go/usim/reader"
)

type connectionRuntime struct {
	done chan struct{}
	once sync.Once
}

type activeConn struct {
	runtime *connectionRuntime
	tunnel  *swutunnel.Session
	ims     imsRuntime
}

type connectSetup struct {
	client    *Client
	setupStop context.CancelFunc
	runtime   *connectionRuntime
	tunnelCfg swutunnel.Config
	imsCfg    IMSConfig
	tunnel    *swutunnel.Session
	ims       imsRuntime
}

type imsRuntime struct {
	sip   *imssession.Session
	reg   *registration.Service
	sms   *imssms.Service
	ussd  *imsussd.Service
	voice *imsvoice.Service
}

const defaultCloseTimeout = 5 * time.Second
const defaultReconnectDelay = 3 * time.Second
const defaultReconnectMaxDelay = time.Minute
const defaultIMSRegistrationRetryBase = 120 * time.Second
const defaultIMSRegistrationRetryMax = 300 * time.Second

var reconnectAttemptTimeout = 30 * time.Second

func newConnectionRuntime() *connectionRuntime {
	return &connectionRuntime{done: make(chan struct{})}
}

func (r *connectionRuntime) stop() {
	r.once.Do(func() {
		close(r.done)
	})
}

func (r *connectionRuntime) stopped() bool {
	select {
	case <-r.done:
		return true
	default:
		return false
	}
}

func (r *connectionRuntime) context() (context.Context, context.CancelFunc) {
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

func (c *Client) connectOnce(ctx context.Context, internal bool) (*activeConn, error) {
	setup, setupCtx, err := c.prepareConnect(ctx, internal)
	if err != nil {
		return nil, err
	}
	defer setup.rollback()

	c.emitStatus(StatusConnecting)
	tunnelInfo, err := c.openTunnel(setupCtx, setup)
	if err != nil {
		c.recordSWUBackoff(err, time.Now())
		c.emitConnectFailure(ctx, err)
		return nil, err
	}
	c.clearCurrentSWUBackoff()

	if err := c.openIMSRuntime(setupCtx, setup, tunnelInfo); err != nil {
		c.emitConnectFailure(ctx, err)
		return nil, err
	}

	active, err := c.commitConnect(setup)
	if err != nil {
		c.emitConnectFailure(ctx, err)
		return nil, err
	}

	c.logger.Info("IMS registered")
	if !internal {
		c.emitStatus(StatusRegistered)
	}
	return active, nil
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
	if err := c.waitSWUBackoff(setupCtx); err != nil {
		setupStop()
		c.finishConnectAttempt()
		return nil, nil, err
	}

	runtime := newConnectionRuntime()
	fail := func(err error) (*connectSetup, context.Context, error) {
		setupStop()
		runtime.stop()
		c.finishConnectAttempt()
		return nil, nil, err
	}

	tunnelCfg := c.cfg.Tunnel
	tunnelCfg.RemoteAddr = c.cfg.EPDG

	tunnelCfg, err := tunnelCfg.Normalized()
	if err != nil {
		return fail(fmt.Errorf("preparing connect: %w", err))
	}
	if tunnelCfg.RemoteAddr == "" {
		return fail(errors.New("preparing connect: tunnel remote address is empty"))
	}

	imsCfg := c.cfg.IMS
	imsCfg, err = imsCfg.Normalized()
	if err != nil {
		return fail(fmt.Errorf("preparing connect: %w", err))
	}

	return &connectSetup{
		client:    c,
		setupStop: setupStop,
		runtime:   runtime,
		tunnelCfg: tunnelCfg,
		imsCfg:    imsCfg,
	}, setupCtx, nil
}

func (c *Client) ensureReady(ctx context.Context) error {
	var ready bool
	var reader usimreader.Reader
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

	card, err := usim.Load(ctx, reader, cfg.Logger)
	if err != nil {
		return fmt.Errorf("loading USIM: %w", err)
	}
	normalized, err := cfg.normalized(card)
	if err != nil {
		return fmt.Errorf("normalizing client config: %w", err)
	}
	if err := c.checkWFCSetup(ctx, &normalized, card); err != nil {
		return err
	}

	var closed bool
	c.withStateLock(func(s *clientState) {
		closed = s.closed
		if c.card == nil {
			c.card = card
			c.cfg = normalized
			c.logger = normalized.Logger.With("component", "vowifi-go")
		}
	})
	if closed {
		return fmt.Errorf("connecting client: %w", ErrClientClosed)
	}
	return nil
}

func (c *Client) commitConnect(setup *connectSetup) (*activeConn, error) {
	active := &activeConn{
		runtime: setup.runtime,
		tunnel:  setup.tunnel,
		ims:     setup.ims,
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
	setup.runtime = nil
	setup.tunnel = nil
	setup.ims = imsRuntime{}
	return active, nil
}

func (s *connectSetup) rollback() {
	if s.client != nil {
		s.client.finishConnectAttempt()
	}
	if s.setupStop != nil {
		s.setupStop()
	}
	if s.runtime == nil {
		return
	}
	s.runtime.stop()
	_ = s.ims.close()
	if s.tunnel != nil {
		_ = s.tunnel.Close()
	}
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
	if active == nil || active.runtime == nil {
		return
	}
	active.runtime.stop()
	if !c.detachActive(active) {
		return
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), defaultCloseTimeout)
	defer cancel()
	if c.waitIMSRunnerStop(closeCtx, runDone) {
		_ = c.closeActive(active)
		return
	}
	_ = c.closeActiveRuntime(active)
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
