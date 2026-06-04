package vowifi

import (
	"context"
	"errors"
	"fmt"

	swutunnel "github.com/damonto/vowifi-go/swu/tunnel"
)

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
	err := r.runIMSRuntime()
	if err == nil || r.active.runtime.stopped() {
		return false
	}
	return r.recover(err)
}

func (r *connectionRunner) recover(cause error) bool {
	if swutunnel.PCSCFReselectionRequested(cause) {
		next, err := r.client.restoreIMSAfterPCSCFReselection(r.active, cause)
		if err == nil {
			r.client.logger.Info("IMS restored after P-CSCF reselection")
			r.active = next
			return true
		}
		cause = fmt.Errorf("restoring IMS after P-CSCF reselection: %w", err)
	}
	if !r.reconnectAfterIMSFailure(cause) {
		return false
	}
	return true
}

func (r *connectionRunner) reconnectAfterIMSFailure(cause error) bool {
	runErr := fmt.Errorf("running IMS loop: %w", cause)
	r.active.runtime.stop()
	if !r.client.detachActive(r.active) {
		return false
	}

	_ = r.client.closeActiveRuntime(r.active)

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
	if !errors.Is(err, context.Canceled) {
		c.logger.Error("reconnecting client", "err", err)
	}
}

func (c *Client) restoreIMSAfterPCSCFReselection(active *activeConn, cause error) (*activeConn, error) {
	if active.tunnel == nil {
		return nil, errors.New("restoring IMS after P-CSCF reselection: tunnel is missing")
	}
	tunnelInfo, ok := swutunnel.PCSCFReselectionInfo(cause)
	if !ok {
		tunnelInfo = active.tunnel.Info()
	}

	closeErr := c.closeIMSRuntime(active)
	if closeErr != nil {
		return nil, closeErr
	}

	setupCtx, setupStop := c.newIMSRestoreContext(active.runtime)
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
		setupStop: setupStop,
		runtime:   active.runtime,
		tunnelCfg: tunnelCfg,
		imsCfg:    imsCfg,
		tunnel:    active.tunnel,
	}
	if err := c.openIMSRuntime(setupCtx, setup, tunnelInfo); err != nil {
		_ = setup.closeIMSRuntime()
		return nil, err
	}
	if err := c.commitIMSRestore(active, setup); err != nil {
		_ = setup.closeIMSRuntime()
		return nil, err
	}
	c.emitStatus(StatusRegistered)
	return active, nil
}

func (c *Client) commitIMSRestore(active *activeConn, setup *connectSetup) error {
	if err := c.state.restoreIMS(active, setup.ims); err != nil {
		return err
	}
	setup.ims = imsRuntime{}
	c.clearUSSDSessionBindings()
	return nil
}

func (c *Client) newIMSRestoreContext(runtime *connectionRuntime) (context.Context, context.CancelFunc) {
	setupCtx, stop := runtime.context()
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

func (r *connectionRunner) runIMSRuntime() error {
	runCtx, cancel := r.active.runtime.context()
	defer cancel()

	results := make(chan imsRuntimeResult, 2)
	go func() {
		results <- imsRuntimeResult{action: "running IMS session", err: r.active.ims.sip.Run(runCtx)}
	}()
	go func() {
		results <- imsRuntimeResult{action: "maintaining IMS registration", err: r.active.ims.reg.Maintain(runCtx)}
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
	return c.state.detachActive(active)
}

func (c *Client) isClosed() bool {
	return c.state.isClosed()
}
