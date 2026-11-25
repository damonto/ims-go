package ims

import (
	"context"
	"errors"
	"net"
	"slices"
	"time"

	"github.com/damonto/ims-go/eapaka"
	imssession "github.com/damonto/ims-go/ims/session"
	swutunnel "github.com/damonto/ims-go/swu/tunnel"
	"github.com/damonto/ims-go/wfcsetup"
)

// ConnectionStage identifies an operation in an IMS connection attempt.
type ConnectionStage string

const (
	stageSIMSetup    ConnectionStage = "sim_setup"
	stageWFCSetup    ConnectionStage = "wfc_entitlement"
	stageEPDGResolve ConnectionStage = "epdg_resolve"
	stageEPDGIKEInit ConnectionStage = "epdg_ike_init"
	stageIMSPDN      ConnectionStage = "ims_pdn"
	stagePCSCF       ConnectionStage = "ims_transport"
	stageIMSStarting ConnectionStage = "ims_starting"
	stageIMSLost     ConnectionStage = "ims_disconnected"
	stageIMSSlot     ConnectionStage = "ims_registration_slot"
	stageRetryWait   ConnectionStage = "retry_wait"
)

// ConnectionProgressStatus describes an attempt or one of its steps.
type ConnectionProgressStatus string

// ProgressReady applies to the attempt. ProgressCompleted applies to individual steps.
const (
	ProgressRunning   ConnectionProgressStatus = "running"
	ProgressWaiting   ConnectionProgressStatus = "waiting"
	ProgressReady     ConnectionProgressStatus = "ready"
	ProgressFailed    ConnectionProgressStatus = "failed"
	ProgressCompleted ConnectionProgressStatus = "completed"
)

const maxConnectionSteps = 32

// ConnectionStep records a stage visited in the current attempt.
type ConnectionStep struct {
	Stage     ConnectionStage
	Status    ConnectionProgressStatus
	StartedAt time.Time
}

// ConnectionFailure identifies the last failed stage without including request data.
type ConnectionFailure struct {
	Attempt uint64
	Stage   ConnectionStage
	Code    string
	At      time.Time
}

// ConnectionProgress describes the current or most recent connection attempt.
// An empty Stage means there is no stage to report.
type ConnectionProgress struct {
	Attempt        uint64
	Status         ConnectionProgressStatus
	Stage          ConnectionStage
	StageStartedAt time.Time
	RetryAt        *time.Time
	Steps          []ConnectionStep
	LastFailure    *ConnectionFailure
}

// ConnectionProgress returns a detached snapshot of connection setup.
func (c *Client) ConnectionProgress() ConnectionProgress {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	value := c.state.progress
	value.Steps = slices.Clone(value.Steps)
	if value.LastFailure != nil {
		failure := *value.LastFailure
		value.LastFailure = &failure
	}
	if value.RetryAt != nil {
		retryAt := *value.RetryAt
		value.RetryAt = &retryAt
	}
	return value
}

func (c *Client) beginConnectionProgress(stage ConnectionStage) uint64 {
	c.state.mu.Lock()
	if c.state.closed {
		c.state.mu.Unlock()
		return 0
	}
	p := &c.state.progress
	*p = ConnectionProgress{Attempt: p.Attempt + 1, LastFailure: p.LastFailure}
	if stage != "" {
		p.enter(stage, ProgressRunning, time.Now())
	}
	attempt := p.Attempt
	c.state.mu.Unlock()
	c.events.progressChanged.publish(struct{}{}, nil)
	return attempt
}

func (p *ConnectionProgress) enter(stage ConnectionStage, status ConnectionProgressStatus, at time.Time) {
	p.finishStep(ProgressCompleted)
	p.Stage = stage
	p.StageStartedAt = at.UTC()
	p.Status = status
	p.RetryAt = nil
	if len(p.Steps) == maxConnectionSteps {
		copy(p.Steps, p.Steps[1:])
		p.Steps = p.Steps[:maxConnectionSteps-1]
	}
	p.Steps = append(p.Steps, ConnectionStep{Stage: stage, Status: status, StartedAt: p.StageStartedAt})
}

func (p *ConnectionProgress) finishStep(status ConnectionProgressStatus) {
	if i := len(p.Steps) - 1; i >= 0 && (p.Steps[i].Status == ProgressRunning || p.Steps[i].Status == ProgressWaiting) {
		p.Steps[i].Status = status
	}
}

func (c *Client) updateConnectionProgress(attempt uint64, update func(*ConnectionProgress) bool) {
	c.state.mu.Lock()
	p := &c.state.progress
	changed := !c.state.closed && attempt != 0 && p.Attempt == attempt && update(p)
	c.state.mu.Unlock()
	if changed {
		c.events.progressChanged.publish(struct{}{}, nil)
	}
}

func (c *Client) connectionStage(attempt uint64, stage ConnectionStage) {
	c.updateConnectionProgress(attempt, func(p *ConnectionProgress) bool {
		if p.Stage == stage && p.Status == ProgressRunning {
			return false
		}
		p.enter(stage, ProgressRunning, time.Now())
		return true
	})
}

func (c *Client) waitConnectionProgress(attempt uint64, stage ConnectionStage, delay time.Duration) {
	c.updateConnectionProgress(attempt, func(p *ConnectionProgress) bool {
		now := time.Now()
		p.enter(stage, ProgressWaiting, now)
		if delay > 0 {
			retryAt := now.Add(delay).UTC()
			p.RetryAt = &retryAt
		}
		return true
	})
}

func (c *Client) finishConnectionProgress(attempt uint64, err error) {
	c.updateConnectionProgress(attempt, func(p *ConnectionProgress) bool {
		if err == nil {
			if p.Status != ProgressRunning {
				return false
			}
			p.finishStep(ProgressCompleted)
			p.Status = ProgressReady
			return true
		}
		if errors.Is(err, wfcsetup.ErrUserActionRequired) || errors.Is(err, wfcsetup.ErrPending) {
			if p.Status != ProgressRunning {
				return false
			}
			p.Status = ProgressWaiting
			p.Steps[len(p.Steps)-1].Status = ProgressWaiting
			return true
		}
		if p.Status == ProgressFailed {
			return false
		}
		if errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			*p = ConnectionProgress{Attempt: p.Attempt}
			return true
		}
		p.finishStep(ProgressFailed)
		p.Status = ProgressFailed
		p.RetryAt = nil
		p.LastFailure = &ConnectionFailure{
			Attempt: attempt, Stage: p.Stage, Code: connectionFailureCode(err), At: time.Now().UTC(),
		}
		return true
	})
}

func connectionFailureCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, swutunnel.ErrIKESAInitNoResponse) {
		return "timeout"
	}
	if _, ok := errors.AsType[*imssession.TransactionTimeoutError](err); ok {
		return "timeout"
	}
	if networkErr, ok := errors.AsType[net.Error](err); ok && networkErr.Timeout() {
		return "timeout"
	}
	switch {
	case errors.Is(err, wfcsetup.ErrDenied), swutunnel.AccessRejected(err):
		return "carrier_denied"
	case errors.Is(err, eapaka.ErrEAPFailure), errors.Is(err, eapaka.ErrAKAPrimeAuthenticationFailure):
		return "authentication_failed"
	default:
		return "connection_failed"
	}
}
