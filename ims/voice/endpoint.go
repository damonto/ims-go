package voice

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/damonto/ims-go/ims/registration"
	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
)

func New(cfg Config, sess *session.Session, reg *registration.Registrar) (*Endpoint, error) {
	if sess == nil {
		return nil, errors.New("creating voice endpoint: session is nil")
	}
	if reg == nil {
		return nil, errors.New("creating voice endpoint: registrar is nil")
	}
	endpointCfg, err := cfg.Normalized()
	if err != nil {
		return nil, err
	}
	endpoint := &Endpoint{
		cfg:          endpointCfg,
		sess:         sess,
		reg:          reg,
		logger:       endpointCfg.Logger.With("component", "ims-voice"),
		timers:       sess.TransactionTimers(),
		rtcpInterval: rtcpInterval,
		nextPort:     endpointCfg.LocalRTPPortMin,
		calls:        make(map[string]*Call),
		incomings:    make(map[string]*Call),
		bgDone:       make(chan struct{}),
	}
	attachment, err := sess.Attach(endpoint)
	if err != nil {
		return nil, fmt.Errorf("creating voice endpoint: %w", err)
	}
	endpoint.attachment = attachment
	sess.SetResponseDecorator(endpoint.addAccessNetworkInfo)
	return endpoint, nil
}

func (s *Endpoint) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	attachment := s.attachment
	s.attachment = nil
	calls := make([]*Call, 0, len(s.calls))
	for _, call := range s.calls {
		calls = append(calls, call)
	}
	s.calls = make(map[string]*Call)
	s.incomings = make(map[string]*Call)
	close(s.bgDone)
	s.mu.Unlock()

	var err error
	if attachment != nil {
		err = attachment.Close()
	}
	for _, call := range calls {
		call.finish(CallStateEnded, "")
	}
	s.bgWG.Wait()
	return err
}

func (s *Endpoint) HandleRequest(ctx context.Context, req session.Request) (bool, error) {
	switch strings.ToUpper(req.Message.Method()) {
	case "INVITE":
		if sip.HeaderTag(req.Message.Header("To")) != "" {
			call := s.lookupCallForMessage(req.Message)
			if call == nil {
				return true, s.writeStatus(ctx, req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist")
			}
			return true, call.handleRequest(ctx, req)
		}
		return true, s.handleIncomingInvite(ctx, req)
	case "ACK", "BYE", "CANCEL", "INFO", "PRACK", "UPDATE":
		call := s.lookupCallForMessage(req.Message)
		if call == nil && strings.EqualFold(req.Message.Method(), "CANCEL") {
			call = s.lookupIncoming(req.Message)
		}
		if call == nil {
			s.logger.Debug("call request did not match dialog",
				"method", req.Message.Method(),
				"call_id", req.Message.Header("Call-ID"),
				"from", req.Message.Header("From"),
				"to", req.Message.Header("To"),
				"cseq", req.Message.Header("CSeq"),
			)
			if strings.EqualFold(req.Message.Method(), "PRACK") {
				return true, s.writeStatus(ctx, req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist")
			}
			return false, nil
		}
		return true, call.handleRequest(ctx, req)
	default:
		return false, nil
	}
}

func (s *Endpoint) HandleResponse(ctx context.Context, msg sip.Message) (bool, error) {
	if !strings.EqualFold(sip.CSeqMethod(msg.Header("CSeq")), "INVITE") {
		return false, nil
	}
	call := s.lookupCall(strings.TrimSpace(msg.Header("Call-ID")))
	if call == nil {
		return false, nil
	}
	if msg.StatusCode() >= sipStatusTrying && msg.StatusCode() < sipStatusOK {
		call.markInviteResponse()
		if msg.StatusCode() == sipStatusTrying {
			return true, nil
		}
		return true, call.handleProvisionalResponse(ctx, msg)
	}
	if msg.StatusCode() < sipStatusOK || msg.StatusCode() >= sipStatusMultipleChoices {
		return false, nil
	}
	return true, call.handleResponse(ctx, msg)
}

func (s *Endpoint) HandleError(err error) {
	if err != nil {
		s.emitError(err)
	}
}

func (s *Endpoint) startBackgroundTask(task func(done <-chan struct{})) bool {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	done := s.bgDone
	s.bgWG.Go(func() {
		task(done)
	})
	s.mu.Unlock()
	return true
}

func (s *Endpoint) backgroundContext() (context.Context, context.CancelFunc) {
	s.mu.Lock()
	done := s.bgDone
	s.mu.Unlock()
	return contextWithDone(done)
}

func (s *Endpoint) timeoutContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	s.mu.Lock()
	done := s.bgDone
	s.mu.Unlock()
	return contextWithDoneTimeout(done, timeout)
}

func contextWithDone(done <-chan struct{}) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	return cancelContextWithDone(ctx, cancel, done)
}

func contextWithDoneTimeout(done <-chan struct{}, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return cancelContextWithDone(ctx, cancel, done)
}

func cancelContextWithDone(ctx context.Context, cancel context.CancelFunc, done <-chan struct{}) (context.Context, context.CancelFunc) {
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
