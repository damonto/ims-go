package session

import (
	"context"
	"errors"
)

func (s *Session) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("running session: session is closed")
	}
	if s.started {
		s.mu.Unlock()
		return errors.New("running session: already started")
	}
	s.started = true
	s.running = true
	primary := s.primary
	aux := append([]Transport(nil), s.aux...)
	inboundCh := make(chan inboundMessage, 16)
	s.runtime = &runtimeState{ctx: ctx, inbound: inboundCh}
	s.mu.Unlock()
	defer s.finishRunning()

	s.startRuntimeReadLoop(ctx, primary, inboundCh)
	for _, transport := range aux {
		s.startRuntimeReadLoop(ctx, transport, inboundCh)
	}
	s.markReady()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case inbound := <-inboundCh:
			if inbound.err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if !s.isTransportActive(inbound.transport) {
					continue
				}
				if s.removeFailedAuxTransport(inbound.transport) {
					s.logger.Warn("removed failed auxiliary SIP transport", "local_addr", inbound.transport.LocalAddr(), "err", inbound.err)
					s.abortTransportTransactions(inbound.transport, inbound.err)
					continue
				}
				return inbound.err
			}
			if err := s.dispatchInbound(ctx, inbound); err != nil {
				return err
			}
		}
	}
}

func (s *Session) handleInboundRequest(ctx context.Context, req Request) error {
	handled, err := s.processServerTransaction(ctx, req)
	if handled || err != nil {
		return err
	}
	return s.handleRequest(ctx, req)
}

func (s *Session) WaitStarted(ctx context.Context) error {
	s.mu.Lock()
	if s.ready {
		s.mu.Unlock()
		return nil
	}
	startedCh := s.startedCh
	closedCh := s.closedCh
	s.mu.Unlock()

	select {
	case <-startedCh:
		return nil
	case <-closedCh:
		s.mu.Lock()
		ready := s.ready
		s.mu.Unlock()
		if ready {
			return nil
		}
		return errors.New("waiting for session start: session is closed")
	case <-ctx.Done():
		return ctx.Err()
	}
}
