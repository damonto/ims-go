package session

import (
	"context"
	"fmt"
	"strings"

	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Session) Exchange(ctx context.Context, req sip.Message) (sip.Message, error) {
	return s.ExchangeWithOptions(ctx, req, ExchangeOptions{})
}

func (s *Session) ExchangeWithOptions(ctx context.Context, req sip.Message, opts ExchangeOptions) (sip.Message, error) {
	return s.ExchangeWithTransport(ctx, s.primaryTransport(), req, opts)
}

func (s *Session) ExchangeWithTransport(ctx context.Context, transport Transport, req sip.Message, opts ExchangeOptions) (sip.Message, error) {
	if err := s.ensureOpen(); err != nil {
		return sip.Message{}, fmt.Errorf("exchanging request: %w", err)
	}
	if err := s.ensureActiveTransport(transport); err != nil {
		return sip.Message{}, fmt.Errorf("exchanging request: %w", err)
	}
	for _, responseTransport := range opts.ResponseTransports {
		if err := s.ensureActiveTransport(responseTransport); err != nil {
			return sip.Message{}, fmt.Errorf("exchanging request: %w", err)
		}
	}
	tx := newClientTransaction(s, transport, req, opts)
	if !s.isRunning() {
		return s.exchangeWithBootstrapReader(ctx, tx)
	}
	if err := tx.start(ctx); err != nil {
		if resp, ok := transactionLayerErrorResponse(req, err); ok {
			return resp, nil
		}
		return sip.Message{}, err
	}
	return tx.await(ctx)
}

func (s *Session) exchangeWithBootstrapReader(ctx context.Context, tx *clientTransaction) (sip.Message, error) {
	if err := tx.start(ctx); err != nil {
		if resp, ok := transactionLayerErrorResponse(tx.request, err); ok {
			return resp, nil
		}
		return sip.Message{}, err
	}

	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	readTransports := exchangeReadTransports(tx.transport, tx.opts.ResponseTransports)
	inboundCh := make(chan inboundMessage, len(readTransports))
	for _, transport := range readTransports {
		s.startBootstrapReadLoop(readCtx, transport, inboundCh)
	}

	resultCh := make(chan transactionResult, 1)
	go func() {
		msg, err := tx.await(ctx)
		resultCh <- transactionResult{msg: msg, err: err}
	}()

	for {
		select {
		case result := <-resultCh:
			if result.err != nil {
				return sip.Message{}, result.err
			}
			return result.msg, nil
		case inbound := <-inboundCh:
			if inbound.err != nil {
				if ctx.Err() != nil {
					tx.abort(ctx.Err())
					continue
				}
				err := fmt.Errorf("receiving %s response: %w", tx.method, inbound.err)
				tx.abort(err)
				return sip.Message{}, err
			}
			if err := s.dispatchInbound(readCtx, inbound); err != nil {
				tx.abort(err)
				return sip.Message{}, err
			}
		}
	}
}

func (s *Session) Send(ctx context.Context, req sip.Message) error {
	if err := s.ensureOpen(); err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	return s.writeRequest(ctx, s.primaryTransport(), req)
}

func (s *Session) writeRequest(ctx context.Context, transport Transport, req sip.Message) error {
	packet, err := messagePacket(req)
	if err != nil {
		return fmt.Errorf("encoding %s request: %w", req.Method(), err)
	}
	s.logger.Debug("sip message", "direction", "send", "start_line", req.StartLine, "sip_message", string(packet))
	if err := s.writePacket(ctx, transport, packet); err != nil {
		return fmt.Errorf("sending %s: %w", req.Method(), err)
	}
	return nil
}

func responseMatchesRequestTransaction(req, resp sip.Message) bool {
	if got, want := sip.PendingKey(resp), sip.PendingKey(req); want != "" && got != want {
		return false
	}
	if want := strings.TrimSpace(sip.TopViaSentBy(req.Header("Via"))); want != "" {
		got := strings.TrimSpace(sip.TopViaSentBy(resp.Header("Via")))
		return strings.EqualFold(got, want)
	}
	return true
}

func exchangeReadTransports(requestTransport Transport, responseTransports []Transport) []Transport {
	if len(responseTransports) == 0 {
		return []Transport{requestTransport}
	}
	return uniqueTransports(responseTransports)
}
