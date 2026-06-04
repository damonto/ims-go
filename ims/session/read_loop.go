package session

import (
	"context"

	"github.com/damonto/vowifi-go/ims/sip"
)

func readTransportMessage(ctx context.Context, transport Transport) (inboundMessage, error) {
	packet, peer, err := transport.ReadPacket(ctx)
	if err != nil {
		return inboundMessage{}, err
	}
	msg, err := sip.ParseMessage(packet)
	if err != nil {
		return inboundMessage{}, err
	}
	return inboundMessage{msg: msg, transport: transport, peer: peer}, nil
}

func (s *Session) startBootstrapReadLoop(ctx context.Context, transport Transport, out chan<- inboundMessage) {
	go func() {
		runTransportReadLoop(ctx, transport, out, true)
	}()
}

func (s *Session) startRuntimeReadLoop(ctx context.Context, transport Transport, out chan<- inboundMessage) {
	s.readWG.Go(func() {
		runTransportReadLoop(ctx, transport, out, false)
	})
}

func runTransportReadLoop(ctx context.Context, transport Transport, out chan<- inboundMessage, reportContextError bool) {
	for {
		inbound, err := readTransportMessage(ctx, transport)
		if err != nil {
			if ctx.Err() != nil && !reportContextError {
				return
			}
			_ = sendInbound(ctx, out, inboundMessage{transport: transport, err: err})
			return
		}
		if !sendInbound(ctx, out, inbound) {
			return
		}
	}
}

func sendInbound(ctx context.Context, out chan<- inboundMessage, inbound inboundMessage) bool {
	select {
	case out <- inbound:
		return true
	case <-ctx.Done():
		return false
	}
}
