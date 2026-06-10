package session

import (
	"context"
	"strings"

	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Session) dispatchInbound(ctx context.Context, inbound inboundMessage) error {
	text, err := inbound.msg.MarshalText()
	if err != nil {
		s.logger.Debug("sip message", "direction", "recv", "start_line", inbound.msg.StartLine, "marshal_error", err)
	} else {
		s.logger.Debug("sip message", "direction", "recv", "start_line", inbound.msg.StartLine, "sip_message", string(text))
	}
	if inbound.msg.IsRequest() {
		return s.handleInboundRequest(ctx, Request{Message: inbound.msg, Transport: inbound.transport, PeerAddr: inbound.peer})
	}
	if !s.dispatchResponse(inbound) {
		return s.handleInboundResponse(ctx, inbound.msg)
	}
	return nil
}

func (s *Session) handleRequest(ctx context.Context, req Request) error {
	handled, err := s.dispatchRequest(ctx, req)
	if err != nil {
		return err
	}
	if handled {
		return nil
	}
	if req.Message.Method() == "ACK" {
		return nil
	}
	if strings.EqualFold(req.Message.Method(), "BYE") {
		return s.WriteStatus(ctx, req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist")
	}
	resp := sip.NewResponse(sipStatusMethodNotAllowed, "Method Not Allowed")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusMethodNotAllowed)
	resp.Headers.Add("Allow", sip.DefaultClientAllow)
	return s.WriteResponse(ctx, req, resp)
}

func (s *Session) dispatchRequest(ctx context.Context, req Request) (bool, error) {
	for _, entry := range s.handlerSnapshot() {
		handler, ok := entry.handlerIfOpen()
		if !ok {
			continue
		}
		handled, err := handler.HandleRequest(ctx, req)
		if err != nil {
			return false, err
		}
		if handled {
			return true, nil
		}
	}
	return false, nil
}

func (s *Session) handleInboundResponse(ctx context.Context, msg sip.Message) error {
	for _, entry := range s.handlerSnapshot() {
		handler, ok := entry.handlerIfOpen()
		if !ok {
			continue
		}
		responseHandler, ok := handler.(ResponseHandler)
		if !ok {
			continue
		}
		handled, err := responseHandler.HandleResponse(ctx, msg)
		if err != nil {
			return err
		}
		if handled {
			return nil
		}
	}
	return nil
}

func isProvisionalResponse(msg sip.Message) bool {
	status := msg.StatusCode()
	return status >= 100 && status < 200
}
