package vowifi

import (
	"context"
	"fmt"
	"time"

	imsvoice "github.com/damonto/vowifi-go/ims/voice"
)

type IncomingCall struct {
	Call       *imsvoice.Call
	From       string
	FromURI    string
	FromNumber string
	Offer      imsvoice.MediaOffer
	ReceivedAt time.Time
}

type CallEvent struct {
	Call   *imsvoice.Call
	CallID string
	State  imsvoice.CallState
	Hold   imsvoice.CallHoldState
	Cause  string
	At     time.Time
}

type VoiceClient struct {
	client *Client
}

func (s *VoiceClient) Dial(ctx context.Context, req imsvoice.DialRequest) (*imsvoice.Call, error) {
	low, err := s.client.currentVoiceClient()
	if err != nil {
		return nil, fmt.Errorf("dialing call: %w", err)
	}
	s.client.logger.Info("dialing call", "to", req.To)
	call, err := low.Dial(ctx, req)
	if err != nil {
		return nil, err
	}
	s.client.logger.Info("call confirmed", "call_id", call.ID(), "to", req.To)
	return call, nil
}

func (c *Client) currentVoiceClient() (*imsvoice.Endpoint, error) {
	return currentIMSEndpoint(c, func(ims imsStack) *imsvoice.Endpoint { return ims.voice })
}

func (c *Client) handleIncomingVoice(event imsvoice.IncomingCall) {
	c.emitIncomingCall(IncomingCall{
		Call:       event.Call,
		From:       event.From,
		FromURI:    event.FromURI,
		FromNumber: event.FromNumber,
		Offer:      event.Offer,
		ReceivedAt: event.Received,
	})
}

func (c *Client) handleVoiceEvent(event imsvoice.CallEvent) {
	c.emitCallEvent(CallEvent{
		Call:   event.Call,
		CallID: event.CallID,
		State:  event.State,
		Hold:   event.Hold,
		Cause:  event.Cause,
		At:     event.At,
	})
}
