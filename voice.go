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
	Cause  string
	At     time.Time
}

func (s *VoiceService) Dial(ctx context.Context, req imsvoice.DialRequest) (*imsvoice.Call, error) {
	low, err := s.client.currentVoiceService()
	if err != nil {
		return nil, fmt.Errorf("dialing call: %w", err)
	}
	return low.Dial(ctx, req)
}

func (c *Client) currentVoiceService() (*imsvoice.Service, error) {
	c.mu.Lock()
	active := c.active
	c.mu.Unlock()
	if active == nil || active.voice == nil {
		return nil, ErrClientNotConnected
	}
	return active.voice, nil
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
		Cause:  event.Cause,
		At:     event.At,
	})
}
