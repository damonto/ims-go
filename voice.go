package imsclient

import (
	"context"
	"fmt"
	"time"

	imscall "github.com/damonto/ims-client/ims/call"
)

type IncomingCall struct {
	Call       *imscall.Call
	From       string
	FromURI    string
	FromNumber string
	Offer      imscall.MediaOffer
	ReceivedAt time.Time
}

type CallEvent struct {
	Call   *imscall.Call
	CallID string
	State  imscall.State
	Cause  string
	At     time.Time
}

func (s *VoiceService) Dial(ctx context.Context, req imscall.Request) (*imscall.Call, error) {
	low, err := s.client.currentVoiceService()
	if err != nil {
		return nil, fmt.Errorf("dialing call: %w", err)
	}
	return low.Dial(ctx, req)
}

func (c *Client) currentVoiceService() (*imscall.Service, error) {
	c.mu.Lock()
	active := c.active
	c.mu.Unlock()
	if active == nil || active.call == nil {
		return nil, ErrClientNotConnected
	}
	return active.call, nil
}

func (c *Client) handleIncomingCall(event imscall.Incoming) {
	c.emitIncomingCall(IncomingCall{
		Call:       event.Call,
		From:       event.From,
		FromURI:    event.FromURI,
		FromNumber: event.FromNumber,
		Offer:      event.Offer,
		ReceivedAt: event.Received,
	})
}

func (c *Client) handleCallEvent(event imscall.Event) {
	c.emitCallEvent(CallEvent{
		Call:   event.Call,
		CallID: event.CallID,
		State:  event.State,
		Cause:  event.Cause,
		At:     event.At,
	})
}
