package imsclient

import (
	"fmt"
	"sync"
)

const eventBufferSize = 16

type eventHub struct {
	state  broadcaster[RegistrationState]
	errors broadcaster[error]

	smsIncoming broadcaster[SMS]
	smsReports  broadcaster[SMSReport]
	ussd        broadcaster[IncomingUSSD]
}

func newEventHub() eventHub {
	return eventHub{
		state:       newBroadcaster[RegistrationState](),
		errors:      newBroadcaster[error](),
		smsIncoming: newBroadcaster[SMS](),
		smsReports:  newBroadcaster[SMSReport](),
		ussd:        newBroadcaster[IncomingUSSD](),
	}
}

func (h *eventHub) close() {
	h.state.close()
	h.errors.close()
	h.smsIncoming.close()
	h.smsReports.close()
	h.ussd.close()
}

type broadcaster[T any] struct {
	mu     sync.Mutex
	nextID uint64
	subs   map[uint64]chan T
	closed bool
}

type broadcastSubscription[T any] struct {
	channel <-chan T
	close   func()
}

func newBroadcaster[T any]() broadcaster[T] {
	return broadcaster[T]{subs: make(map[uint64]chan T)}
}

func (b *broadcaster[T]) subscribe(buffer int) broadcastSubscription[T] {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan T, buffer)
	if b.closed {
		close(ch)
		return broadcastSubscription[T]{channel: ch, close: func() {}}
	}

	id := b.nextID
	b.nextID++
	b.subs[id] = ch

	var once sync.Once
	return broadcastSubscription[T]{
		channel: ch,
		close: func() {
			once.Do(func() {
				b.unsubscribe(id)
			})
		},
	}
}

func (b *broadcaster[T]) unsubscribe(id uint64) {
	b.mu.Lock()
	ch, ok := b.subs[id]
	if ok {
		delete(b.subs, id)
	}
	b.mu.Unlock()
	if ok {
		close(ch)
	}
}

func (b *broadcaster[T]) publish(value T, onDrop func()) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}

	targets := make([]chan T, 0, len(b.subs))
	for _, ch := range b.subs {
		targets = append(targets, ch)
	}
	b.mu.Unlock()

	for _, ch := range targets {
		select {
		case ch <- value:
		default:
			if onDrop != nil {
				onDrop()
			}
		}
	}
}

func (b *broadcaster[T]) close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	targets := make([]chan T, 0, len(b.subs))
	for id, ch := range b.subs {
		targets = append(targets, ch)
		delete(b.subs, id)
	}
	b.mu.Unlock()

	for _, ch := range targets {
		close(ch)
	}
}

func (c *Client) Events() *Events {
	stateSub := c.events.state.subscribe(eventBufferSize)
	errorSub := c.events.errors.subscribe(eventBufferSize)
	return &Events{
		State:  stateSub.channel,
		Errors: errorSub.channel,
		closeFn: func() {
			stateSub.close()
			errorSub.close()
		},
	}
}

func (c *Client) Subscribe(fn func(RegistrationState) error) func() {
	events := c.Events()
	if fn != nil {
		go runSubscription(c, "state subscriber", events.State, fn)
	}
	return events.Close
}

func (s *SMSService) Events() *SMSEvents {
	incomingSub := s.client.events.smsIncoming.subscribe(eventBufferSize)
	reportSub := s.client.events.smsReports.subscribe(eventBufferSize)
	return &SMSEvents{
		Incoming: incomingSub.channel,
		Reports:  reportSub.channel,
		closeFn: func() {
			incomingSub.close()
			reportSub.close()
		},
	}
}

func (s *SMSService) Subscribe(fn func(SMS) error) func() {
	events := s.Events()
	if fn != nil {
		go runSubscription(s.client, "sms subscriber", events.Incoming, fn)
	}
	return events.Close
}

func (s *SMSService) SubscribeReports(fn func(SMSReport) error) func() {
	events := s.Events()
	if fn != nil {
		go runSubscription(s.client, "sms report subscriber", events.Reports, fn)
	}
	return events.Close
}

func (s *USSDService) Events() *USSDEvents {
	sub := s.client.events.ussd.subscribe(eventBufferSize)
	return &USSDEvents{
		Incoming: sub.channel,
		closeFn:  sub.close,
	}
}

func (s *USSDService) Subscribe(fn func(IncomingUSSD) error) func() {
	events := s.Events()
	if fn != nil {
		go runSubscription(s.client, "ussd subscriber", events.Incoming, fn)
	}
	return events.Close
}

func runSubscription[T any](client *Client, name string, ch <-chan T, fn func(T) error) {
	for value := range ch {
		if err := fn(value); err != nil {
			client.logger.Warn("subscription callback", "subscriber", name, "err", err)
			client.emitError(fmt.Errorf("%s: %w", name, err))
		}
	}
}

func (c *Client) emitState(state RegistrationState) {
	c.events.state.publish(state, func() {
		c.logger.Debug("dropping state event", "state", state)
	})
}

func (c *Client) emitError(err error) {
	if err == nil {
		return
	}
	c.events.errors.publish(err, func() {
		c.logger.Debug("dropping error event", "err", err)
	})
}

func (c *Client) emitSMS(msg SMS) {
	c.events.smsIncoming.publish(msg, func() {
		c.logger.Debug("dropping sms event", "from", msg.From, "to", msg.To, "service_center", msg.ServiceCenter)
	})
}

func (c *Client) emitSMSReport(report SMSReport) {
	c.events.smsReports.publish(report, func() {
		c.logger.Debug("dropping sms status report event", "recipient", report.Recipient, "service_center", report.ServiceCenter, "message_reference", report.MessageReference, "status", report.Status)
	})
}

func (c *Client) emitIncomingUSSD(event IncomingUSSD) {
	c.events.ussd.publish(event, func() {
		c.logger.Debug("dropping ussd event", "text", event.Message.Text, "request", event.Message.Request, "notify", event.Message.Notify, "final", event.Message.Final)
	})
}
