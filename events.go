package ims

import "sync"

const eventBufferSize = 16

// Events provides client state, registration changes, and asynchronous errors.
type Events struct {
	State  <-chan ClientState
	Errors <-chan error

	// RegistrationChanged coalesces changes. Subscribe before calling
	// Client.Registration, then read a fresh snapshot after each notification.
	RegistrationChanged <-chan struct{}

	closeOnce sync.Once
	closeFn   func()
}

func (e *Events) Close() {
	e.closeOnce.Do(e.closeFn)
}

type SMSEvents struct {
	Incoming <-chan SMS
	Reports  <-chan SMSReport

	closeOnce sync.Once
	closeFn   func()
}

func (e *SMSEvents) Close() {
	e.closeOnce.Do(e.closeFn)
}

type USSDEvents struct {
	Incoming <-chan IncomingUSSD

	closeOnce sync.Once
	closeFn   func()
}

func (e *USSDEvents) Close() {
	e.closeOnce.Do(e.closeFn)
}

type VoiceEvents struct {
	Incoming <-chan IncomingCall
	Events   <-chan CallEvent

	closeOnce sync.Once
	closeFn   func()
}

func (e *VoiceEvents) Close() {
	e.closeOnce.Do(e.closeFn)
}

type eventHub struct {
	state               broadcaster[ClientState]
	errors              broadcaster[error]
	registrationChanged broadcaster[struct{}]

	smsIncoming broadcaster[SMS]
	smsReports  broadcaster[SMSReport]
	ussd        broadcaster[IncomingUSSD]
	voiceIn     broadcaster[IncomingCall]
	voiceEvents broadcaster[CallEvent]
}

func newEventHub() eventHub {
	return eventHub{
		state:               newBroadcaster[ClientState](),
		errors:              newBroadcaster[error](),
		registrationChanged: newBroadcaster[struct{}](),
		smsIncoming:         newBroadcaster[SMS](),
		smsReports:          newBroadcaster[SMSReport](),
		ussd:                newBroadcaster[IncomingUSSD](),
		voiceIn:             newBroadcaster[IncomingCall](),
		voiceEvents:         newBroadcaster[CallEvent](),
	}
}

func (h *eventHub) close() {
	h.state.close()
	h.errors.close()
	h.registrationChanged.close()
	h.smsIncoming.close()
	h.smsReports.close()
	h.ussd.close()
	h.voiceIn.close()
	h.voiceEvents.close()
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
		close(ch)
	}
	b.mu.Unlock()
}

func (b *broadcaster[T]) publish(value T, onDrop func()) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}

	dropped := 0
	for _, ch := range b.subs {
		select {
		case ch <- value:
		default:
			dropped++
		}
	}
	b.mu.Unlock()

	if onDrop == nil {
		return
	}
	for range dropped {
		onDrop()
	}
}

func (b *broadcaster[T]) close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	for id, ch := range b.subs {
		delete(b.subs, id)
		close(ch)
	}
	b.mu.Unlock()
}

// Events subscribes to future changes. Close the subscription when it is no
// longer needed; registration notifications are paired with Registration reads.
func (c *Client) Events() *Events {
	stateSub := c.events.state.subscribe(eventBufferSize)
	errorSub := c.events.errors.subscribe(eventBufferSize)
	registrationSub := c.events.registrationChanged.subscribe(1)
	return &Events{
		State:               stateSub.channel,
		Errors:              errorSub.channel,
		RegistrationChanged: registrationSub.channel,
		closeFn: func() {
			stateSub.close()
			errorSub.close()
			registrationSub.close()
		},
	}
}

func (s *SMSClient) Events() *SMSEvents {
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

func (s *USSDClient) Events() *USSDEvents {
	sub := s.client.events.ussd.subscribe(eventBufferSize)
	return &USSDEvents{
		Incoming: sub.channel,
		closeFn:  sub.close,
	}
}

func (s *VoiceClient) Events() *VoiceEvents {
	incomingSub := s.client.events.voiceIn.subscribe(eventBufferSize)
	eventSub := s.client.events.voiceEvents.subscribe(eventBufferSize)
	return &VoiceEvents{
		Incoming: incomingSub.channel,
		Events:   eventSub.channel,
		closeFn: func() {
			incomingSub.close()
			eventSub.close()
		},
	}
}

func (c *Client) emitStatus(status ClientStatus) {
	snapshot := c.transitionStatus(status, nil)
	c.publishState(snapshot)
}

func (c *Client) emitError(err error) {
	if err == nil {
		return
	}
	snapshot := c.transitionStatus("", err)
	c.publishError(snapshot, err)
}

func (c *Client) emitStatusError(status ClientStatus, err error) {
	if err == nil {
		c.emitStatus(status)
		return
	}
	snapshot := c.transitionStatus(status, err)
	c.publishError(snapshot, err)
	c.publishState(snapshot)
}

func (c *Client) publishState(snapshot ClientState) {
	c.logger.Info("client status", "status", snapshot.Status, "active", snapshot.Active, "connecting", snapshot.Connecting, "reconnecting", snapshot.Reconnecting)
	c.events.state.publish(snapshot, func() {
		c.logger.Debug("dropping status event", "status", snapshot.Status)
	})
}

func (c *Client) publishError(snapshot ClientState, err error) {
	c.logger.Error("client error", "err", err, "status", snapshot.Status, "active", snapshot.Active, "connecting", snapshot.Connecting, "reconnecting", snapshot.Reconnecting)
	c.events.errors.publish(err, func() {
		c.logger.Debug("dropping error event", "err", err)
	})
}

func (c *Client) emitSMS(msg SMS) {
	c.logger.Info("incoming SMS", "from", msg.From, "from_uri", msg.FromURI, "to", msg.To, "service_center", msg.ServiceCenter)
	c.events.smsIncoming.publish(msg, func() {
		c.logger.Debug("dropping sms event", "from", msg.From, "from_uri", msg.FromURI, "to", msg.To, "service_center", msg.ServiceCenter)
	})
}

func (c *Client) emitSMSReport(report SMSReport) {
	c.logger.Info("SMS status report", "recipient", report.Recipient, "service_center", report.ServiceCenter, "message_reference", report.MessageReference, "status", report.Status)
	c.events.smsReports.publish(report, func() {
		c.logger.Debug("dropping sms status report event", "recipient", report.Recipient, "service_center", report.ServiceCenter, "message_reference", report.MessageReference, "status", report.Status)
	})
}

func (c *Client) emitIncomingUSSD(event IncomingUSSD) {
	c.logger.Info("incoming USSD", "request", event.Message.Request, "notify", event.Message.Notify, "final", event.Message.Final, "error_code", event.Message.ErrorCode)
	c.events.ussd.publish(event, func() {
		c.logger.Debug("dropping ussd event", "text", event.Message.Text, "request", event.Message.Request, "notify", event.Message.Notify, "final", event.Message.Final)
	})
}

func (c *Client) emitIncomingCall(event IncomingCall) {
	c.logger.Info("incoming call", "from", event.From, "from_number", event.FromNumber)
	c.events.voiceIn.publish(event, func() {
		c.logger.Debug("dropping incoming call event", "from", event.From)
	})
}

func (c *Client) emitCallEvent(event CallEvent) {
	c.logger.Info("call event", "call_id", event.CallID, "state", event.State, "cause", event.Cause)
	c.events.voiceEvents.publish(event, func() {
		c.logger.Debug("dropping call event", "call_id", event.CallID, "state", event.State)
	})
}
