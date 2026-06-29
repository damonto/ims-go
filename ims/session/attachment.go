package session

import (
	"errors"
	"fmt"
)

type Attachment interface {
	Close() error
}

type TransportAttachment interface {
	Attachment
	Transport() Transport
}

type handlerEntry struct {
	session *Session
	handler Handler
	closed  bool
}

type transportAttachment struct {
	session   *Session
	transport Transport
	closed    bool
}

type responseRouteAttachment struct {
	session *Session
	from    Transport
	to      Transport
	closed  bool
}

func (s *Session) Attach(h Handler) (Attachment, error) {
	if h == nil {
		return nil, errors.New("attaching handler: handler is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("attaching handler: session is closed")
	}
	entry := &handlerEntry{session: s, handler: h}
	s.handlers = append(s.handlers, entry)
	return entry, nil
}

func (s *Session) AddTransport(t Transport) (Attachment, error) {
	if t == nil {
		return nil, errors.New("adding transport: transport is nil")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errors.New("adding transport: session is closed")
	}
	if s.started && !s.running {
		s.mu.Unlock()
		return nil, errors.New("adding transport: session has stopped")
	}
	s.aux = append(s.aux, t)
	s.active[t] = struct{}{}
	run := s.run
	running := s.running
	s.mu.Unlock()

	if running {
		s.startReadLoop(run.ctx, t, run.inbound)
	}
	return &transportAttachment{session: s, transport: t}, nil
}

// RouteResponses binds requests received on one transport to responses sent on another.
func (s *Session) RouteResponses(from, to Transport) (Attachment, error) {
	if from == nil {
		return nil, errors.New("routing responses: source transport is nil")
	}
	if to == nil {
		return nil, errors.New("routing responses: response transport is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("routing responses: session is closed")
	}
	if _, ok := s.active[from]; !ok {
		return nil, errors.New("routing responses: source transport is not active")
	}
	if _, ok := s.active[to]; !ok {
		return nil, errors.New("routing responses: response transport is not active")
	}
	s.responseRoutes[from] = to
	return &responseRouteAttachment{session: s, from: from, to: to}, nil
}

func (s *Session) ReplacePrimary(t Transport) error {
	if t == nil {
		return errors.New("replacing primary transport: transport is nil")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("replacing primary transport: session is closed")
	}
	if s.started {
		s.mu.Unlock()
		return errors.New("replacing primary transport: session has already started")
	}
	old := s.primary
	s.primary = t
	delete(s.active, old)
	s.active[t] = struct{}{}
	s.mu.Unlock()
	if old != nil && old != t {
		if err := old.Close(); err != nil {
			return fmt.Errorf("replacing primary transport: %w", err)
		}
	}
	return nil
}

func (s *Session) PromotePrimary(t Transport) (Attachment, error) {
	if t == nil {
		return nil, errors.New("promoting primary transport: transport is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("promoting primary transport: session is closed")
	}
	if s.started && !s.running {
		return nil, errors.New("promoting primary transport: session has stopped")
	}
	if _, ok := s.active[t]; !ok {
		return nil, errors.New("promoting primary transport: transport is not active")
	}
	old := s.primary
	if old == t {
		return nil, nil
	}
	s.primary = t
	s.aux = removeTransport(s.aux, t)
	if old != nil {
		s.aux = append(s.aux, old)
	}
	return &transportAttachment{session: s, transport: old}, nil
}

func (s *Session) handlerSnapshot() []*handlerEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handlerSnapshotCopy()
}

func (s *Session) handlerSnapshotCopy() []*handlerEntry {
	snapshot := make([]*handlerEntry, 0, len(s.handlers))
	for _, entry := range s.handlers {
		if entry.closed {
			continue
		}
		snapshot = append(snapshot, entry)
	}
	return snapshot
}

func (s *Session) notifyHandlersOnce(handlers []*handlerEntry, err error) {
	notify := false
	s.notifyOnce.Do(func() {
		notify = true
	})
	if !notify {
		return
	}
	for _, entry := range handlers {
		handler, ok := entry.handlerIfOpen()
		if !ok {
			continue
		}
		errorHandler, ok := handler.(ErrorHandler)
		if ok {
			errorHandler.HandleError(err)
		}
	}
}

func (a *handlerEntry) Close() error {
	a.session.mu.Lock()
	defer a.session.mu.Unlock()
	a.closed = true
	return nil
}

func (a *handlerEntry) handlerIfOpen() (Handler, bool) {
	a.session.mu.Lock()
	defer a.session.mu.Unlock()
	if a.closed {
		return nil, false
	}
	return a.handler, true
}

func (a *transportAttachment) Close() error {
	a.session.mu.Lock()
	if a.closed {
		a.session.mu.Unlock()
		return nil
	}
	a.closed = true
	delete(a.session.active, a.transport)
	a.session.removeResponseRoutesFor(a.transport)
	a.session.aux = removeTransport(a.session.aux, a.transport)
	a.session.mu.Unlock()
	return a.transport.Close()
}

func (a *transportAttachment) Transport() Transport {
	return a.transport
}

func (a *responseRouteAttachment) Close() error {
	a.session.mu.Lock()
	defer a.session.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	if a.session.responseRoutes[a.from] == a.to {
		delete(a.session.responseRoutes, a.from)
	}
	return nil
}

func (s *Session) removeResponseRoutesFor(transport Transport) {
	for from, to := range s.responseRoutes {
		if from == transport || to == transport {
			delete(s.responseRoutes, from)
		}
	}
}
