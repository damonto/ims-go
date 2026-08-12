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

type processorEntry struct {
	session   *Stack
	processor RequestProcessor
	closed    bool
}

type transportAttachment struct {
	session   *Stack
	transport Transport
	closed    bool
}

type responseRouteAttachment struct {
	session *Stack
	from    Transport
	to      Transport
	closed  bool
}

func (s *Stack) Attach(h RequestProcessor) (Attachment, error) {
	if h == nil {
		return nil, errors.New("attaching processor: processor is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("attaching processor: session is closed")
	}
	entry := &processorEntry{session: s, processor: h}
	s.processors = append(s.processors, entry)
	return entry, nil
}

func (s *Stack) AddTransport(t Transport) (Attachment, error) {
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
	if _, ok := s.active[t]; ok {
		s.mu.Unlock()
		return nil, errors.New("adding transport: transport is already active")
	}
	attachment := &transportAttachment{session: s, transport: t}
	s.aux = append(s.aux, t)
	s.active[t] = struct{}{}
	s.attachments[t] = attachment
	s.startReadLoop(t)
	s.mu.Unlock()
	return attachment, nil
}

// RouteResponses binds requests received on one transport to responses sent on another.
func (s *Stack) RouteResponses(from, to Transport) (Attachment, error) {
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

func (s *Stack) ReplacePrimary(t Transport) error {
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
	if old == t {
		s.mu.Unlock()
		return nil
	}
	if _, ok := s.active[t]; ok {
		s.mu.Unlock()
		return errors.New("replacing primary transport: transport is already active; use PromotePrimary")
	}
	_, oldActive := s.active[old]
	s.primary = t
	s.primaryErr = nil
	delete(s.active, old)
	s.removeResponseRoutesFor(old)
	s.active[t] = struct{}{}
	s.startReadLoop(t)
	s.mu.Unlock()
	if old != nil && oldActive {
		if err := old.Close(); err != nil {
			return fmt.Errorf("replacing primary transport: %w", err)
		}
	}
	return nil
}

func (s *Stack) PromotePrimary(t Transport) (Attachment, error) {
	if t == nil {
		return nil, errors.New("promoting primary transport: transport is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("promoting primary transport: session is closed")
	}
	// A stopped session still owns its active transports. Allowing promotion
	// during teardown lets protocol layers restore an unprotected primary before
	// detaching the protected transport; a closed session owns nothing.
	if _, ok := s.active[t]; !ok {
		return nil, errors.New("promoting primary transport: transport is not active")
	}
	old := s.primary
	if old == t {
		return nil, nil
	}
	if attachment := s.attachments[t]; attachment != nil {
		attachment.closed = true
		delete(s.attachments, t)
	}
	s.primary = t
	s.primaryErr = nil
	s.aux = removeTransport(s.aux, t)
	var oldAttachment *transportAttachment
	if _, ok := s.active[old]; old != nil && ok {
		s.aux = append(s.aux, old)
		oldAttachment = &transportAttachment{session: s, transport: old}
		s.attachments[old] = oldAttachment
	}
	return oldAttachment, nil
}

func (s *Stack) processorSnapshot() []*processorEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.processorSnapshotCopy()
}

func (s *Stack) processorSnapshotCopy() []*processorEntry {
	snapshot := make([]*processorEntry, 0, len(s.processors))
	for _, entry := range s.processors {
		if entry.closed {
			continue
		}
		snapshot = append(snapshot, entry)
	}
	return snapshot
}

func (s *Stack) notifyProcessorsOnce(processors []*processorEntry, err error) {
	notify := false
	s.notifyOnce.Do(func() {
		notify = true
	})
	if !notify {
		return
	}
	for _, entry := range processors {
		processor, ok := entry.processorIfOpen()
		if !ok {
			continue
		}
		errorObserver, ok := processor.(ErrorObserver)
		if ok {
			errorObserver.HandleError(err)
		}
	}
}

func (s *Stack) notifyProcessors(err error) {
	for _, entry := range s.processorSnapshot() {
		processor, ok := entry.processorIfOpen()
		if !ok {
			continue
		}
		if errorObserver, ok := processor.(ErrorObserver); ok {
			errorObserver.HandleError(err)
		}
	}
}

func (a *processorEntry) Close() error {
	a.session.mu.Lock()
	defer a.session.mu.Unlock()
	a.closed = true
	return nil
}

func (a *processorEntry) processorIfOpen() (RequestProcessor, bool) {
	a.session.mu.Lock()
	defer a.session.mu.Unlock()
	if a.closed {
		return nil, false
	}
	return a.processor, true
}

func (a *transportAttachment) Close() error {
	a.session.mu.Lock()
	if a.closed {
		a.session.mu.Unlock()
		return nil
	}
	if a.session.attachments[a.transport] != a {
		a.closed = true
		a.session.mu.Unlock()
		return nil
	}
	a.closed = true
	delete(a.session.attachments, a.transport)
	delete(a.session.active, a.transport)
	a.session.removeResponseRoutesFor(a.transport)
	a.session.aux = removeTransport(a.session.aux, a.transport)
	a.session.mu.Unlock()
	a.session.abortTransportKeepAlives(a.transport, errors.New("waiting for keepalive: transport was detached"))
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

func (s *Stack) removeResponseRoutesFor(transport Transport) {
	for from, to := range s.responseRoutes {
		if from == transport || to == transport {
			delete(s.responseRoutes, from)
		}
	}
}
