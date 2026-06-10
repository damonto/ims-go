package tunnel

import (
	"errors"
	"sync"

	"github.com/damonto/vowifi-go/swu/packet"
)

var errSessionClosed = errors.New("session is closed")

type InnerHandler interface {
	HandleInnerPacket(pkt packet.InnerPacket) bool
	HandleError(err error)
}

type Attachment interface {
	Close() error
}

type sessionAttachment struct {
	session *Session
	handler InnerHandler

	mu     sync.RWMutex
	closed bool
	once   sync.Once
}

func (s *Session) Attach(handler InnerHandler) (Attachment, error) {
	if handler == nil {
		return nil, errors.New("attaching inner handler: handler is nil")
	}
	if s.isClosed() {
		return nil, errors.New("attaching inner handler: session is closed")
	}
	s.mu.RLock()
	connected := s.connected
	s.mu.RUnlock()
	if !connected {
		return nil, errors.New("attaching inner handler: session is not connected")
	}
	attachment := &sessionAttachment{session: s, handler: handler}
	s.attachmentsMu.Lock()
	s.attachments = append(s.attachments, attachment)
	s.attachmentsMu.Unlock()
	return attachment, nil
}

func (s *Session) dispatchInnerPacket(pkt packet.InnerPacket) bool {
	s.attachmentsMu.RLock()
	attachments := append([]*sessionAttachment(nil), s.attachments...)
	s.attachmentsMu.RUnlock()
	for _, attachment := range attachments {
		if attachment == nil || attachment.isClosed() {
			continue
		}
		if attachment.handler.HandleInnerPacket(pkt) {
			return true
		}
	}
	return false
}

func (s *Session) removeAttachment(target *sessionAttachment) {
	s.attachmentsMu.Lock()
	defer s.attachmentsMu.Unlock()
	for i, attachment := range s.attachments {
		if attachment != target {
			continue
		}
		s.attachments = append(s.attachments[:i], s.attachments[i+1:]...)
		return
	}
}

func (s *Session) detachAllAttachments() []*sessionAttachment {
	s.attachmentsMu.Lock()
	defer s.attachmentsMu.Unlock()
	attachments := append([]*sessionAttachment(nil), s.attachments...)
	s.attachments = nil
	return attachments
}

func (a *sessionAttachment) Close() error {
	a.close()
	return nil
}

func (a *sessionAttachment) fail(err error) {
	if !a.close() {
		return
	}
	a.handler.HandleError(err)
}

func (a *sessionAttachment) close() bool {
	closed := false
	a.once.Do(func() {
		closed = true
		a.mu.Lock()
		a.closed = true
		a.mu.Unlock()
		if a.session != nil {
			a.session.removeAttachment(a)
		}
	})
	return closed
}

func (a *sessionAttachment) isClosed() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.closed
}
