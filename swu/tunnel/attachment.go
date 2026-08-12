package tunnel

import (
	"errors"
	"sync"

	ipsecbase "github.com/damonto/ims-go/ipsec"
	"github.com/damonto/ims-go/ipsec/packet"
)

var errSessionClosed = errors.New("session is closed")

type sessionAttachment struct {
	session   *Session
	processor ipsecbase.InnerPacketProcessor

	mu     sync.RWMutex
	closed bool
	once   sync.Once
}

func (s *Session) Attach(processor ipsecbase.InnerPacketProcessor) (ipsecbase.Attachment, error) {
	if processor == nil {
		return nil, errors.New("attaching inner processor: processor is nil")
	}
	s.attachmentsMu.Lock()
	defer s.attachmentsMu.Unlock()
	if s.isClosed() {
		return nil, errors.New("attaching inner processor: session is closed")
	}
	s.mu.RLock()
	connected := s.connected
	s.mu.RUnlock()
	if !connected {
		return nil, errors.New("attaching inner processor: session is not connected")
	}
	attachment := &sessionAttachment{session: s, processor: processor}
	s.attachments = append(s.attachments, attachment)
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
		if attachment.processor.HandleInnerPacket(pkt) {
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
	a.processor.HandleError(err)
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
