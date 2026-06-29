package ussd

import (
	"errors"
	"fmt"
	"github.com/damonto/vowifi-go/ims/sip"
)

var errSessionActive = errors.New("ussd session is active")

func (s *Endpoint) storeSession(session *Session) error {
	key := session.sessionKey()
	if s.hasActiveSession() {
		return fmt.Errorf("storing USSD session: %w", errSessionActive)
	}
	attachment, err := s.sess.RegisterDialog(sip.DialogID{
		CallID:    session.callID,
		LocalTag:  session.localTag,
		RemoteTag: session.remoteTag,
	}, key)
	if err != nil {
		return fmt.Errorf("storing USSD session: %w", err)
	}
	session.dialogAttachment = attachment
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) > 0 {
		_ = attachment.Close()
		session.dialogAttachment = nil
		return fmt.Errorf("storing USSD session: %w", errSessionActive)
	}
	s.sessions[key] = session
	if inviteKey := session.inviteRequestKey(); inviteKey != "" {
		s.incomingIndex[inviteKey] = key
	}
	return nil
}

func (s *Endpoint) ensureNoActiveSession() error {
	if s.hasActiveSession() {
		return errSessionActive
	}
	return nil
}

func (s *Endpoint) hasActiveSession() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions) > 0
}

func (s *Endpoint) lookupSessionByCallID(callID string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, session := range s.sessions {
		if session.callID == callID {
			return session
		}
	}
	return nil
}

func (s *Endpoint) lookupIncomingInviteSession(msg sip.Message) *Session {
	inviteKey := incomingInviteKey(msg)
	if inviteKey == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.incomingIndex[inviteKey]
	if !ok {
		return nil
	}
	return s.sessions[key]
}

func (s *Endpoint) lookupSessionForMessage(msg sip.Message) *Session {
	key, ok := s.sess.LookupDialogKey(msg)
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[key]
}

func (s *Endpoint) removeSession(key string) {
	s.mu.Lock()
	session := s.sessions[key]
	if session != nil {
		delete(s.sessions, key)
		if inviteKey := session.inviteRequestKey(); inviteKey != "" {
			delete(s.incomingIndex, inviteKey)
		}
	}
	s.mu.Unlock()
	if session != nil && session.dialogAttachment != nil {
		_ = session.dialogAttachment.Close()
		session.dialogAttachment = nil
	}
}
