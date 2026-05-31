package ussd

import (
	"errors"
	"fmt"
	"github.com/damonto/vowifi-go/ims/sip"
)

var errSessionActive = errors.New("ussd session is active")

func (s *Service) storeSession(ussdSession *Session) error {
	key := ussdSession.sessionKey()
	if s.hasActiveSession() {
		return fmt.Errorf("storing USSD session: %w", errSessionActive)
	}
	attachment, err := s.sess.RegisterDialog(sip.DialogID{
		CallID:    ussdSession.callID,
		LocalTag:  ussdSession.localTag,
		RemoteTag: ussdSession.remoteTag,
	}, key)
	if err != nil {
		return fmt.Errorf("storing USSD session: %w", err)
	}
	ussdSession.dialogAttachment = attachment
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) > 0 {
		_ = attachment.Close()
		ussdSession.dialogAttachment = nil
		return fmt.Errorf("storing USSD session: %w", errSessionActive)
	}
	s.sessions[key] = ussdSession
	if inviteKey := ussdSession.inviteRequestKey(); inviteKey != "" {
		s.incomingIndex[inviteKey] = key
	}
	return nil
}

func (s *Service) ensureNoActiveSession(action string) error {
	if s.hasActiveSession() {
		return fmt.Errorf("%s: %w", action, errSessionActive)
	}
	return nil
}

func (s *Service) hasActiveSession() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions) > 0
}

func (s *Service) lookupSessionByCallID(callID string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ussdSession := range s.sessions {
		if ussdSession.callID == callID {
			return ussdSession
		}
	}
	return nil
}

func (s *Service) lookupIncomingInviteSession(msg sip.Message) *Session {
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

func (s *Service) lookupSessionForMessage(msg sip.Message) *Session {
	key, ok := s.sess.LookupDialogKey(msg)
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[key]
}

func (s *Service) removeSession(key string) {
	s.mu.Lock()
	ussdSession := s.sessions[key]
	if ussdSession != nil {
		delete(s.sessions, key)
		if inviteKey := ussdSession.inviteRequestKey(); inviteKey != "" {
			delete(s.incomingIndex, inviteKey)
		}
	}
	s.mu.Unlock()
	if ussdSession != nil && ussdSession.dialogAttachment != nil {
		_ = ussdSession.dialogAttachment.Close()
		ussdSession.dialogAttachment = nil
	}
}
