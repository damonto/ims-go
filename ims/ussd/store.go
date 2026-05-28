package ussd

import (
	"fmt"
	"github.com/damonto/ims-client/ims/sip"
)

func (s *Service) storeSession(ussdSession *Session) error {
	key := ussdSession.sessionKey()
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
	s.sessions[key] = ussdSession
	if inviteKey := ussdSession.inviteRequestKey(); inviteKey != "" {
		s.incomingIndex[inviteKey] = key
	}
	return nil
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
