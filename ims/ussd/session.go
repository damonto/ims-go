package ussd

import (
	"context"
	"fmt"
	"github.com/damonto/vowifi-go/ims/sip"
	"strings"
)

func (s *Session) Events() <-chan Message {
	return s.events
}

func (s *Session) Reply(ctx context.Context, text string) error {
	if err := s.ensureActive("replying USSD"); err != nil {
		return err
	}
	payload, err := s.marshalDialogPayload(Message{Text: text, Language: s.currentLanguage()})
	if err != nil {
		return fmt.Errorf("replying USSD: encoding XML payload: %w", err)
	}
	msg := s.buildDialogRequest("INFO", payload)
	msg.Headers.Add("Info-Package", infoPackage)
	msg.Headers.Add("Content-Disposition", infoPackageDisposition)
	msg.Headers.Add("Content-Type", xmlContentType)
	if queued, err := s.queueInitialRequest(ctx, msg, "replying USSD", false); queued || err != nil {
		return err
	}
	return s.exchange(ctx, msg, "replying USSD")
}

func (s *Session) ReplyError(ctx context.Context, errorCode int) error {
	if err := s.ensureActive("replying USSD"); err != nil {
		return err
	}
	payload, err := (xmlBody{Message: Message{Language: s.currentLanguage(), ErrorCode: normalizeErrorCode(errorCode)}}).MarshalText()
	if err != nil {
		return fmt.Errorf("replying USSD: encoding error payload: %w", err)
	}
	msg := s.buildDialogRequest("INFO", payload)
	msg.Headers.Add("Info-Package", infoPackage)
	msg.Headers.Add("Content-Disposition", infoPackageDisposition)
	msg.Headers.Add("Content-Type", xmlContentType)
	if queued, err := s.queueInitialRequest(ctx, msg, "replying USSD", false); queued || err != nil {
		return err
	}
	return s.exchange(ctx, msg, "replying USSD")
}

func (s *Session) End(ctx context.Context, text string) error {
	if err := s.ensureActive("ending USSD"); err != nil {
		return err
	}
	var payload []byte
	if strings.TrimSpace(text) != "" {
		encoded, err := s.marshalDialogPayload(Message{Text: text, Language: s.currentLanguage(), Final: true})
		if err != nil {
			return fmt.Errorf("ending USSD: encoding XML payload: %w", err)
		}
		payload = encoded
	}
	msg := s.buildDialogRequest("BYE", payload)
	if len(payload) > 0 {
		msg.Headers.Add("Content-Type", xmlContentType)
	}
	if queued, err := s.queueInitialRequest(ctx, msg, "ending USSD", true); queued || err != nil {
		return err
	}
	if err := s.exchange(ctx, msg, "ending USSD"); err != nil {
		return err
	}
	s.finish(false)
	return nil
}

func (s *Session) EndError(ctx context.Context, errorCode int) error {
	if err := s.ensureActive("ending USSD"); err != nil {
		return err
	}
	payload, err := (xmlBody{Message: Message{Language: s.currentLanguage(), ErrorCode: normalizeErrorCode(errorCode), Final: true}}).MarshalText()
	if err != nil {
		return fmt.Errorf("ending USSD: encoding error payload: %w", err)
	}
	msg := s.buildDialogRequest("BYE", payload)
	msg.Headers.Add("Content-Type", xmlContentType)
	if queued, err := s.queueInitialRequest(ctx, msg, "ending USSD", true); queued || err != nil {
		return err
	}
	if err := s.exchange(ctx, msg, "ending USSD"); err != nil {
		return err
	}
	s.finish(false)
	return nil
}

func (s *Session) endDirect(ctx context.Context, text string) error {
	var payload []byte
	if strings.TrimSpace(text) != "" {
		encoded, err := s.marshalDialogPayload(Message{Text: text, Language: s.currentLanguage(), Final: true})
		if err != nil {
			return fmt.Errorf("ending USSD: encoding XML payload: %w", err)
		}
		payload = encoded
	}
	msg := s.buildDialogRequest("BYE", payload)
	if len(payload) > 0 {
		msg.Headers.Add("Content-Type", xmlContentType)
	}
	if err := s.exchange(ctx, msg, "ending USSD"); err != nil {
		return err
	}
	return nil
}

func (s *Session) marshalDialogPayload(msg Message) ([]byte, error) {
	if s.networkInitiated {
		switch s.dialogKind() {
		case dialogKindRequest:
			msg.Request = true
		case dialogKindNotify:
			msg.Notify = true
		}
	}
	return (xmlBody{Message: msg}).MarshalText()
}

func (s *Session) dialogKind() dialogKind {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.responseKind
}

func (s *Session) currentLanguage() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.language
}

func (s *Session) setLanguage(language string) {
	if strings.TrimSpace(language) == "" {
		return
	}
	s.mu.Lock()
	s.language = language
	s.mu.Unlock()
}

func (s *Session) ensureActive(action string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == sessionStateClosed {
		return fmt.Errorf("%s: session is closed", action)
	}
	return nil
}

func (s *Session) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == sessionStateClosed
}

func (s *Session) waitForACK(ctx context.Context, action string) error {
	s.mu.Lock()
	if !s.networkInitiated || s.acked || s.ackCh == nil {
		s.mu.Unlock()
		return nil
	}
	ackCh := s.ackCh
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return fmt.Errorf("%s: %w", action, ctx.Err())
	case <-ackCh:
		return nil
	}
}

func (s *Session) exchange(ctx context.Context, msg sip.Message, action string) error {
	releaseInfo := false
	if strings.EqualFold(msg.Method(), "INFO") {
		if err := s.beginInfoExchange(action); err != nil {
			return err
		}
		releaseInfo = true
		defer func() {
			if releaseInfo {
				s.releaseInfoExchange()
			}
		}()
	}
	if err := s.waitForACK(ctx, action); err != nil {
		return err
	}
	resp, err := s.service.sess.Exchange(ctx, msg)
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	if resp.StatusCode() != sipStatusOK {
		return fmt.Errorf("%s: unexpected response: %w", action, sip.NewResponseError(resp))
	}
	releaseInfo = false
	return nil
}

func (s *Session) beginInfoExchange(action string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.state {
	case sessionStateClosed:
		return fmt.Errorf("%s: session is closed", action)
	case sessionStateInfoInFlight, sessionStateWaitingACKInfoInFlight:
		return fmt.Errorf("%s: awaiting remote INFO", action)
	case sessionStateWaitingACK:
		s.state = sessionStateWaitingACKInfoInFlight
	default:
		s.state = sessionStateInfoInFlight
	}
	return nil
}

func (s *Session) releaseInfoExchange() {
	s.mu.Lock()
	switch s.state {
	case sessionStateInfoInFlight:
		s.state = sessionStateActive
	case sessionStateWaitingACKInfoInFlight:
		s.state = sessionStateWaitingACK
	}
	s.mu.Unlock()
}
