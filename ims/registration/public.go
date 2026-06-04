package registration

import (
	"context"
	"strings"

	"github.com/damonto/vowifi-go/ims/security"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Service) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state
	state.Flow = s.flow.clone()
	state.ServiceRoutes = append([]string(nil), state.Flow.ServiceRoutes...)
	state.SecurityClient = state.Flow.SecurityClient
	state.SecurityClients = append(security.Params(nil), state.Flow.SecurityClients...)
	state.SecurityVerify = nil
	if state.Flow.SecurityVerify != nil {
		verify := *state.Flow.SecurityVerify
		state.SecurityVerify = &verify
	}
	state.ContactHost = state.Flow.ContactHost
	state.RegisterPort = state.Flow.RegisterPort
	state.MessagePort = state.Flow.MessagePort
	return state
}

func (s *Service) CurrentFlow() Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flow.clone()
}

func (s *Service) SecurityVerifyValue() string {
	return s.CurrentFlow().SecurityVerifyValue()
}

func (s *Service) RequestPolicy() sip.ClientRequestPolicy {
	state := s.State()
	return state.Flow.requestPolicy(s.preloadedRoutes(state.Flow), state.UserAgent, state.AccessNetworkInfo)
}

func (s *Service) DialogRequestPolicy(routes []string) sip.ClientRequestPolicy {
	state := s.State()
	return state.Flow.DialogRequestPolicy(routes, state.UserAgent, state.AccessNetworkInfo)
}

func (s *Service) StrictDialogRequestPolicy(routes []string) sip.ClientRequestPolicy {
	state := s.State()
	return state.Flow.StrictDialogRequestPolicy(routes, state.UserAgent, state.AccessNetworkInfo)
}

func (s *Service) Close() error {
	s.closeSecureResources()
	err := s.closeAttachment()
	s.setRegistered(false)
	return err
}

func (s *Service) closeAttachment() error {
	s.mu.Lock()
	attachment := s.attachment
	s.attachment = nil
	s.mu.Unlock()
	if attachment == nil {
		return nil
	}
	return attachment.Close()
}

func (s *Service) HandleRequest(ctx context.Context, req session.Request) (bool, error) {
	if !strings.EqualFold(req.Message.Method(), "NOTIFY") {
		return false, nil
	}
	if !s.notifyMatchesSubscription(req.Message) {
		return true, s.sess.WriteStatus(ctx, req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist")
	}
	if status, reason := s.recordNotifyCSeq(req.Message); status != 0 {
		return true, s.sess.WriteStatus(ctx, req, status, reason)
	}
	s.applySubscriptionStateFromNotify(req.Message)
	notifyErr := s.applyRegInfoNotify(req.Message)
	if err := s.sess.WriteStatus(ctx, req, sipStatusOK, "OK"); err != nil {
		return true, err
	}
	if notifyErr != nil {
		s.publishRegistrationEvent(notifyErr)
	}
	return true, nil
}

func (s *Service) HandleError(err error) {
	if err == nil {
		return
	}
	s.logger.Warn("IMS registration session error", "err", err)
}
