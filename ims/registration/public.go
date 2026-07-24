package registration

import (
	"context"
	"errors"
	"strings"

	"github.com/damonto/ims-go/ims/security"
	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
)

func (s *Registrar) State() State {
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
	contactPort := state.MessagePort
	if contactPort == 0 {
		contactPort = state.RegisterPort
	}
	state.ContactURI = s.registerContactURI(state.ContactHost, contactPort)
	return state
}

// RequestContactURI returns the registered contact address with the flow
// marker required for requests sent over an outbound registration.
func (state State) RequestContactURI() string {
	if !state.Flow.Outbound {
		return state.ContactURI
	}
	return state.ContactURI + ";ob"
}

func (s *Registrar) CurrentFlow() Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flow.clone()
}

func (s *Registrar) SecurityVerifyValue() string {
	return s.CurrentFlow().SecurityVerifyValue()
}

func (s *Registrar) RequestPolicy() sip.ClientRequestPolicy {
	state := s.State()
	return state.Flow.requestPolicy(s.preloadedRoutes(state.Flow), state.UserAgent, state.AccessNetworkInfo)
}

func (s *Registrar) DialogRequestPolicy(routes []string) sip.ClientRequestPolicy {
	state := s.State()
	return state.Flow.DialogRequestPolicy(routes, state.UserAgent, state.AccessNetworkInfo)
}

func (s *Registrar) StrictDialogRequestPolicy(routes []string) sip.ClientRequestPolicy {
	state := s.State()
	return state.Flow.StrictDialogRequestPolicy(routes, state.UserAgent, state.AccessNetworkInfo)
}

func (s *Registrar) Close() error {
	err := errors.Join(s.closeSecureResources(), s.closeAttachment())
	s.setRegistered(false)
	return err
}

func (s *Registrar) closeAttachment() error {
	s.mu.Lock()
	attachment := s.attachment
	s.attachment = nil
	s.mu.Unlock()
	if attachment == nil {
		return nil
	}
	return attachment.Close()
}

func (s *Registrar) HandleRequest(ctx context.Context, req session.Request) (bool, error) {
	if !strings.EqualFold(req.Message.Method(), "NOTIFY") {
		return false, nil
	}
	if !s.notifyMatchesSubscription(req.Message) {
		return true, s.sess.WriteStatus(ctx, req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist")
	}
	if !strings.EqualFold(strings.TrimSpace(req.Message.Header("Event")), regEventPackage) {
		return true, s.sess.WriteStatus(ctx, req, sipStatusBadEvent, "Bad Event")
	}
	if len(req.Message.Body) != 0 {
		contentType := strings.TrimSpace(req.Message.Header("Content-Type"))
		if contentType == "" {
			return true, s.sess.WriteStatus(ctx, req, sipStatusBadRequest, "Bad Request")
		}
		if !regInfoContentTypeMatches(contentType) {
			return true, s.writeUnsupportedRegInfoMediaType(ctx, req)
		}
	}
	pending, pendingAccepted := s.preparePendingSubscriptionNotify(req.Message)
	if status, reason := s.recordNotifyCSeq(req.Message); status != 0 {
		return true, s.sess.WriteStatus(ctx, req, status, reason)
	}
	subscriptionTerminated := s.applySubscriptionStateFromNotify(req.Message)
	notifyErr := s.applyRegInfoNotify(req.Message)
	if err := s.sess.WriteStatus(ctx, req, sipStatusOK, "OK"); err != nil {
		return true, err
	}
	s.completePendingSubscription(pending, pendingAccepted && !subscriptionTerminated)
	if subscriptionTerminated {
		s.resetSubscription()
		s.resetRegInfoState()
		if s.isRegistered() {
			s.requestSubscribeRefresh()
		}
	}
	if notifyErr != nil {
		if errors.Is(notifyErr, errNetworkDeregistered) {
			// TS 24.229 requires deleting registration state and security
			// associations after the NOTIFY server transaction completes.
			if strings.EqualFold(sip.TransportToken(req.Transport.LocalAddr()), "UDP") {
				s.resetRegistrationState()
				s.clearSecureResourcesAfter(s.sess.TransactionTimers().TJ)
			} else if err := s.clearRegistrationState(); err != nil {
				s.publishRegistrationEvent(notifyErr)
				return true, err
			}
		}
		s.publishRegistrationEvent(notifyErr)
	}
	return true, nil
}

func (s *Registrar) writeUnsupportedRegInfoMediaType(ctx context.Context, req session.Request) error {
	resp := sip.NewResponse(sipStatusUnsupportedMediaType, "Unsupported Media Type")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusUnsupportedMediaType)
	resp.Headers.Add("Accept", regInfoContentType)
	return s.sess.WriteResponse(ctx, req, resp)
}
