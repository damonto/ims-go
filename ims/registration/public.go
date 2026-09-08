package registration

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/damonto/ims-go/ims/security"
	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
)

// State returns a detached snapshot of the registrar and its current SIP flow.
func (s *Registrar) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state
	state.AssociatedURIs = slices.Clone(state.AssociatedURIs)
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
func (s State) RequestContactURI() string {
	if !s.Flow.Outbound {
		return s.ContactURI
	}
	return s.ContactURI + ";ob"
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
	s.stopRegistrationMaintenance()
	s.maintenanceWG.Wait()
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
	networkDeregistered := errors.Is(notifyErr, errNetworkDeregistered)
	if networkDeregistered {
		s.stopRegistrationMaintenance()
	}
	replacement := networkDeregistered && s.registrationReplacementActive()
	if replacement {
		s.finishRegistrationReplacement()
	}
	if err := s.sess.WriteStatus(ctx, req, sipStatusOK, "OK"); err != nil {
		if replacement {
			s.publishRegistrationEvent(ErrRegistrationReplaced)
			return true, fmt.Errorf("acknowledging replaced IMS registration: %w: %w", ErrRegistrationReplaced, err)
		}
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
		eventErr := notifyErr
		if replacement {
			eventErr = ErrRegistrationReplaced
		}
		if errors.Is(notifyErr, errNetworkDeregistered) {
			// TS 24.229 requires deleting registration state and security
			// associations after the NOTIFY server transaction completes.
			s.registrationCommitMu.Lock()
			if strings.EqualFold(sip.TransportToken(req.Transport.LocalAddr()), "UDP") {
				s.resetRegistrationState()
				s.clearSecureResourcesAfter(s.sess.TransactionTimers().TJ, func() {
					s.publishRegistrationEvent(eventErr)
				})
				s.registrationCommitMu.Unlock()
				return true, nil
			}
			err := s.clearRegistrationState()
			s.registrationCommitMu.Unlock()
			if err != nil {
				s.publishRegistrationEvent(eventErr)
				if replacement {
					return true, fmt.Errorf("deleting replaced IMS registration state: %w: %w", eventErr, err)
				}
				return true, err
			}
		}
		s.publishRegistrationEvent(eventErr)
	}
	return true, nil
}

func (s *Registrar) writeUnsupportedRegInfoMediaType(ctx context.Context, req session.Request) error {
	resp := sip.NewResponse(sipStatusUnsupportedMediaType, "Unsupported Media Type")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusUnsupportedMediaType)
	resp.Headers.Add("Accept", regInfoContentType)
	return s.sess.WriteResponse(ctx, req, resp)
}
