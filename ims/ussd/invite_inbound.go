package ussd

import (
	"context"
	"errors"
	"fmt"

	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Service) handleIncomingInvite(ctx context.Context, req session.Request) error {
	if handled, err := s.handleExistingInvite(ctx, req); handled || err != nil {
		return err
	}
	if !s.cfg.NetworkInitiatedSupported {
		return s.sess.WriteStatus(ctx, req, sipStatusNotFound, "Not Found")
	}
	if s.hasActiveSession() {
		return s.sess.WriteStatus(ctx, req, sipStatusBusyHere, "Busy Here")
	}
	payload, err := validateIncomingInvite(req.Message)
	if err != nil {
		if errors.Is(err, errUnsupportedMediaType) {
			return s.writeUnsupportedMediaType(ctx, req)
		}
		return s.sess.WriteStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
	}
	session := s.newIncomingSession(req.Message, payload)
	if err := s.sess.WriteStatus(ctx, req, sipStatusTrying, "Trying"); err != nil {
		return fmt.Errorf("handling USSD INVITE: sending 100 Trying: %w", err)
	}
	session.inviteOK = s.buildIncomingInviteOK(req.Message, session.localURI, session.localTag)
	if err := s.storeSession(session); err != nil {
		session.closeEvents()
		if errors.Is(err, errSessionActive) {
			return s.sess.WriteStatus(ctx, req, sipStatusBusyHere, "Busy Here")
		}
		return err
	}
	session.emit(payload)
	session.setDeliveringInvite(true)
	if s.cfg.OnIncoming != nil {
		s.cfg.OnIncoming(session, payload)
	}
	session.setDeliveringInvite(false)
	if err := s.sess.WriteResponse(ctx, req, session.inviteOK); err != nil {
		session.finish(false)
		return fmt.Errorf("handling USSD INVITE: sending 200 OK: %w", err)
	}
	session.startInviteOKRetransmit(req, session.inviteOK)
	s.logger.Info("accepted network-initiated USSD", "call_id", session.callID, "target_uri", session.targetURI)
	return nil
}

func (s *Service) handleExistingInvite(ctx context.Context, req session.Request) (bool, error) {
	session := s.lookupIncomingInviteSession(req.Message)
	if session == nil {
		return false, nil
	}
	if session.inviteOK.StartLine != "" {
		return true, s.sess.WriteResponse(ctx, req, session.inviteOK)
	}
	return true, s.sess.WriteStatus(ctx, req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist")
}

func (s *Service) newIncomingSession(msg sip.Message, payload Message) *Session {
	state := s.reg.State()
	localTag := sip.RandomAlphaNum(10)
	remoteTo := msg.Header("From")
	targetURI := nonEmpty(sip.AddressURI(msg.Header("Contact")), sip.AddressURI(remoteTo))
	if targetURI == "" {
		targetURI = state.PublicIdentity
	}
	return &Session{
		service:          s,
		incomingInviteID: incomingInviteKey(msg),
		callID:           msg.Header("Call-ID"),
		sessionID:        nonEmpty(msg.Header("Session-ID"), sip.RandomHex(32)),
		localURI:         nonEmpty(sip.AddressURI(msg.Header("To")), preferredIdentity(state)),
		localTag:         localTag,
		remoteTag:        sip.HeaderTag(remoteTo),
		remoteTo:         remoteTo,
		targetURI:        targetURI,
		routeSet:         append([]string(nil), msg.HeadersByName("Record-Route")...),
		inviteSeq:        sip.CSeqNumber(msg.Header("CSeq")),
		localCSeq:        0,
		remoteCSeq:       sip.CSeqNumber(msg.Header("CSeq")),
		language:         defaultValue(payload.Language, defaultValue(s.cfg.Language, defaultLang)),
		networkInitiated: true,
		responseKind:     kindFromPayload(payload),
		ackCh:            make(chan struct{}),
		state:            sessionStateWaitingACK,
		events:           make(chan Message, 16),
		remoteCSeqs:      map[string]struct{}{"INVITE|" + msg.Header("CSeq"): {}},
	}
}

func (s *Service) buildIncomingInviteOK(msg sip.Message, localURI, localTag string) sip.Message {
	ok := sip.NewResponse(sipStatusOK, "OK")
	ok.Headers = sip.ResponseHeaders(msg, sipStatusOK)
	ok.Headers = sip.UpsertHeader(ok.Headers, "To", sip.WithTag(msg.Header("To"), localURI, localTag))
	ok.Headers.Add("Contact", contactValue(s.reg.State(), s.cfg.NetworkInitiatedSupported))
	ok.Headers.Add("Recv-Info", infoPackage)
	ok.Headers.Add("Accept", acceptHeader)
	ok.Headers.Add("Content-Type", sdpContentType)
	ok.Body = []byte(s.sdp())
	return ok
}
