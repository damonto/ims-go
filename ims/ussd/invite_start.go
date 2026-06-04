package ussd

import (
	"context"
	"errors"
	"fmt"
	"net/textproto"
	"strings"
	"sync/atomic"
	"time"

	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Service) newStart(code string) (startRequest, sip.Message, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return startRequest{}, sip.Message{}, errors.New("starting USSD: code is empty")
	}
	start := startRequest{
		code:      code,
		callID:    sip.RandomAlphaNum(24),
		sessionID: sip.RandomHex(32),
		localTag:  sip.RandomAlphaNum(10),
		branch:    sip.RandomAlphaNum(15),
		inviteSeq: atomic.AddInt64(&s.cseq, 1),
		language:  defaultValue(s.cfg.Language, defaultLang),
	}
	start.target = s.targetURI(start.code)
	boundary, body, err := s.buildInviteBody(start.code, start.language)
	if err != nil {
		return startRequest{}, sip.Message{}, err
	}
	return start, s.buildInvite(start, boundary, body), nil
}

func (s *Service) buildInviteBody(code, language string) (string, []byte, error) {
	payload, err := (xmlBody{Message: Message{Text: code, Language: language}}).MarshalText()
	if err != nil {
		return "", nil, fmt.Errorf("starting USSD: encoding XML payload: %w", err)
	}
	boundary := "ussd-" + sip.RandomAlphaNum(12)
	body, err := (multipartBody{Boundary: boundary, Parts: []multipartBodyPart{
		{
			Header: textproto.MIMEHeader{"Content-Type": {sdpContentType}},
			Body:   []byte(s.sdp()),
		},
		{
			Header: textproto.MIMEHeader{
				"Content-Type":        {xmlContentType},
				"Content-Disposition": {renderOptionalDisposition},
			},
			Body: payload,
		},
	}}).MarshalBinary()
	if err != nil {
		return "", nil, fmt.Errorf("starting USSD: building multipart body: %w", err)
	}
	return boundary, body, nil
}

func (s *Service) buildInvite(start startRequest, boundary string, body []byte) sip.Message {
	state := s.reg.State()
	senderIdentity := preferredIdentity(state)
	msg := sip.NewRequest("INVITE", start.target)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(s.sess.LocalAddr()), state.ContactHost, state.MessagePort, start.branch))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", senderIdentity, start.localTag))
	msg.Headers.Add("To", fmt.Sprintf("<%s>", start.target))
	msg.Headers.Add("Call-ID", start.callID)
	msg.Headers.Add("Session-ID", start.sessionID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d INVITE", start.inviteSeq))
	msg.Headers.Add("Accept-Contact", "*;"+icsiRefFeatureTag)
	msg.Headers.Add("P-Preferred-Identity", fmt.Sprintf("<%s>", senderIdentity))
	msg.Headers.Add("Contact", contactValue(state, s.cfg.NetworkInitiatedSupported))
	msg.Headers.Add("Accept", acceptHeader)
	msg.Headers.Add("Recv-Info", infoPackage)
	s.reg.RequestPolicy().Apply(&msg)
	msg.Headers.Add("Content-Type", fmt.Sprintf("%s; boundary=%s", mixedMultipartType, boundary))
	msg.Body = body
	return msg
}

func (s *Service) startSession(ctx context.Context, start startRequest, invite, resp sip.Message) (*Session, error) {
	if err := validateInviteOK(resp); err != nil {
		return nil, fmt.Errorf("starting USSD: validating 200 OK: %w", err)
	}
	session := &Session{
		service:      s,
		callID:       start.callID,
		sessionID:    start.sessionID,
		localURI:     nonEmpty(sip.AddressURI(invite.Header("From")), preferredIdentity(s.reg.State())),
		localTag:     start.localTag,
		remoteTag:    sip.HeaderTag(resp.Header("To")),
		remoteTo:     nonEmpty(resp.Header("To"), invite.Header("To")),
		targetURI:    nonEmpty(sip.AddressURI(resp.Header("Contact")), start.target),
		routeSet:     reverseValues(resp.HeadersByName("Record-Route")),
		inviteSeq:    start.inviteSeq,
		localCSeq:    start.inviteSeq,
		language:     start.language,
		events:       make(chan Message, 16),
		remoteCSeqs:  make(map[string]struct{}),
		responseKind: dialogKindRequest,
	}
	if err := s.storeSession(session); err != nil {
		if endErr := session.endDirect(ctx, ""); endErr != nil {
			err = errors.Join(err, endErr)
		}
		session.finish(false)
		return nil, err
	}
	if err := s.sess.Send(ctx, session.buildACK()); err != nil {
		s.removeSession(session.sessionKey())
		session.closeEvents()
		return nil, fmt.Errorf("starting USSD: %w", err)
	}
	s.logger.Info("started USSD session", "code", start.code, "call_id", start.callID, "target_uri", session.targetURI)
	return session, nil
}

func (s *Service) cancelInvite(invite sip.Message) {
	ctx, cancel := s.timeoutContext(2 * time.Second)
	defer cancel()
	_ = s.sess.Send(ctx, buildCancel(invite))
}
