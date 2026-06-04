package ussd

import (
	"fmt"
	"strconv"

	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Session) buildACK() sip.Message {
	state := s.service.reg.State()
	senderIdentity := s.localDialogURI()
	msg := sip.NewRequest("ACK", s.targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(s.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("Max-Forwards", strconv.Itoa(sip.DefaultMaxForwards))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", senderIdentity, s.localTag))
	msg.Headers.Add("To", s.remoteTo)
	msg.Headers.Add("Call-ID", s.callID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d ACK", s.inviteSeq))
	s.service.reg.DialogRequestPolicy(s.routeSet).Apply(&msg)
	return msg
}

func (s *Session) buildDialogRequest(method string, body []byte) sip.Message {
	state := s.service.reg.State()
	senderIdentity := s.localDialogURI()
	msg := sip.NewRequest(method, s.targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(s.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", senderIdentity, s.localTag))
	msg.Headers.Add("To", s.remoteTo)
	msg.Headers.Add("Call-ID", s.callID)
	msg.Headers.Add("Session-ID", s.sessionID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d %s", s.nextCSeq(), method))
	msg.Headers.Add("Contact", contactValue(state, s.service.cfg.NetworkInitiatedSupported))
	s.service.reg.DialogRequestPolicy(s.routeSet).Apply(&msg)
	msg.Body = body
	return msg
}

func (s *Session) nextCSeq() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.localCSeq++
	return s.localCSeq
}
