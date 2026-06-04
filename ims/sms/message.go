package sms

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Service) buildMessage(target string, body []byte, inReplyTo string) (sip.Message, error) {
	state := s.reg.State()
	target = strings.TrimSpace(target)
	if target == "" {
		sc, err := s.resolveServiceCenter()
		if err != nil {
			return sip.Message{}, err
		}
		target = sc.target
	}
	callID, _, tag, branch := sip.NewTransaction()
	senderIdentity := preferredIdentity(state)
	msg := sip.NewRequest("MESSAGE", target)
	msg.Headers.Add("Call-ID", callID)
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", senderIdentity, tag))
	msg.Headers.Add("To", fmt.Sprintf("<%s>", target))
	msg.Headers.Add("Request-Disposition", "no-fork")
	msg.Headers.Add("Accept-Contact", acceptContact)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d MESSAGE", atomic.AddInt64(&s.cseq, 1)))
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(s.sess.LocalAddr()), state.ContactHost, state.MessagePort, branch))
	msg.Headers.Add("P-Preferred-Identity", fmt.Sprintf("<%s>", senderIdentity))
	s.reg.RequestPolicy().Apply(&msg)
	msg.Headers.Add("Content-Type", messageContentType)
	msg.Headers.Add("Content-Transfer-Encoding", binaryTransferValue)
	if inReplyTo != "" {
		msg.Headers.Add("In-Reply-To", inReplyTo)
	}
	msg.Body = body
	return msg, nil
}

func (s *Service) buildDeliveryReportMessage(target string, body []byte, inReplyTo string, info xmlInfo) (sip.Message, error) {
	if strings.TrimSpace(info.From) == "" {
		return s.buildMessage(target, body, inReplyTo)
	}
	payload, contentType, err := buildMultipartPayload(xmlInfo{To: strings.TrimSpace(info.From)}, body)
	if err != nil {
		return sip.Message{}, fmt.Errorf("building sms delivery report multipart body: %w", err)
	}

	msg, err := s.buildMessage(target, payload, inReplyTo)
	if err != nil {
		return sip.Message{}, err
	}
	msg.Headers.Set("Content-Type", contentType)
	msg.Headers.Del("Content-Transfer-Encoding")
	return msg, nil
}

func preferredIdentity(state registration.State) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(state.TelPublicID)), "tel:") {
		return state.TelPublicID
	}
	if identity := strings.TrimSpace(state.DefaultPublicID); identity != "" {
		return identity
	}
	return state.PublicIdentity
}

func (s *Service) reportTarget(msg sip.Message) string {
	return sipMessageTarget(sip.AddressURI(msg.Header("P-Asserted-Identity")))
}

func sipMessageTarget(uri string) string {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return ""
	}
	lower := strings.ToLower(uri)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") {
		return uri
	}
	return ""
}
