package voice

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/damonto/ims-go/ims/sip"
)

func (s *Endpoint) storeCall(call *Call) error {
	attachment, err := s.sess.RegisterDialog(sip.DialogID{
		CallID:    call.id,
		LocalTag:  call.localTag,
		RemoteTag: call.remoteTag,
	}, call.id)
	if err != nil {
		return fmt.Errorf("storing call: %w", err)
	}
	call.dialogAttachment = attachment
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		_ = attachment.Close()
		return errors.New("storing call: endpoint is closed")
	}
	s.calls[call.id] = call
	return nil
}

func (s *Endpoint) removeCall(callID string) {
	s.mu.Lock()
	call := s.calls[callID]
	if call != nil {
		delete(s.calls, callID)
		for key, incoming := range s.incomings {
			if incoming == call {
				delete(s.incomings, key)
			}
		}
	}
	s.mu.Unlock()
	if call != nil {
		call.mu.Lock()
		attachment := call.dialogAttachment
		call.dialogAttachment = nil
		call.mu.Unlock()
		if attachment != nil {
			_ = attachment.Close()
		}
	}
}

func (s *Endpoint) lookupCallForMessage(msg sip.Message) *Call {
	key, ok := s.sess.LookupDialogKey(msg)
	if !ok {
		return nil
	}
	return s.lookupCall(key)
}

func (s *Endpoint) lookupCall(callID string) *Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[callID]
}

func (s *Endpoint) storeIncoming(msg sip.Message, call *Call) {
	key := incomingInviteKey(msg, "INVITE")
	if key == "" {
		return
	}
	s.mu.Lock()
	s.incomings[key] = call
	s.mu.Unlock()
}

func (s *Endpoint) lookupIncoming(msg sip.Message) *Call {
	method := sip.CSeqMethod(msg.Header("CSeq"))
	if strings.EqualFold(method, "CANCEL") {
		method = "INVITE"
	}
	key := incomingInviteKey(msg, method)
	if key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.incomings[key]
}

func (s *Endpoint) targetURI(to string) string {
	to = strings.TrimSpace(to)
	if to == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(to), "sip:") || strings.HasPrefix(strings.ToLower(to), "tel:") {
		return to
	}
	realm := strings.TrimPrefix(s.reg.State().RegisterURI, "sip:")
	phoneContext := s.cfg.PhoneContextDomain
	if phoneContext == "" {
		phoneContext = realm
	}
	if s.cfg.RequestURIFormat == RequestURIFormatTEL {
		if strings.HasPrefix(to, "+") {
			return "tel:" + to
		}
		return fmt.Sprintf("tel:%s;phone-context=%s", to, phoneContext)
	}
	if strings.HasPrefix(to, "+") {
		return fmt.Sprintf("sip:%s@%s;user=phone", to, realm)
	}
	return fmt.Sprintf("sip:%s;phone-context=%s@%s;user=phone", to, phoneContext, realm)
}

func (s *Endpoint) reserveRTPPort() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	port := s.nextPort
	if port%2 != 0 {
		port++
	}
	s.nextPort = port + 2
	if s.nextPort > s.cfg.LocalRTPPortMax {
		s.nextPort = s.cfg.LocalRTPPortMin
	}
	return port
}

func (s *Endpoint) localIP() net.IP {
	ip := net.ParseIP(s.reg.State().ContactHost)
	if ip == nil || ip.IsUnspecified() {
		return net.IPv4(0, 0, 0, 0)
	}
	return ip
}

func (s *Endpoint) emit(event CallEvent) {
	if s.cfg.OnCallEvent != nil {
		s.cfg.OnCallEvent(event)
	}
}

func (s *Endpoint) emitMedia(call *Call, media NegotiatedMedia) {
	if s.cfg.OnMedia == nil || !media.Negotiated {
		return
	}
	s.cfg.OnMedia(MediaEvent{
		Call:   call,
		CallID: call.ID(),
		Media:  cloneNegotiatedMedia(media),
		At:     time.Now(),
	})
}

func (s *Endpoint) emitError(err error) {
	if err == nil {
		return
	}
	if s.cfg.OnError != nil {
		s.cfg.OnError(err)
		return
	}
	s.logger.Debug("voice endpoint error", "err", err)
}
