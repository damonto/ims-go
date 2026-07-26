package voice

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/damonto/ims-go/ims/registration"
	"github.com/damonto/ims-go/ims/sip"
)

type dialogSnapshot struct {
	id                string
	sessionID         string
	localURI          string
	localTag          string
	remoteTo          string
	peerAllowsUPDATE  bool
	targetURI         string
	routeSet          []string
	inviteSeq         int64
	inviteRequest     sip.Message
	localSDP          []byte
	sessionTimer      bool
	preconditions     bool
	flow              registration.Flow
	userAgent         string
	accessNetworkInfo string
	transport         string
	contactHost       string
	messagePort       int
	contact           string
}

func (c *Call) dialogSnapshot() dialogSnapshot {
	// Keep SIP builders off Call's mutable fields. Callers take this snapshot
	// while holding c.mu, then build messages from the copied state.
	state := c.endpoint.reg.State()
	invite := c.inviteRequest
	invite.Headers = invite.Headers.Clone()
	invite.Body = append([]byte(nil), invite.Body...)
	preconditions := c.endpoint.cfg.Preconditions
	if c.direction == CallDirectionIncoming {
		preconditions = c.preconditions
	}
	return dialogSnapshot{
		id:                c.id,
		sessionID:         c.sessionID,
		localURI:          c.localURI,
		localTag:          c.localTag,
		remoteTo:          c.remoteTo,
		peerAllowsUPDATE:  sip.TokenListContains(c.remoteAllow, "UPDATE"),
		targetURI:         c.targetURI,
		routeSet:          append([]string(nil), c.routeSet...),
		inviteSeq:         c.inviteSeq,
		inviteRequest:     invite,
		localSDP:          append([]byte(nil), c.localSDP...),
		sessionTimer:      c.endpoint.cfg.SessionTimer,
		preconditions:     preconditions,
		flow:              state.Flow,
		userAgent:         state.UserAgent,
		accessNetworkInfo: state.AccessNetworkInfo,
		transport:         sip.TransportToken(c.endpoint.sess.LocalAddr()),
		contactHost:       state.ContactHost,
		messagePort:       state.MessagePort,
		contact:           requestContactValue(state),
	}
}

func (c *Call) nextCSeq() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.localCSeq++
	return c.localCSeq
}

func (s dialogSnapshot) requestPolicy(routes []string) sip.ClientRequestPolicy {
	if routes == nil {
		routes = s.routeSet
	}
	return s.flow.DialogRequestPolicy(routes, s.userAgent, s.accessNetworkInfo)
}

func (s dialogSnapshot) applyRequestPolicy(msg *sip.Message, routes []string) {
	s.requestPolicy(routes).Apply(msg)
	if s.sessionTimer && !strings.EqualFold(msg.Method(), "ACK") {
		addTokenHeader(msg, "Supported", sessionTimerOption)
	}
}

func (s dialogSnapshot) applyACKRequestPolicy(msg *sip.Message, routes []string) {
	s.applyRequestPolicy(msg, routes)
	msg.Headers.Del("Require")
	msg.Headers.Del("Proxy-Require")
}

func (s dialogSnapshot) addDialogHeaders(msg *sip.Message, method string, cseq int64) {
	msg.Headers.Add("Via", sip.BuildVia(s.transport, s.contactHost, s.messagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", s.localURI, s.localTag))
	msg.Headers.Add("To", s.remoteTo)
	msg.Headers.Add("Call-ID", s.id)
	if s.sessionID != "" {
		msg.Headers.Add("Session-ID", s.sessionID)
	}
	msg.Headers.Add("CSeq", fmt.Sprintf("%d %s", cseq, method))
}

func (s dialogSnapshot) buildACK() sip.Message {
	msg := sip.NewRequest("ACK", s.targetURI)
	s.addDialogHeaders(&msg, "ACK", s.inviteSeq)
	msg.Headers.Del("Session-ID")
	s.applyACKRequestPolicy(&msg, nil)
	return msg
}

func (s dialogSnapshot) buildACKForResponse(resp sip.Message) sip.Message {
	targetURI := nonEmpty(sip.AddressURI(resp.Header("Contact")), sip.AddressURI(resp.Header("To")), s.targetURI)
	msg := sip.NewRequest("ACK", targetURI)
	s.addDialogHeaders(&msg, "ACK", s.inviteSeq)
	msg.Headers.Set("To", nonEmpty(resp.Header("To"), s.remoteTo))
	msg.Headers.Del("Session-ID")
	s.applyACKRequestPolicy(&msg, reverseValues(resp.HeaderList("Record-Route")))
	return msg
}

func (s dialogSnapshot) buildACKForSessionRefreshINVITE(resp sip.Message) sip.Message {
	targetURI := nonEmpty(sip.AddressURI(resp.Header("Contact")), s.targetURI)
	msg := sip.NewRequest("ACK", targetURI)
	s.addDialogHeaders(&msg, "ACK", sip.CSeqNumber(resp.Header("CSeq")))
	msg.Headers.Set("To", nonEmpty(resp.Header("To"), s.remoteTo))
	msg.Headers.Del("Session-ID")
	s.applyACKRequestPolicy(&msg, nil)
	return msg
}

func (s dialogSnapshot) buildCANCEL(reason string) sip.Message {
	invite := s.inviteRequest
	msg := sip.NewRequest("CANCEL", sip.RequestURI(invite))
	if via := invite.Header("Via"); via != "" {
		msg.Headers.Add("Via", via)
	}
	msg.Headers.Add("From", invite.Header("From"))
	msg.Headers.Add("To", invite.Header("To"))
	msg.Headers.Add("Call-ID", invite.Header("Call-ID"))
	msg.Headers.Add("CSeq", fmt.Sprintf("%d CANCEL", s.inviteSeq))
	if maxForwards := invite.Header("Max-Forwards"); maxForwards != "" {
		msg.Headers.Add("Max-Forwards", maxForwards)
	}
	for _, route := range invite.HeadersByName("Route") {
		msg.Headers.Add("Route", route)
	}
	for _, supported := range invite.HeadersByName("Supported") {
		msg.Headers.Add("Supported", supported)
	}
	if userAgent := strings.TrimSpace(s.userAgent); userAgent != "" {
		msg.Headers.Add("User-Agent", userAgent)
	}
	if securityVerify := invite.Header("Security-Verify"); securityVerify != "" {
		msg.Headers.Add("Security-Verify", securityVerify)
	}
	if reason != "" {
		msg.Headers.Add("Reason", reason)
	}
	return msg
}

func (c *Call) buildBYE(reason string) sip.Message {
	c.mu.Lock()
	snap := c.dialogSnapshot()
	c.mu.Unlock()
	return snap.buildBYE(reason, c.nextCSeq())
}

func (s dialogSnapshot) buildBYE(reason string, cseq int64) sip.Message {
	msg := s.buildDialogRequest("BYE", cseq)
	if reason != "" {
		msg.Headers.Add("Reason", reason)
	}
	return msg
}

func (s dialogSnapshot) buildSessionRefreshUPDATE(cseq int64, timer sessionTimerState) sip.Message {
	msg := s.buildDialogRequest("UPDATE", cseq)
	addTokenHeader(&msg, "Supported", sessionTimerOption)
	if timer.active {
		seconds := durationSeconds(timer.interval)

		seconds = max(seconds, timer.minSE)

		msg.Headers.Set("Session-Expires", sessionExpiresHeader{
			seconds:   seconds,
			refresher: sessionRefresherUAC,
		}.String())
	}
	if timer.minSE > durationSeconds(defaultMinSessionExpires) {
		msg.Headers.Set("Min-SE", strconv.Itoa(timer.minSE))
	}
	return msg
}

func (s dialogSnapshot) buildPreconditionUPDATEForResponse(resp sip.Message, cseq int64, remoteTarget string, routes []string, body []byte) sip.Message {
	targetURI := nonEmpty(remoteTarget, sip.AddressURI(resp.Header("Contact")), sip.AddressURI(resp.Header("To")), s.targetURI)
	msg := sip.NewRequest("UPDATE", targetURI)
	s.addDialogHeaders(&msg, "UPDATE", cseq)
	msg.Headers.Set("To", nonEmpty(resp.Header("To"), s.remoteTo))
	msg.Headers.Add("Contact", s.contact)
	msg.Headers.Set("Content-Type", "application/sdp")
	msg.Headers.Add("Require", preconditionOption)
	msg.Body = append([]byte(nil), body...)
	s.applyRequestPolicy(&msg, routes)
	return msg
}

func (s dialogSnapshot) buildPreconditionUPDATE(cseq int64, body []byte) sip.Message {
	msg := s.buildDialogRequest("UPDATE", cseq)
	msg.Headers.Set("Content-Type", "application/sdp")
	msg.Headers.Add("Require", preconditionOption)
	msg.Body = append([]byte(nil), body...)
	return msg
}

func (s dialogSnapshot) buildSessionRefreshRequest(cseq int64, timer sessionTimerState) sip.Message {
	if s.peerAllowsUPDATE {
		return s.buildSessionRefreshUPDATE(cseq, timer)
	}
	msg := s.buildDialogRequest("INVITE", cseq)
	addTokenHeader(&msg, "Supported", sessionTimerOption)
	if len(s.localSDP) != 0 {
		msg.Headers.Set("Content-Type", "application/sdp")
		msg.Body = append([]byte(nil), s.localSDP...)
		s.addPreconditionSupport(&msg, s.localSDP)
	}
	if timer.active {
		seconds := durationSeconds(timer.interval)
		seconds = max(seconds, timer.minSE)
		msg.Headers.Set("Session-Expires", sessionExpiresHeader{
			seconds:   seconds,
			refresher: sessionRefresherUAC,
		}.String())
	}
	if timer.minSE > durationSeconds(defaultMinSessionExpires) {
		msg.Headers.Set("Min-SE", strconv.Itoa(timer.minSE))
	}
	return msg
}

func (s dialogSnapshot) buildMediaReINVITE(cseq int64, timer sessionTimerState, body []byte) sip.Message {
	msg := s.buildDialogRequest("INVITE", cseq)
	msg.Headers.Set("Content-Type", "application/sdp")
	msg.Body = append([]byte(nil), body...)
	addTokenHeader(&msg, "Supported", sessionTimerOption)
	s.addPreconditionSupport(&msg, body)
	if timer.active {
		seconds := durationSeconds(timer.interval)

		seconds = max(seconds, timer.minSE)

		msg.Headers.Set("Session-Expires", sessionExpiresHeader{
			seconds:   seconds,
			refresher: sessionRefresherUAC,
		}.String())
	}
	if timer.minSE > durationSeconds(defaultMinSessionExpires) {
		msg.Headers.Set("Min-SE", strconv.Itoa(timer.minSE))
	}
	return msg
}

func (s dialogSnapshot) addPreconditionSupport(msg *sip.Message, body []byte) {
	if s.preconditions && sdpUsesPreconditions(body) {
		addTokenHeader(msg, "Supported", preconditionOption)
	}
}

func (s dialogSnapshot) buildBYEForResponse(resp sip.Message, cseq int64, reason string) sip.Message {
	targetURI := nonEmpty(sip.AddressURI(resp.Header("Contact")), sip.AddressURI(resp.Header("To")), s.targetURI)
	msg := sip.NewRequest("BYE", targetURI)
	s.addDialogHeaders(&msg, "BYE", cseq)
	msg.Headers.Set("To", nonEmpty(resp.Header("To"), s.remoteTo))
	msg.Headers.Add("Contact", s.contact)
	if reason != "" {
		msg.Headers.Add("Reason", reason)
	}
	s.applyRequestPolicy(&msg, reverseValues(resp.HeaderList("Record-Route")))
	return msg
}

func (s dialogSnapshot) buildDialogRequest(method string, cseq int64) sip.Message {
	msg := sip.NewRequest(method, s.targetURI)
	s.addDialogHeaders(&msg, method, cseq)
	msg.Headers.Add("Contact", s.contact)
	s.applyRequestPolicy(&msg, nil)
	return msg
}
