package voice

import (
	"context"
	"strconv"
	"strings"

	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Service) writeStatus(ctx context.Context, req session.Request, code int, reason string) error {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req.Message, code)
	s.addAccessNetworkInfo(&resp)
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Service) writePRACKOK(ctx context.Context, req session.Request, sdp []byte) error {
	resp := sip.NewResponse(sipStatusOK, "OK")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusOK)
	s.addAccessNetworkInfo(&resp)
	if len(sdp) != 0 {
		resp.Headers.Add("Content-Type", "application/sdp")
		if s.usesPreconditions(req.Message) && sdpUsesPreconditions(sdp) {
			addTokenHeader(&resp, "Require", preconditionOption)
		}
		resp.Body = sdp
	}
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Service) writeRetryAfter(ctx context.Context, req session.Request, code int, reason string, seconds int) error {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req.Message, code)
	resp.Headers.Set("Retry-After", strconv.Itoa(seconds))
	s.addAccessNetworkInfo(&resp)
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Service) writeUnsupportedRequired(ctx context.Context, req session.Request, option string) error {
	resp := sip.NewResponse(sipStatusBadExtension, "Bad Extension")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusBadExtension)
	resp.Headers.Set("Unsupported", option)
	s.addAccessNetworkInfo(&resp)
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Service) writeSessionIntervalTooSmall(ctx context.Context, req session.Request, minSE int) error {
	resp := sip.NewResponse(sipStatusSessionIntervalTooSmall, "Session Interval Too Small")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusSessionIntervalTooSmall)
	resp.Headers.Set("Min-SE", strconv.Itoa(minSE))
	s.addAccessNetworkInfo(&resp)
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Service) writeRinging(ctx context.Context, req session.Request, call *Call) error {
	resp := sip.NewResponse(sipStatusRinging, "Ringing")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusRinging)
	s.addAccessNetworkInfo(&resp)
	resp.Headers.Add("Contact", contactValue(s.reg.State()))
	resp.Headers.Add("Allow", sip.DefaultClientAllow)
	resp.Headers.Add("Accept", callAcceptHeader(false, false))
	var rseq int64
	if call != nil && s.canSendReliableProvisional(req.Message) {
		resp.Headers.Add("Require", reliableProvisionalOption)
		rseq = call.beginReliableProvisional(sipStatusRinging, sip.CSeqNumber(req.Message.Header("CSeq")), "INVITE")
		resp.Headers.Add("RSeq", strconv.FormatInt(rseq, 10))
	}
	if err := s.sess.WriteResponse(ctx, req, resp); err != nil {
		return err
	}
	if rseq != 0 {
		call.startReliableProvisionalRetransmit(req, resp, rseq)
	}
	return nil
}

func (s *Service) writeProgress(ctx context.Context, req session.Request, call *Call, body []byte, reliable bool) error {
	resp := sip.NewResponse(sipStatusSessionProgress, "Session Progress")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusSessionProgress)
	s.addAccessNetworkInfo(&resp)
	resp.Headers = sip.UpsertHeader(resp.Headers, "To", sip.WithTag(req.Message.Header("To"), call.localURI, call.localTag))
	resp.Headers.Add("Contact", contactValue(s.reg.State()))
	resp.Headers.Add("Allow", sip.DefaultClientAllow)
	resp.Headers.Add("Accept", callAcceptHeader(false, false))
	var rseq int64
	if reliable {
		resp.Headers.Add("Require", reliableProvisionalOption)
		rseq = call.beginReliableProvisional(sipStatusSessionProgress, sip.CSeqNumber(req.Message.Header("CSeq")), "INVITE")
		resp.Headers.Add("RSeq", strconv.FormatInt(rseq, 10))
	}
	if len(body) != 0 {
		if err := setInviteResponseBody(&resp, s.cfg, call.localURI, false, body); err != nil {
			return err
		}
		if s.usesPreconditions(req.Message) && sdpUsesPreconditions(body) {
			addTokenHeader(&resp, "Require", preconditionOption)
		}
		call.mu.Lock()
		call.localSDP = append([]byte(nil), body...)
		call.mu.Unlock()
	}
	if err := s.sess.WriteResponse(ctx, req, resp); err != nil {
		return err
	}
	if rseq != 0 {
		call.startReliableProvisionalRetransmit(req, resp, rseq)
	}
	return nil
}

func (s *Service) addAccessNetworkInfo(resp *sip.Message) {
	state := s.reg.State()
	if value := strings.TrimSpace(state.UserAgent); value != "" && strings.TrimSpace(resp.Header("Server")) == "" {
		resp.Headers.Add("Server", value)
	}
	if value := strings.TrimSpace(state.AccessNetworkInfo); value != "" && strings.TrimSpace(resp.Header("P-Access-Network-Info")) == "" {
		resp.Headers.Add("P-Access-Network-Info", value)
	}
}
