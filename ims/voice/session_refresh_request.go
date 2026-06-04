package voice

import (
	"errors"

	"github.com/damonto/vowifi-go/ims/sip"
)

func (c *Call) sessionRefreshAnswer(msg sip.Message) ([]byte, NegotiatedMedia, CallHoldState, bool, error) {
	if len(msg.Body) == 0 {
		return nil, NegotiatedMedia{}, "", false, nil
	}
	body, ok := sdpBody(msg)
	if !ok {
		return nil, NegotiatedMedia{}, "", false, errors.New("handling re-INVITE: missing SDP offer")
	}
	offer, err := parseSDP(body)
	if err != nil {
		return nil, NegotiatedMedia{}, "", false, err
	}
	c.mu.Lock()
	localPort := c.localPort
	currentHold := c.hold
	c.mu.Unlock()
	answer, media, err := buildSDPAnswerWithLocalHold(c.service.cfg, c.service.localIP(), localPort, offer, MediaOffer{}, holdHasLocal(currentHold))
	if err != nil {
		return nil, NegotiatedMedia{}, "", false, err
	}
	return answer, media, setRemoteHold(currentHold, remoteHoldFromDirection(offer.Direction)), true, nil
}

func (c *Call) buildSessionRefreshOK(req sip.Message) sip.Message {
	resp := sip.NewResponse(sipStatusOK, "OK")
	resp.Headers = sip.ResponseHeaders(req, sipStatusOK)
	c.service.addAccessNetworkInfo(&resp)
	resp.Headers.Add("Contact", contactValue(c.service.reg.State()))
	resp.Headers.Add("Allow", sip.DefaultClientAllow)
	addInviteOKSessionTimer(&resp, req, c.service.cfg)
	return resp
}

func (c *Call) rememberSessionTimerMinSE(msg sip.Message) {
	minSE, ok := parseMinSessionSeconds(msg.Header("Min-SE"))
	if !ok {
		return
	}
	c.mu.Lock()
	if c.sessionTimer.minSE < minSE {
		c.sessionTimer.minSE = minSE
	}
	c.mu.Unlock()
}
