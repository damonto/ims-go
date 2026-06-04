package voice

import (
	"context"
	"math/rand/v2"

	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
)

func (c *Call) handleReINVITEGlare(ctx context.Context, req session.Request) (bool, error) {
	cseq := sip.CSeqNumber(req.Message.Header("CSeq"))
	c.mu.Lock()
	switch {
	case c.localINVITEPending:
		c.mu.Unlock()
		return true, c.service.writeStatus(ctx, req, sipStatusRequestPending, "Request Pending")
	case c.remoteINVITEPending:
		c.mu.Unlock()
		return true, c.service.writeRetryAfter(ctx, req, sipStatusServerInternalError, "Server Internal Error", rand.IntN(11))
	default:
		c.remoteINVITEPending = true
		c.remoteINVITECSeq = cseq
		c.mu.Unlock()
		return false, nil
	}
}

func (c *Call) clearRemoteINVITEPending() {
	c.mu.Lock()
	c.remoteINVITEPending = false
	c.remoteINVITECSeq = 0
	c.mu.Unlock()
}

func (c *Call) markLocalINVITEPending(method string) func() {
	if method != "INVITE" {
		return func() {}
	}
	c.mu.Lock()
	c.localINVITEPending = true
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		c.localINVITEPending = false
		c.mu.Unlock()
	}
}
