package voice

import (
	"strings"

	"github.com/damonto/vowifi-go/ims/sip"
)

func (c *Call) updateRemoteAllow(msg sip.Message) {
	allow := strings.TrimSpace(msg.Header("Allow"))
	if allow == "" {
		return
	}
	c.mu.Lock()
	c.remoteAllow = allow
	c.mu.Unlock()
}

func (c *Call) updateRemoteTargetFromRequest(msg sip.Message) {
	c.updateRemoteTarget(msg)
}

func (c *Call) updateRemoteTargetFromResponse(msg sip.Message) {
	c.updateRemoteTarget(msg)
}

func (c *Call) updateRemoteTarget(msg sip.Message) {
	contact := sip.AddressURI(msg.Header("Contact"))
	allow := strings.TrimSpace(msg.Header("Allow"))
	if contact == "" && allow == "" {
		return
	}
	c.mu.Lock()
	if contact != "" {
		c.remoteURI = contact
		c.targetURI = contact
	}
	if allow != "" {
		c.remoteAllow = allow
	}
	c.mu.Unlock()
}
