package ims

import "github.com/damonto/ims-go/ims/registration"

// RegistrationInfo is a detached snapshot of network-provided public identities.
type RegistrationInfo = registration.Info

// Registration returns the current IMS registration, or an empty snapshot when
// no registration is active. Changing its identities does not affect the client.
func (c *Client) Registration() RegistrationInfo {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	if c.state.active == nil || c.state.active.ims.reg == nil {
		return RegistrationInfo{}
	}
	return c.state.active.ims.reg.Info()
}

func (c *Client) notifyRegistrationChange() {
	c.events.registrationChanged.publish(struct{}{}, nil)
}
