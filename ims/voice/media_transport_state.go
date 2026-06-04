package voice

import "fmt"

func (c *Call) closeMedia() error {
	c.mu.Lock()
	transport := c.transport
	c.transport = nil
	c.mu.Unlock()
	if transport == nil {
		return nil
	}
	return transport.Close()
}

func (c *Call) mediaTransport(action string) (MediaTransport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, fmt.Errorf("%s: call is closed", action)
	}
	if c.transport == nil {
		return nil, fmt.Errorf("%s: media transport is not configured", action)
	}
	return c.transport, nil
}
