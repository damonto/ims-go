package voice

func (c *Call) terminateAfterSessionRefreshFailure() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	c.expireUnrefreshedSession()
}

func (c *Call) expireUnrefreshedSession() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	ctx, cancel := c.service.timeoutContext(callReleaseTimeout)
	defer cancel()
	c.setState(CallStateEnding, "session timer expired")
	_ = c.closeMedia()
	resp, err := c.service.sess.Exchange(ctx, c.buildBYE(""))
	if !byeReleaseCompleted(resp, err) {
		err := byeReleaseError("expiring session timer", resp, err)
		c.finish(CallStateFailed, err.Error())
		c.service.emitError(err)
		return
	}
	c.finish(CallStateEnded, "session timer expired")
}
