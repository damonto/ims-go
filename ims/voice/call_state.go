package voice

import "time"

func (c *Call) setState(state CallState, cause string) {
	c.mu.Lock()
	if c.state == state && cause == "" {
		c.mu.Unlock()
		return
	}
	if !callCanTransition(c.state, state) {
		from := c.state
		id := c.id
		c.mu.Unlock()
		c.service.logger.Warn("ignoring invalid call state transition", "call_id", id, "from", from, "to", state, "cause", cause)
		return
	}
	c.state = state
	id := c.id
	hold := normalizeHoldState(c.hold)
	c.mu.Unlock()
	c.service.emit(CallEvent{Call: c, CallID: id, State: state, Hold: hold, Cause: cause, At: time.Now()})
}

func callCanTransition(from, to CallState) bool {
	if from == "" || from == to {
		return true
	}
	if from == CallStateEnded || from == CallStateFailed {
		return false
	}
	if to == CallStateEnded || to == CallStateFailed {
		return true
	}
	switch from {
	case CallStateDialing:
		return to == CallStateRinging || to == CallStateEarlyMedia || to == CallStateConfirmed || to == CallStateEnding
	case CallStateRinging:
		return to == CallStateEarlyMedia || to == CallStateAnswering || to == CallStateConfirmed || to == CallStateActive || to == CallStateEnding
	case CallStateEarlyMedia:
		return to == CallStateRinging || to == CallStateConfirmed || to == CallStateActive || to == CallStateEnding
	case CallStateAnswering:
		return to == CallStateActive || to == CallStateEnding
	case CallStateConfirmed:
		return to == CallStateActive || to == CallStateEnding
	case CallStateActive:
		return to == CallStateEnding
	case CallStateEnding:
		return false
	default:
		return true
	}
}

func (c *Call) finish(state CallState, cause string) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	id := c.id
	emit := c.state != state || cause != ""
	c.state = state
	hold := normalizeHoldState(c.hold)
	attachment := c.dialogAttachment
	stop := c.inviteOKStop
	ringbackStop := c.ringbackStop
	ringingStop := c.ringingStop
	mediaStop := c.mediaWatchStop
	reliableStop := c.reliableStop
	sessionTimerStop := c.sessionTimerStop
	provisionalReady := c.provisionalReady
	c.inviteOKStop = nil
	c.inviteOKCSeq = 0
	c.ringbackStop = nil
	c.ringingStop = nil
	c.mediaActivity = nil
	c.mediaWatchStop = nil
	c.reliableStop = nil
	c.sessionTimerStop = nil
	c.provisionalReady = nil
	c.dialogAttachment = nil
	c.mu.Unlock()

	if stop != nil {
		close(stop)
	}
	if ringbackStop != nil {
		close(ringbackStop)
	}
	if ringingStop != nil {
		close(ringingStop)
	}
	if mediaStop != nil {
		close(mediaStop)
	}
	if reliableStop != nil {
		close(reliableStop)
	}
	if sessionTimerStop != nil {
		close(sessionTimerStop)
	}
	if provisionalReady != nil {
		close(provisionalReady)
	}
	if attachment != nil {
		_ = attachment.Close()
	}
	_ = c.closeMedia()
	c.service.removeCall(id)
	if emit {
		c.service.emit(CallEvent{Call: c, CallID: id, State: state, Hold: hold, Cause: cause, At: time.Now()})
	}
}
