package voice

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/damonto/vowifi-go/ims/sip"
)

func (c *Call) beginReliableProvisional(status int, cseq int64, method string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nextRSeq == 0 {
		c.nextRSeq = initialReliableRSeq() - 1
	}
	c.nextRSeq++
	if status == sipStatusSessionProgress && c.provisionalReady == nil {
		c.provisionalReady = make(chan struct{})
	}
	c.pendingReliable = reliableProvisional{
		rseq:   c.nextRSeq,
		cseq:   cseq,
		method: strings.ToUpper(strings.TrimSpace(method)),
		status: status,
	}
	return c.nextRSeq
}

func initialReliableRSeq() int64 {
	return rand.Int64N(rseqInitialMax) + 1
}

func nextReliableProvisionalRetransmitInterval(interval time.Duration) time.Duration {
	// RFC 3262 reliable 1xx retransmissions double until the 64*T1 deadline;
	// unlike INVITE 2xx retransmissions, they are not capped at T2.
	return interval * 2
}

func (c *Call) clearReliableProvisional(rseq int64) {
	c.mu.Lock()
	var stop chan struct{}
	if c.pendingReliable.rseq == rseq {
		c.pendingReliable = reliableProvisional{}
		c.reliableResponse = sip.Message{}
		stop = c.reliableStop
		c.reliableStop = nil
	}
	c.mu.Unlock()
	if stop != nil {
		close(stop)
	}
}

func (c *Call) pendingReliableProvisionalResponse() (sip.Message, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pendingReliable.rseq == 0 || c.reliableResponse.StartLine == "" {
		return sip.Message{}, false
	}
	return cloneSIPMessage(c.reliableResponse), true
}

func (c *Call) waitForReliableProvisionalAnswer(ctx context.Context) error {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return errors.New("answering call: call is closed")
		}
		wait := c.direction == CallDirectionIncoming &&
			c.state == CallStateRinging &&
			c.pendingReliable.status == sipStatusSessionProgress &&
			((c.delayedOffer && !c.prackAnsweredOffer) || (!c.delayedOffer && !c.provisionalAnswer))
		ch := c.provisionalReady
		if wait && ch == nil {
			ch = make(chan struct{})
			c.provisionalReady = ch
		}
		c.mu.Unlock()
		if !wait {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("answering call: waiting for PRACK: %w", ctx.Err())
		case <-ch:
		}
	}
}

func (c *Call) signalProvisionalReady() {
	c.mu.Lock()
	ch := c.provisionalReady
	c.provisionalReady = nil
	c.mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (c *Call) recordReliableProvisional(msg sip.Message) (bool, error) {
	tag := sip.HeaderTag(msg.Header("To"))
	if tag == "" {
		return false, errors.New("handling reliable provisional response: missing To tag")
	}
	var rseq rseqHeader
	if err := rseq.UnmarshalText([]byte(msg.Header("RSeq"))); err != nil {
		return false, err
	}
	if c.reliableRSeq == nil {
		c.reliableRSeq = make(map[string]int64)
	}
	last, ok := c.reliableRSeq[tag]
	current := int64(rseq)
	if !ok {
		if current > rseqInitialMax {
			return false, fmt.Errorf("handling reliable provisional response: initial RSeq %d exceeds %d", current, rseqInitialMax)
		}
		c.reliableRSeq[tag] = current
		return true, nil
	}
	if current <= last {
		return false, nil
	}
	if current != last+1 {
		return false, nil
	}
	c.reliableRSeq[tag] = current
	return true, nil
}
