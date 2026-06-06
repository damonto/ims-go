package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/damonto/vowifi-go/swu/ike"
)

var invalidMessageIDNotifyTimeout = 750 * time.Millisecond

type informationalAction struct {
	deleteIKE             bool
	deleteChild           bool
	reactivationRequested bool
	promotePendingChild   bool
	deleteRetiredChildSPI uint32
	pcscfReselection      bool
	pcscfInfo             Info
}

func (s *Session) closeDone() <-chan struct{} {
	return s.closeCh
}

func (s *Session) sendInvalidMessageIDNotification(state informationalState, invalidMessageID uint32) error {
	if !state.available() || !s.allowInvalidMessageIDNotification(time.Now()) {
		return nil
	}
	ctx, cancel := s.timeoutContext(invalidMessageIDNotifyTimeout)
	defer cancel()
	release, err := s.acquireIKERequest(ctx, ikeActionSendInvalidMessageIDNotification)
	if err != nil {
		return err
	}
	defer release()
	messageID, err := s.allocateMessageID()
	if err != nil {
		return fmt.Errorf("sending invalid message id notification: %w", err)
	}
	key := state.responseMessageKey(messageID, exchangeTypeInformational)
	waiter := s.registerInformationalWaiter(key)
	defer s.unregisterInformationalWaiter(key, waiter)
	wires, err := state.sealInitiatorRequest(messageID, []ike.Payload{
		&ike.NotifyPayload{NotifyType: notifyTypeInvalidMessageID, Data: uint32Bytes(invalidMessageID)},
	})
	if err != nil {
		return fmt.Errorf("sending invalid message id notification: sealing request: %w", err)
	}
	if _, err := s.exchangeInformational(ctx, state, messageID, wires, waiter); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}

func (s *Session) informationalResponsePeer(addr net.Addr, fallback *net.UDPAddr) *net.UDPAddr {
	udpAddr, _ := addr.(*net.UDPAddr)
	if udpAddr != nil {
		return cloneUDPAddr(udpAddr)
	}
	return cloneUDPAddr(fallback)
}

func (s *Session) timeoutContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return contextWithStopTimeout(s.closeCh, timeout)
}

func contextWithStopTimeout(stop <-chan struct{}, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	done := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-stop:
			cancel()
		case <-done:
		}
	}()
	return ctx, func() {
		once.Do(func() {
			close(done)
			cancel()
		})
	}
}
