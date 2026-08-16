package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/damonto/ims-go/swu/ike"
)

const defaultInvalidMessageIDNotifyTimeout = 750 * time.Millisecond

type ikeExchangeState struct {
	informWaiters      map[ikeMessageKey]chan inboundIKE
	informResponses    map[uint32][][]byte
	informResponseReqs map[uint32][]byte
	ikeFragments       map[ikeMessageKey]*ikeFragmentReassembly
	ikeRequestGate     chan struct{}
	rekeyWake          chan struct{}
}

type informationalAction struct {
	deleteIKE              bool
	deleteChild            bool
	reactivationRequested  bool
	pdnDeactivated         bool
	promotePendingChild    bool
	deleteRetiredChildSPIs []uint32
	pcscfReselection       bool
	pcscfInfo              Info
}

func (s *Session) closeDone() <-chan struct{} {
	return s.closeCh
}

func (s *Session) sendInvalidMessageIDNotification(state informationalState, invalidMessageID uint32) error {
	if !state.available() || !s.allowInvalidMessageIDNotification(time.Now()) {
		return nil
	}
	timeout := s.invalidMessageIDNotifyTimeout
	if timeout <= 0 {
		timeout = defaultInvalidMessageIDNotifyTimeout
	}
	ctx, cancel := s.timeoutContext(timeout)
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
	if _, err := s.exchangeInformationalRequest(ctx, state, messageID, wires, waiter, ikeActionSendInvalidMessageIDNotification, false); err != nil && !errors.Is(err, context.DeadlineExceeded) {
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
