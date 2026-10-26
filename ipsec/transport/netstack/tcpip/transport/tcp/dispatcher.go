// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp

import (
	"fmt"
	"hash/maphash"
	"sync"

	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/header"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/stack"
	"github.com/damonto/ims-go/ipsec/transport/netstack/waiter"
)

// epQueue is a queue of endpoints.
type epQueue struct {
	mu   epQueueMutex
	list endpointList
}

// enqueue adds e to the queue if the endpoint is not already on the queue.
func (q *epQueue) enqueue(e *Endpoint) {
	q.mu.Lock()
	defer q.mu.Unlock()
	e.pendingProcessingMu.Lock()
	defer e.pendingProcessingMu.Unlock()

	if e.pendingProcessing {
		return
	}
	q.list.PushBack(e)
	e.pendingProcessing = true
}

// dequeue removes and returns the first element from the queue if available,
// returns nil otherwise.
func (q *epQueue) dequeue() *Endpoint {
	q.mu.Lock()
	if e := q.list.Front(); e != nil {
		q.list.Remove(e)
		e.pendingProcessingMu.Lock()
		e.pendingProcessing = false
		e.pendingProcessingMu.Unlock()
		q.mu.Unlock()
		return e
	}
	q.mu.Unlock()
	return nil
}

// processor is responsible for processing packets queued to a tcp endpoint.
type processor struct {
	epQ             epQueue
	newEndpointChan chan struct{}
	closeChan       chan struct{}
}

func signal(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (p *processor) close() {
	signal(p.closeChan)
}

func (p *processor) queueEndpoint(ep *Endpoint) {
	// Queue an endpoint for processing by the processor goroutine.
	p.epQ.enqueue(ep)
	signal(p.newEndpointChan)
}

// deliverAccepted delivers a passively connected endpoint to the accept queue
// of its associated listening endpoint.
//
// +checklocks:ep.mu
func deliverAccepted(ep *Endpoint) bool {
	lEP := ep.h.listenEP
	lEP.acceptMu.Lock()

	// Remove endpoint from list of pendingEndpoints as the handshake is now
	// complete.
	delete(lEP.acceptQueue.pendingEndpoints, ep)
	// Deliver this endpoint to the listening socket's accept queue.
	if lEP.acceptQueue.capacity == 0 {
		lEP.acceptMu.Unlock()
		return false
	}

	// NOTE: We always queue the endpoint and on purpose do not check if
	// accept queue is full at this point. This is similar to linux because
	// two racing incoming ACK's can both pass the acceptQueue.isFull check
	// and proceed to ESTABLISHED state. In such a case its better to
	// deliver both even if it temporarily exceeds the queue limit rather
	// than drop a connection that is fully connected.
	//
	// For reference see:
	//    https://github.com/torvalds/linux/blob/169e77764adc041b1dacba84ea90516a895d43b2/net/ipv4/tcp_minisocks.c#L764
	//    https://github.com/torvalds/linux/blob/169e77764adc041b1dacba84ea90516a895d43b2/net/ipv4/tcp_ipv4.c#L1500
	lEP.acceptQueue.endpoints.PushBack(ep)
	lEP.acceptMu.Unlock()
	ep.h.listenEP.waiterQueue.Notify(waiter.ReadableEvents)

	return true
}

// handleConnecting is responsible for TCP processing for an endpoint in one of
// the connecting states.
func handleConnecting(ep *Endpoint) {
	if !ep.TryLock() {
		return
	}
	cleanup := func() {
		ep.mu.Unlock()
		ep.drainClosingSegmentQueue()
		ep.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
	}
	if !ep.EndpointState().connecting() {
		// If the endpoint has already transitioned out of a connecting
		// stage then just return (only possible if it was closed or
		// timed out by the time we got around to processing the wakeup.
		ep.mu.Unlock()
		return
	}
	if err := ep.h.processSegments(); err != nil {
		// handshake failed. clean up the tcp endpoint and handshake
		// state.
		if lEP := ep.h.listenEP; lEP != nil {
			lEP.acceptMu.Lock()
			delete(lEP.acceptQueue.pendingEndpoints, ep)
			lEP.acceptMu.Unlock()
		}
		ep.handshakeFailed(err)
		cleanup()
		return
	}

	if ep.EndpointState() == StateEstablished && ep.h.listenEP != nil {
		ep.isConnectNotified = true
		ep.stack.Stats().TCP.PassiveConnectionOpenings.Increment()
		if !deliverAccepted(ep) {
			ep.resetConnectionLocked(&tcpip.ErrConnectionAborted{})
			cleanup()
			return
		}
	}
	ep.mu.Unlock()
}

// handleConnected is responsible for TCP processing for an endpoint in one of
// the connected states(StateEstablished, StateFinWait1 etc.)
func handleConnected(ep *Endpoint) {
	if !ep.TryLock() {
		return
	}

	if !ep.EndpointState().connected() {
		// If the endpoint has already transitioned out of a connected
		// state then just return (only possible if it was closed or
		// timed out by the time we got around to processing the wakeup.
		ep.mu.Unlock()
		return
	}

	// NOTE: We read this outside of e.mu lock which means that by the time
	// we get to handleSegments the endpoint may not be in ESTABLISHED. But
	// this should be fine as all normal shutdown states are handled by
	// handleSegmentsLocked.
	switch err := ep.handleSegmentsLocked(); {
	case err != nil:
		// Send any active resets if required.
		ep.resetConnectionLocked(err)
		fallthrough
	case ep.EndpointState() == StateClose:
		ep.mu.Unlock()
		ep.drainClosingSegmentQueue()
		ep.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
		return
	case ep.EndpointState() == StateTimeWait:
		startTimeWait(ep)
	}
	ep.mu.Unlock()
}

// startTimeWait starts a new goroutine to handle TIME-WAIT.
//
// +checklocks:ep.mu
func startTimeWait(ep *Endpoint) {
	// Disable close timer as we are now entering real TIME_WAIT.
	if ep.finWait2Timer != nil {
		ep.finWait2Timer.Stop()
	}
	// Wake up any waiters before we start TIME-WAIT.
	ep.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
	timeWaitDuration := ep.getTimeWaitDuration()
	ep.timeWaitTimer = ep.stack.Clock().AfterFunc(timeWaitDuration, ep.timeWaitTimerExpired)
}

// handleTimeWait is responsible for TCP processing for an endpoint in TIME-WAIT
// state.
func handleTimeWait(ep *Endpoint) {
	if !ep.TryLock() {
		return
	}

	if ep.EndpointState() != StateTimeWait {
		// If the endpoint has already transitioned out of a TIME-WAIT
		// state then just return (only possible if it was closed or
		// timed out by the time we got around to processing the wakeup.
		ep.mu.Unlock()
		return
	}

	extendTimeWait, reuseTW := ep.handleTimeWaitSegments()
	if reuseTW != nil {
		ep.transitionToStateCloseLocked()
		ep.mu.Unlock()
		ep.drainClosingSegmentQueue()
		ep.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
		reuseTW()
		return
	}
	if extendTimeWait {
		ep.timeWaitTimer.Reset(ep.getTimeWaitDuration())
	}
	ep.mu.Unlock()
}

// handleListen is responsible for TCP processing for an endpoint in LISTEN
// state.
func handleListen(ep *Endpoint) {
	if !ep.TryLock() {
		return
	}
	defer ep.mu.Unlock()

	if ep.EndpointState() != StateListen {
		// If the endpoint has already transitioned out of a LISTEN
		// state then just return (only possible if it was closed or
		// shutdown).
		return
	}

	for i := 0; i < maxSegmentsPerWake; i++ {
		s := ep.segmentQueue.dequeue()
		if s == nil {
			break
		}

		// Rejected listen segments are dropped after protocol validation.
		_ = ep.handleListenSegment(ep.listenCtx, s)
		s.DecRef()
	}
}

// start runs the main loop for a processor which is responsible for all TCP
// processing for TCP endpoints.
func (p *processor) start(wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case <-p.closeChan:
			return
		case <-p.newEndpointChan:
			for {
				ep := p.epQ.dequeue()
				if ep == nil {
					break
				}
				if ep.segmentQueue.empty() {
					continue
				}
				switch state := ep.EndpointState(); {
				case state.connecting():
					handleConnecting(ep)
				case state.connected() && state != StateTimeWait:
					handleConnected(ep)
				case state == StateTimeWait:
					handleTimeWait(ep)
				case state == StateListen:
					handleListen(ep)
				case state == StateError || state == StateClose:
					// Try to redeliver any still queued
					// packets to another endpoint or send a
					// RST if it can't be delivered.
					ep.mu.Lock()
					if st := ep.EndpointState(); st == StateError || st == StateClose {
						ep.drainClosingSegmentQueue()
					}
					ep.mu.Unlock()
				default:
					panic(fmt.Sprintf("unexpected tcp state in processor: %v", state))
				}
				// If there are more segments to process and the
				// endpoint lock is not held by user then
				// requeue this endpoint for processing.
				if !ep.segmentQueue.empty() && !ep.isOwnedByUser() {
					p.epQ.enqueue(ep)
				}
			}
		}
	}
}

// dispatcher manages a pool of TCP endpoint processors which are responsible
// for the processing of inbound segments. This fixed pool of processor
// goroutines do full tcp processing. The processor is selected based on the
// hash of the endpoint id to ensure that delivery for the same endpoint happens
// in-order.
type dispatcher struct {
	processors []processor
	wg         sync.WaitGroup
	hasher     endpointHasher
	mu         dispatcherMutex
	// +checklocks:mu
	closed bool
}

// init initializes a dispatcher and starts the main loop for all the processors
// owned by this dispatcher.
func (d *dispatcher) init(nProcessors int) {
	d.close()
	d.wait()

	d.mu.Lock()
	defer d.mu.Unlock()

	d.closed = false
	d.processors = make([]processor, nProcessors)
	d.hasher = endpointHasher{seed: maphash.MakeSeed()}
	d.startLocked()
}

// +checklocks:d.mu
func (d *dispatcher) startLocked() {
	if d.closed {
		return
	}
	for i := range d.processors {
		p := &d.processors[i]
		p.newEndpointChan = make(chan struct{}, 1)
		p.closeChan = make(chan struct{}, 1)
		d.wg.Add(1)
		go p.start(&d.wg)
	}
}

// close closes a dispatcher and its processors.
func (d *dispatcher) close() {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	for i := range d.processors {
		d.processors[i].close()
	}
}

// wait waits for all processor goroutines to end.
func (d *dispatcher) wait() {
	d.wg.Wait()
}

// queuePacket queues an incoming packet to the matching tcp endpoint and
// also queues the endpoint to a processor queue for processing.
func (d *dispatcher) queuePacket(stackEP stack.TransportEndpoint, id stack.TransportEndpointID, clock tcpip.Clock, pkt *stack.PacketBuffer) {
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()

	if closed {
		return
	}

	ep := stackEP.(*Endpoint)

	s, err := newIncomingSegment(id, clock, pkt)
	if err != nil {
		ep.stack.Stats().TCP.InvalidSegmentsReceived.Increment()
		ep.stats.ReceiveErrors.MalformedPacketsReceived.Increment()
		return
	}
	defer s.DecRef()

	if !s.csumValid {
		ep.stack.Stats().TCP.ChecksumErrors.Increment()
		ep.stats.ReceiveErrors.ChecksumErrors.Increment()
		return
	}

	ep.stack.Stats().TCP.ValidSegmentsReceived.Increment()
	ep.stats.SegmentsReceived.Increment()
	if (s.flags & header.TCPFlagRst) != 0 {
		ep.stack.Stats().TCP.ResetsReceived.Increment()
	}

	if !ep.enqueueSegment(s) {
		return
	}

	// Only wakeup the processor if endpoint lock is not held by a user
	// goroutine as endpoint.UnlockUser will wake up the processor if the
	// segment queue is not empty.
	if !ep.isOwnedByUser() {
		d.selectProcessor(id).queueEndpoint(ep)
	}
}

// selectProcessor uses a hash of the transport endpoint ID to queue the
// endpoint to a specific processor. This is required to main TCP ordering as
// queueing the same endpoint to multiple processors can *potentially* result in
// out of order processing of incoming segments. It also ensures that a dispatcher
// evenly loads the processor goroutines.
func (d *dispatcher) selectProcessor(id stack.TransportEndpointID) *processor {
	return &d.processors[d.hasher.hash(id)%uint64(len(d.processors))]
}

// endpointHasher distributes packets for one flow to the same processor.
type endpointHasher struct {
	seed maphash.Seed
}

func (h endpointHasher) hash(id stack.TransportEndpointID) uint64 {
	return maphash.Comparable(h.seed, id)
}
