package transport

import (
	"errors"
	"slices"

	imssession "github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ipsec/packet"
)

// Keep the out-of-order queue below the advertised window so retransmitted
// in-order data still has room to arrive and unblock delivery.
const tcpPendingReceiveMax = tcpDefaultWindow * 3 / 4

var errTCPReceiveQueueFull = errors.New("tcp receive queue is full")

type tcpReceivedSegment struct {
	seq     uint32
	flags   byte
	payload []byte
}

func (t *TCPConn) consumeSegment(seq uint32, flags byte, payload []byte) error {
	segLen := uint32(len(payload)) + tcpControlSequenceLen(flags)
	if segLen == 0 {
		return nil
	}
	if !tcpSeqAfter(seq+segLen, t.recvSeq) {
		return nil
	}
	if tcpSeqAfter(t.recvSeq, seq) {
		skip := t.recvSeq - seq

		skip = min(skip, uint32(len(payload)))

		payload = payload[skip:]
		seq = t.recvSeq
	}
	if seq != t.recvSeq {
		return nil
	}

	fin := flags&packet.TCPFlagFIN != 0
	nextRecv := seq + uint32(len(payload))
	if fin {
		nextRecv++
	}
	if len(payload) == 0 {
		t.recvSeq = nextRecv
		return errTCPPeerClosed
	}

	stream := append(append([]byte(nil), t.stream...), payload...)
	messages, rest, err := imssession.StageSIPMessages(stream)
	startLine := ""
	if len(messages) > 0 {
		startLine = packetStartLine(messages[0])
	}
	t.session.Logger().Debug("staged TCP SIP stream", "payload_len", len(payload), "stream_len", len(stream), "messages", len(messages), "rest_len", len(rest), "start_line", startLine, "err", err)
	if err != nil && len(messages) > cap(t.msgCh)-len(t.msgCh) {
		return errTCPReceiveQueueFull
	}
	if err != nil {
		t.recvSeq = nextRecv
		t.stream = rest
		for _, msg := range messages {
			t.msgCh <- msg
		}
		return err
	}
	if len(messages) > cap(t.msgCh)-len(t.msgCh) {
		return errTCPReceiveQueueFull
	}
	t.recvSeq = nextRecv
	t.stream = rest
	for _, msg := range messages {
		t.msgCh <- msg
	}
	if fin {
		return errTCPPeerClosed
	}
	return nil
}

func (t *TCPConn) queuePendingSegment(seq uint32, flags byte, payload []byte) {
	pending := tcpReceivedSegment{
		seq:     seq,
		flags:   flags & packet.TCPFlagFIN,
		payload: append([]byte(nil), payload...),
	}
	size := pending.bufferedBytes()
	if size == 0 {
		return
	}
	for i := range t.pendingRcvdSegments {
		if t.pendingRcvdSegments[i].seq != seq {
			continue
		}
		if size <= t.pendingRcvdSegments[i].bufferedBytes() {
			return
		}
		nextSize := t.pendingRcvdBytes - t.pendingRcvdSegments[i].bufferedBytes() + size
		if nextSize > tcpPendingReceiveMax {
			return
		}
		t.pendingRcvdSegments[i] = pending
		t.pendingRcvdBytes = nextSize
		t.sortPendingSegments()
		return
	}
	if t.pendingRcvdBytes+size > tcpPendingReceiveMax {
		return
	}
	t.pendingRcvdSegments = append(t.pendingRcvdSegments, pending)
	t.pendingRcvdBytes += size
	t.sortPendingSegments()
}

func (t *TCPConn) consumePendingSegments() error {
	for len(t.pendingRcvdSegments) > 0 {
		pending := t.pendingRcvdSegments[0]
		if tcpSeqAfter(pending.seq, t.recvSeq) {
			return nil
		}
		err := t.consumeSegment(pending.seq, pending.flags, pending.payload)
		if errors.Is(err, errTCPReceiveQueueFull) {
			return nil
		}
		t.dropPendingSegment(0)
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *TCPConn) sortPendingSegments() {
	base := t.recvSeq
	slices.SortFunc(t.pendingRcvdSegments, func(a, b tcpReceivedSegment) int {
		da := a.seq - base
		db := b.seq - base
		if da < db {
			return -1
		}
		if da > db {
			return 1
		}
		return 0
	})
}

func (t *TCPConn) dropPendingSegment(index int) {
	t.pendingRcvdBytes -= t.pendingRcvdSegments[index].bufferedBytes()
	copy(t.pendingRcvdSegments[index:], t.pendingRcvdSegments[index+1:])
	last := len(t.pendingRcvdSegments) - 1
	t.pendingRcvdSegments[last] = tcpReceivedSegment{}
	t.pendingRcvdSegments = t.pendingRcvdSegments[:last]
}

func (s tcpReceivedSegment) bufferedBytes() int {
	return len(s.payload) + int(tcpControlSequenceLen(s.flags))
}
