package voice

import (
	"encoding/binary"
	"time"
)

// DTMFEvent reports the first received report of a remote key, even if that
// report is already an end packet. It does not report release or final duration.
// Reports older than an evicted segment are ignored while source history is
// retained. Missing boundary reports can produce separate notifications for
// long-press segments; detection never guesses that two keys are one event.
type DTMFEvent struct {
	Call   *Call
	CallID string
	Digit  string
	At     time.Time
}

// This is a resource policy, not an RFC limit. Keep up to 32 active source
// histories; retire a history after two minutes without RTP from that source.
// Very late reports after retirement are treated as a new source incarnation.
const (
	maxDTMFSources        = 32
	dtmfSourceIdleTimeout = 2 * time.Minute
)

type dtmfReceiveState struct {
	sources map[uint32]*dtmfSource
}

type dtmfSource struct {
	lastSeen time.Time
	recent   [64]dtmfSegment
	count    int
	floor    uint32
	hasFloor bool
}

type dtmfSegment struct {
	timestamp uint32
	event     byte
	duration  uint16
	end       bool
	start     bool
}

// parseDTMFReports validates the entire payload before any receive state changes.
// Unknown event codes still contribute duration to subsequent timestamps.
func parseDTMFReports(packet MediaPacket) []dtmfSegment {
	payload := packet.RTPPayload
	if len(payload) == 0 || len(payload)%dtmfPayloadSize != 0 {
		return nil
	}
	reports := make([]dtmfSegment, 0, len(payload)/dtmfPayloadSize)
	timestamp := packet.RTPTimestamp
	for offset := 0; offset < len(payload); offset += dtmfPayloadSize {
		report := payload[offset : offset+dtmfPayloadSize]
		duration := binary.BigEndian.Uint16(report[2:])
		if duration == 0 {
			return nil
		}
		reports = append(reports, dtmfSegment{
			timestamp: timestamp,
			event:     report[0],
			duration:  duration,
			end:       report[1]&0x80 != 0,
			// A packed packet's M bit identifies some event, not necessarily the first.
			start: len(payload) == dtmfPayloadSize && packet.RTPMarker,
		})
		timestamp += uint32(duration)
	}
	return reports
}

func (c *Call) receiveDTMF(packet MediaPacket) {
	c.mu.Lock()
	format := c.media.DTMF
	if c.closed || packet.RTCP || format == nil || packet.RTPPayloadType != format.PayloadType {
		c.mu.Unlock()
		return
	}
	reports := parseDTMFReports(packet)
	var events []DTMFEvent
	for _, report := range reports {
		if !dtmfEventMaskContains(dtmfEventMaskOrDefault(format.DTMFEventMask), report.event) {
			continue
		}
		if c.dtmfRecv.record(packet.RTPSSRC, report) {
			events = append(events, DTMFEvent{Call: c, CallID: c.id, Digit: string("0123456789*#ABCD"[report.event]), At: time.Now()})
		}
	}
	var notify func(DTMFEvent)
	if c.endpoint != nil {
		notify = c.endpoint.cfg.OnDTMF
	}
	c.mu.Unlock()
	// Callbacks can read Call state; never invoke them with c.mu held.
	if notify != nil {
		for _, event := range events {
			notify(event)
		}
	}
}

func (r *dtmfReceiveState) record(ssrc uint32, segment dtmfSegment) bool {
	source := r.source(ssrc, time.Now())
	return source != nil && source.record(segment)
}

// Speech activity keeps an existing source's DTMF replay history alive.
func (r *dtmfReceiveState) refreshSource(ssrc uint32, now time.Time) {
	source := r.sources[ssrc]
	if source == nil {
		return
	}
	if now.Sub(source.lastSeen) >= dtmfSourceIdleTimeout {
		delete(r.sources, ssrc)
		return
	}
	source.lastSeen = now
}

func (r *dtmfReceiveState) source(ssrc uint32, now time.Time) *dtmfSource {
	for id, source := range r.sources {
		if now.Sub(source.lastSeen) >= dtmfSourceIdleTimeout {
			delete(r.sources, id)
		}
	}
	source := r.sources[ssrc]
	if source == nil {
		if len(r.sources) >= maxDTMFSources {
			return nil
		}
		if r.sources == nil {
			r.sources = make(map[uint32]*dtmfSource)
		}
		source = &dtmfSource{}
		r.sources[ssrc] = source
	}
	source.lastSeen = now
	return source
}

func (s *dtmfSource) record(segment dtmfSegment) bool {
	// Serial timestamp comparisons handle rollover within half the RTP timestamp
	// space. Reports outside the retained history are deliberately not replayed.
	if s.hasFloor && int32(segment.timestamp-s.floor) <= 0 {
		return false
	}
	continuation := false
	oldest := 0
	for i := range s.count {
		previous := &s.recent[i]
		if int32(previous.timestamp-s.recent[oldest].timestamp) < 0 {
			oldest = i
		}
		if previous.event != segment.event {
			continue
		}
		if previous.timestamp == segment.timestamp {
			previous.duration = max(previous.duration, segment.duration)
			previous.end = previous.end || segment.end
			previous.start = previous.start || segment.start
			return false
		}
		// RFC 4733 section 2.5.2.3 requires an observed full unfinished
		// segment. Check both orders, without inferring missing boundaries.
		if dtmfContinues(*previous, segment) || dtmfContinues(segment, *previous) {
			continuation = true
		}
	}
	if s.count < len(s.recent) {
		s.recent[s.count] = segment
		s.count++
		return !continuation
	}
	if int32(segment.timestamp-s.recent[oldest].timestamp) <= 0 {
		return false
	}
	s.floor = s.recent[oldest].timestamp
	s.hasFloor = true
	s.recent[oldest] = segment
	return !continuation
}

func dtmfContinues(first, next dtmfSegment) bool {
	distance := int32(next.timestamp - first.timestamp)
	return first.duration == 0xffff && !first.end && !next.start && distance == 0xffff
}
