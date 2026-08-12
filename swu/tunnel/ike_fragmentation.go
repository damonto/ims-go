package tunnel

import (
	"errors"
	"time"

	"github.com/damonto/ims-go/swu/ike"
)

const (
	maxIKEFragmentReassemblyQueues = 16
	maxIKEFragmentReassemblyBytes  = 256 * 1024
)

var errIKEFragmentReassemblyTooLarge = errors.New("ike fragment reassembly exceeds limit")

type ikeFragmentReassembly struct {
	total        uint16
	firstPayload byte
	firstPacket  []byte
	expiresAt    time.Time
	bytes        int
	fragments    map[uint16][]byte
}

func (r *ikeFragmentReassembly) add(fragment ikeFragment, packet []byte) ([]ike.Payload, []byte, bool, bool, error) {
	return r.addAt(fragment, packet, time.Now(), ikeFragmentReassemblyTimeout(defaultIKERetransmitDelays), maxIKEFragmentReassemblyBytes)
}

func (r *ikeFragmentReassembly) addAt(fragment ikeFragment, packet []byte, now time.Time, timeout time.Duration, maxBytes int) ([]ike.Payload, []byte, bool, bool, error) {
	if fragment.number == 0 || fragment.total == 0 {
		return nil, nil, false, false, nil
	}
	if fragment.number > fragment.total {
		return nil, nil, false, false, nil
	}
	if r.fragments == nil || fragment.total > r.total {
		r.total = fragment.total
		r.firstPayload = payloadTypeNone
		r.firstPacket = nil
		r.expiresAt = now.Add(timeout)
		r.bytes = 0
		r.fragments = make(map[uint16][]byte, int(fragment.total))
	}
	if fragment.total < r.total {
		return nil, nil, false, false, nil
	}
	if _, ok := r.fragments[fragment.number]; ok {
		return nil, nil, false, false, nil
	}
	if maxBytes > 0 && r.bytes+len(fragment.data) > maxBytes {
		return nil, nil, false, false, errIKEFragmentReassemblyTooLarge
	}
	if fragment.number == 1 {
		r.firstPayload = fragment.firstPayload
		r.firstPacket = append([]byte(nil), packet...)
	}
	r.fragments[fragment.number] = append([]byte(nil), fragment.data...)
	r.bytes += len(fragment.data)
	if len(r.fragments) < int(r.total) {
		if fragment.number == 1 {
			return nil, r.firstPacket, false, true, nil
		}
		return nil, nil, false, true, nil
	}
	body := make([]byte, 0)
	for i := uint16(1); i <= r.total; i++ {
		chunk, ok := r.fragments[i]
		if !ok {
			return nil, nil, false, true, nil
		}
		body = append(body, chunk...)
	}
	payloads, err := ike.DecodePayloadChain(r.firstPayload, body)
	if err != nil {
		if _, ok := errors.AsType[ike.UnsupportedCriticalPayloadError](err); ok {
			return nil, r.firstPacket, false, true, err
		}
		return nil, r.firstPacket, false, true, ike.InvalidSyntaxError{Err: err}
	}
	if hasEncryptedPayload(payloads) {
		return nil, r.firstPacket, false, true, ike.InvalidSyntaxError{Err: errors.New("nested encrypted payload")}
	}
	return payloads, r.firstPacket, true, true, nil
}

func (r ikeFragmentReassembly) expired(now time.Time) bool {
	return !r.expiresAt.IsZero() && !now.Before(r.expiresAt)
}

func (s *Session) openIKEPacketForState(state informationalState, packet ike.Packet, senderInitiator bool) ([]ike.Payload, []byte, bool, bool, error) {
	key := ikeMessageKeyForHeader(packet.Header)
	if _, _, ok := encryptedFragmentPayload(packet.Payloads); !ok {
		if len(packet.Payloads) != 1 {
			return nil, nil, false, false, errors.New("expected encrypted payload container")
		}
		s.clearIKEFragments(key)
		payloads, err := state.ike.OpenIKE(packet, senderInitiator)
		return payloads, packet.Raw, true, true, err
	}
	if !state.ikeFragmentationSupported {
		s.clearIKEFragments(key)
		return nil, nil, false, false, errors.New("ike fragmentation is not negotiated")
	}
	fragment, err := state.ike.OpenIKEFragment(packet, senderInitiator)
	if err != nil {
		return nil, nil, false, false, nil
	}
	payloads, firstPacket, complete, stored, err := s.addIKEFragment(key, fragment, packet.Raw)
	if err != nil || complete {
		s.clearIKEFragments(key)
	}
	if errors.Is(err, errIKEFragmentReassemblyTooLarge) {
		s.failSecurityAssociations(err)
	}
	return payloads, firstPacket, complete, stored, err
}

func canRetransmitCachedResponse(packet ike.Packet) bool {
	fragment, _, ok := encryptedFragmentPayload(packet.Payloads)
	if !ok {
		if len(packet.Payloads) != 1 {
			return false
		}
		return true
	}
	return fragment.FragmentNumber == 1
}

func encryptedFragmentPayload(payloads []ike.Payload) (*ike.EncryptedFragmentPayload, int, bool) {
	for i, payload := range payloads {
		fragment, ok := payload.(*ike.EncryptedFragmentPayload)
		if ok {
			return fragment, i, true
		}
	}
	return nil, 0, false
}

func responseCacheRequest(packet ike.Packet, request []byte) []byte {
	if len(request) != 0 {
		return request
	}
	return packet.Raw
}

func (s *Session) addIKEFragment(key ikeMessageKey, fragment ikeFragment, packet []byte) ([]ike.Payload, []byte, bool, bool, error) {
	now := time.Now()
	timeout := s.ikeFragmentReassemblyTimeout()
	s.mu.Lock()
	s.pruneIKEFragmentsLocked(now)
	reassembly := s.ikeFragments[key]
	if reassembly == nil {
		if len(s.ikeFragments) >= maxIKEFragmentReassemblyQueues {
			s.mu.Unlock()
			return nil, nil, false, false, errIKEFragmentReassemblyTooLarge
		}
		if s.ikeFragments == nil {
			s.ikeFragments = make(map[ikeMessageKey]*ikeFragmentReassembly)
		}
		reassembly = &ikeFragmentReassembly{}
		s.ikeFragments[key] = reassembly
	}
	payloads, firstPacket, complete, stored, err := reassembly.addAt(fragment, packet, now, timeout, maxIKEFragmentReassemblyBytes)
	if !stored && len(reassembly.fragments) == 0 {
		delete(s.ikeFragments, key)
	}
	s.mu.Unlock()
	return payloads, firstPacket, complete, stored, err
}

func (s *Session) clearIKEFragments(key ikeMessageKey) {
	s.mu.Lock()
	delete(s.ikeFragments, key)
	s.mu.Unlock()
}

func (s *Session) pruneIKEFragmentsLocked(now time.Time) {
	for key, reassembly := range s.ikeFragments {
		if reassembly == nil || reassembly.expired(now) {
			delete(s.ikeFragments, key)
		}
	}
}

func (s *Session) ikeFragmentReassemblyTimeout() time.Duration {
	return ikeFragmentReassemblyTimeout(s.ikeRetransmitDelays())
}

func ikeFragmentReassemblyTimeout(delays []time.Duration) time.Duration {
	if len(delays) == 0 {
		delays = defaultIKERetransmitDelays
	}
	var timeout time.Duration
	for _, delay := range delays {
		timeout += delay
	}
	return timeout
}
