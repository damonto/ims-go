package tunnel

import "time"

func (s *Session) acceptInboundESPSequence(sequence uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.connected {
		return false
	}
	return s.inboundReplay.Accept(sequence)
}

type espAcceptResult struct {
	accepted      bool
	expireCurrent bool
}

func (s *Session) acceptESPSequence(spi, sequence uint32, protectedBytes uint64) espAcceptResult {
	rekeyNow := false
	s.mu.Lock()
	now := time.Now()
	s.pruneRetiredChildSAs(now)
	if !s.connected && len(s.retiredChildSAs) == 0 {
		s.mu.Unlock()
		return espAcceptResult{}
	}
	if s.inboundESP.SPI == spi {
		if !s.inboundReplay.Accept(sequence) {
			s.mu.Unlock()
			return espAcceptResult{}
		}
		if byteLifetimeWouldExpire(s.childSAInboundBytes, protectedBytes, s.childSAByteExpiresAt) {
			s.mu.Unlock()
			return espAcceptResult{expireCurrent: true}
		}
		s.childSAInboundBytes = addByteCount(s.childSAInboundBytes, protectedBytes)
		if s.childSAByteRekeyAt != 0 && s.childSAInboundBytes >= s.childSAByteRekeyAt {
			s.childSARekeyAt = now
			rekeyNow = true
		}
		result := espAcceptResult{
			accepted:      true,
			expireCurrent: s.childSAByteExpiresAt != 0 && s.childSAInboundBytes >= s.childSAByteExpiresAt,
		}
		s.mu.Unlock()
		if rekeyNow {
			s.notifyRekeyStateChanged()
		}
		return result
	}
	for i := range s.retiredChildSAs {
		if s.retiredChildSAs[i].inbound.SPI == spi {
			if !s.retiredChildSAs[i].replay.Accept(sequence) {
				s.mu.Unlock()
				return espAcceptResult{}
			}
			if byteLifetimeWouldExpire(s.retiredChildSAs[i].protectedBytes, protectedBytes, s.retiredChildSAs[i].byteExpiresAt) {
				s.retiredChildSAs = append(s.retiredChildSAs[:i], s.retiredChildSAs[i+1:]...)
				s.mu.Unlock()
				return espAcceptResult{}
			}
			s.retiredChildSAs[i].protectedBytes = addByteCount(s.retiredChildSAs[i].protectedBytes, protectedBytes)
			if s.retiredChildSAs[i].byteExpiresAt != 0 && s.retiredChildSAs[i].protectedBytes >= s.retiredChildSAs[i].byteExpiresAt {
				s.retiredChildSAs = append(s.retiredChildSAs[:i], s.retiredChildSAs[i+1:]...)
			}
			s.mu.Unlock()
			return espAcceptResult{accepted: true}
		}
	}
	s.mu.Unlock()
	return espAcceptResult{}
}
