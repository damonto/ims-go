package tunnel

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"time"

	"github.com/damonto/vowifi-go/swu/esp"
)

func (s *Session) commitConnect(state *connectState) {
	if state.established.LivenessTimeout <= 0 {
		state.established.LivenessTimeout = state.sessionLivenessTimeout()
	}
	s.mu.Lock()
	s.connected = true
	s.connecting = false
	s.innerLocal = state.innerLocalAddr(s.cfg.LocalSIPPort)
	s.innerRemote = state.innerRemoteAddr(s.cfg.SIPPort)
	s.tunnel = infoFromHandshake(state.established.Info)
	s.ike = state.crypto
	s.pendingIKESA = ikeSARekeyResult{}
	s.pendingIKESAReady = false
	s.retiredIKESAs = nil
	s.ikeLocalInitiator = true
	s.tunnelErr = nil
	s.initiatorSPI = state.initiatorSPI
	s.responderSPI = state.responderSPI
	s.nextMessageID = state.established.NextMessageID
	s.nextPeerMessageID = 0
	s.deviceIdentity = state.established.DeviceIdentity
	s.espSeq = 0
	s.inboundReplay.Reset()
	now := time.Now()
	s.lastProtectedRx = now
	s.lastProtectedTx = now
	s.ikeSAExpiresAt = childSAExpiry(now, s.cfg.IKESALifetime)
	s.ikeSARekeyAt = childSARekeyTime(now, s.cfg.IKESALifetime, s.cfg.IKESARekeyMargin)
	s.ikeSAByteExpiresAt = saByteExpiry(s.cfg.IKESAByteLifetime)
	s.ikeSAByteRekeyAt = saByteRekeyLimit(s.cfg.IKESAByteLifetime, s.cfg.IKESAByteRekeyMargin)
	s.ikeSAInboundBytes = 0
	s.ikeSAOutboundBytes = 0
	s.ikeSARekeying = false
	s.simultaneousIKESA = simultaneousIKESARekey{}
	s.childSAExpiresAt = childSAExpiry(now, s.cfg.ChildSALifetime)
	s.childSARekeyAt = childSARekeyTime(now, s.cfg.ChildSALifetime, s.cfg.ChildSARekeyMargin)
	s.childSAByteExpiresAt = saByteExpiry(s.cfg.ChildSAByteLifetime)
	s.childSAByteRekeyAt = saByteRekeyLimit(s.cfg.ChildSAByteLifetime, s.cfg.ChildSAByteRekeyMargin)
	s.childSAInboundBytes = 0
	s.childSAOutboundBytes = 0
	s.childSARekeying = false
	s.simultaneousChildSA = simultaneousChildSARekey{}
	s.livenessTimeout = state.established.LivenessTimeout
	s.natKeepaliveInterval = s.cfg.NATKeepaliveInterval
	s.informWaiters = make(map[ikeMessageKey]chan inboundIKE)
	s.informResponses = make(map[uint32][]byte)
	s.informResponseReqs = make(map[uint32][]byte)
	s.outboundESP = state.outboundESPCodec()
	s.inboundESP = state.inboundESPCodec()
	s.retiredChildSAs = nil
	s.pendingChildSA = pendingChildSA{}
	s.dataPlaneDone = make(chan struct{})
	s.mu.Unlock()
}

func (s *Session) startBackgroundLoops() {
	s.wg.Add(5)
	go s.readLoop()
	go s.livenessLoop()
	go s.natKeepaliveLoop()
	go s.ikeSARekeyLoop()
	go s.childSARekeyLoop()
}

func (s *Session) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultCloseTimeout)
	defer cancel()
	return s.CloseContext(ctx)
}

func (s *Session) CloseContext(ctx context.Context) error {
	_ = s.sendDeleteRequest(ctx)
	if s.closeCancel != nil {
		s.closeCancel()
	}
	s.wg.Wait()
	s.discardSecurityAssociations(nil)
	if !s.owned {
		return nil
	}
	closeErr := s.conn.Close()
	if errors.Is(closeErr, net.ErrClosed) {
		return nil
	}
	return closeErr
}

func (s *Session) isClosed() bool {
	return s.closeCtx.Err() != nil
}

func (s *Session) discardSecurityAssociations(cause error) {
	if cause == nil {
		cause = errSessionClosed
	}
	s.abortInformationalWaiters(cause)
	s.mu.Lock()
	closeDataPlaneDone(s.dataPlaneDone)
	s.dataPlaneDone = nil
	s.connected = false
	s.connecting = false
	s.innerLocal = nil
	s.innerRemote = nil
	s.tunnel = Info{}
	s.outboundESP = esp.Codec{}
	s.inboundESP = esp.Codec{}
	s.espSeq = 0
	s.inboundReplay.Reset()
	s.retiredChildSAs = nil
	s.pendingChildSA = pendingChildSA{}
	s.ike = nil
	s.pendingIKESA = ikeSARekeyResult{}
	s.pendingIKESAReady = false
	s.retiredIKESAs = nil
	s.ikeLocalInitiator = false
	s.tunnelErr = nil
	s.initiatorSPI = 0
	s.responderSPI = 0
	s.deviceIdentity = ""
	s.nextMessageID = 0
	s.nextPeerMessageID = 0
	s.lastProtectedRx = time.Time{}
	s.lastProtectedTx = time.Time{}
	s.ikeSAExpiresAt = time.Time{}
	s.ikeSARekeyAt = time.Time{}
	s.ikeSAByteExpiresAt = 0
	s.ikeSAByteRekeyAt = 0
	s.ikeSAInboundBytes = 0
	s.ikeSAOutboundBytes = 0
	s.ikeSARekeying = false
	s.simultaneousIKESA = simultaneousIKESARekey{}
	s.childSAExpiresAt = time.Time{}
	s.childSARekeyAt = time.Time{}
	s.childSAByteExpiresAt = 0
	s.childSAByteRekeyAt = 0
	s.childSAInboundBytes = 0
	s.childSAOutboundBytes = 0
	s.childSARekeying = false
	s.simultaneousChildSA = simultaneousChildSARekey{}
	s.livenessTimeout = 0
	s.natKeepaliveInterval = 0
	s.informResponses = nil
	s.informResponseReqs = nil
	s.mu.Unlock()

	s.notifyDetachedAttachments(s.detachAllAttachments(), cause)
}

var (
	errChildSAUnavailable = errors.New("child sa is unavailable")
	errChildSAExpired     = errors.New("child sa lifetime expired")
)

func (s *Session) discardChildSecurityAssociations(cause error) {
	if cause == nil {
		cause = errChildSAUnavailable
	}
	s.mu.Lock()
	closeDataPlaneDone(s.dataPlaneDone)
	s.dataPlaneDone = nil
	s.connected = false
	s.connecting = false
	s.innerLocal = nil
	s.innerRemote = nil
	s.tunnel = Info{}
	s.outboundESP = esp.Codec{}
	s.inboundESP = esp.Codec{}
	s.espSeq = 0
	s.inboundReplay.Reset()
	s.retiredChildSAs = nil
	s.pendingChildSA = pendingChildSA{}
	s.ikeSARekeying = false
	s.simultaneousIKESA = simultaneousIKESARekey{}
	s.childSAExpiresAt = time.Time{}
	s.childSARekeyAt = time.Time{}
	s.childSAByteExpiresAt = 0
	s.childSAByteRekeyAt = 0
	s.childSAInboundBytes = 0
	s.childSAOutboundBytes = 0
	s.childSARekeying = false
	s.simultaneousChildSA = simultaneousChildSARekey{}
	s.tunnelErr = cause
	s.mu.Unlock()

	s.tryDeliverError(fmt.Errorf("reading packet: %w", cause))
	s.notifyDetachedAttachments(s.detachAllAttachments(), cause)
}

func (s *Session) failSecurityAssociations(cause error) {
	s.discardSecurityAssociations(cause)
	if s.closeCancel != nil {
		s.closeCancel()
	}
	if s.owned && s.conn != nil {
		_ = s.conn.Close()
	}
}

func (s *Session) notifyDetachedAttachments(attachments []*sessionAttachment, cause error) {
	if cause == nil {
		cause = errSessionClosed
	}
	for _, attachment := range attachments {
		attachment.fail(cause)
	}
}

func (s *Session) disconnectedTunnelErrLocked() error {
	if s.connected || s.ike == nil {
		return nil
	}
	if s.tunnelErr != nil {
		return s.tunnelErr
	}
	return errChildSAUnavailable
}

func (s *Session) currentDisconnectedTunnelErr(action string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.disconnectedTunnelErrLocked(); err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	return nil
}

func (s *Session) ikeSALifecycleLocked() ikeSALifecycleState {
	if s.ike == nil {
		return ikeSALifecycleNone
	}
	if s.pendingIKESAReady {
		return ikeSALifecyclePendingInstall
	}
	if s.ikeSARekeying {
		return ikeSALifecycleRekeying
	}
	return ikeSALifecycleActive
}

func (s *Session) childSALifecycleLocked() childSALifecycleState {
	if !s.connected {
		return childSALifecycleNone
	}
	if s.pendingChildSA.ready {
		return childSALifecyclePendingOutbound
	}
	if s.childSARekeying {
		return childSALifecycleRekeying
	}
	return childSALifecycleActive
}

func childSAExpiry(now time.Time, lifetime time.Duration) time.Time {
	if lifetime <= 0 {
		return time.Time{}
	}
	return now.Add(lifetime)
}

var saRekeyJitter = randomSARekeyJitter

func childSARekeyTime(now time.Time, lifetime, margin time.Duration) time.Time {
	if lifetime <= 0 || margin <= 0 {
		return time.Time{}
	}
	return now.Add(lifetime - margin + saRekeyJitter(margin/2))
}

func saByteExpiry(lifetime uint64) uint64 {
	return lifetime
}

func saByteRekeyLimit(lifetime, margin uint64) uint64 {
	if lifetime == 0 || margin == 0 {
		return 0
	}
	return lifetime - margin
}

func byteLifetimeWouldExpire(current, add, limit uint64) bool {
	if limit == 0 {
		return false
	}
	if current >= limit {
		return true
	}
	return add > limit-current
}

func addByteCount(current, add uint64) uint64 {
	if add > ^uint64(0)-current {
		return ^uint64(0)
	}
	return current + add
}

func randomSARekeyJitter(maxDelay time.Duration) time.Duration {
	if maxDelay <= 0 {
		return 0
	}
	n, err := crand.Int(crand.Reader, big.NewInt(int64(maxDelay)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

func (s *Session) ikeSAExpiredLocked(now time.Time) bool {
	return s.ike != nil && !s.ikeSAExpiresAt.IsZero() && !now.Before(s.ikeSAExpiresAt)
}

func (s *Session) ikeSAByteExpiredLocked(add uint64) bool {
	return s.ike != nil && byteLifetimeWouldExpire(s.ikeSAOutboundBytes, add, s.ikeSAByteExpiresAt)
}

func (s *Session) expireIKESAIfNeeded(action string) error {
	s.mu.RLock()
	expired := s.ikeSAExpiredLocked(time.Now()) || s.ikeSAByteExpiredLocked(0)
	s.mu.RUnlock()
	if !expired {
		return nil
	}
	s.failSecurityAssociations(errIKESAExpired)
	return fmt.Errorf("%s: %w", action, errIKESAExpired)
}

func (s *Session) addIKESAOutboundBytes(protectedBytes uint64, now time.Time) bool {
	if protectedBytes == 0 {
		return false
	}
	rekeyNow := false
	s.mu.Lock()
	if s.ike == nil {
		s.mu.Unlock()
		return false
	}
	s.ikeSAOutboundBytes = addByteCount(s.ikeSAOutboundBytes, protectedBytes)
	if s.ikeSAByteRekeyAt != 0 && s.ikeSAOutboundBytes >= s.ikeSAByteRekeyAt && (s.ikeSARekeyAt.IsZero() || now.Before(s.ikeSARekeyAt)) {
		s.ikeSARekeyAt = now
		rekeyNow = true
	}
	expired := s.ikeSAByteExpiresAt != 0 && s.ikeSAOutboundBytes >= s.ikeSAByteExpiresAt
	s.mu.Unlock()
	if rekeyNow {
		s.notifyRekeyStateChanged()
	}
	return expired
}

type ikeAcceptResult struct {
	accepted bool
	expired  bool
}

func (s *Session) acceptIKESAInboundBytes(protectedBytes uint64, now time.Time) ikeAcceptResult {
	if protectedBytes == 0 {
		return ikeAcceptResult{accepted: true}
	}
	rekeyNow := false
	s.mu.Lock()
	if s.ike == nil {
		s.mu.Unlock()
		return ikeAcceptResult{}
	}
	if byteLifetimeWouldExpire(s.ikeSAInboundBytes, protectedBytes, s.ikeSAByteExpiresAt) {
		s.mu.Unlock()
		return ikeAcceptResult{expired: true}
	}
	s.ikeSAInboundBytes = addByteCount(s.ikeSAInboundBytes, protectedBytes)
	if s.ikeSAByteRekeyAt != 0 && s.ikeSAInboundBytes >= s.ikeSAByteRekeyAt && (s.ikeSARekeyAt.IsZero() || now.Before(s.ikeSARekeyAt)) {
		s.ikeSARekeyAt = now
		rekeyNow = true
	}
	result := ikeAcceptResult{
		accepted: true,
		expired:  s.ikeSAByteExpiresAt != 0 && s.ikeSAInboundBytes >= s.ikeSAByteExpiresAt,
	}
	s.mu.Unlock()
	if rekeyNow {
		s.notifyRekeyStateChanged()
	}
	return result
}

func (s *Session) childSAExpiredLocked(now time.Time) bool {
	return s.connected && !s.childSAExpiresAt.IsZero() && !now.Before(s.childSAExpiresAt)
}

func (s *Session) childSAByteExpiredLocked(add uint64) bool {
	return s.connected && byteLifetimeWouldExpire(s.childSAOutboundBytes, add, s.childSAByteExpiresAt)
}

func (s *Session) expireChildSAIfNeeded(action string) error {
	s.mu.RLock()
	expired := s.childSAExpiredLocked(time.Now())
	s.mu.RUnlock()
	if !expired {
		return nil
	}
	s.discardChildSecurityAssociations(errChildSAExpired)
	return fmt.Errorf("%s: %w", action, errChildSAExpired)
}

func (s *Session) addCurrentChildSAOutboundBytes(protectedBytes uint64, now time.Time) bool {
	if protectedBytes == 0 {
		return false
	}
	rekeyNow := false
	s.mu.Lock()
	if !s.connected {
		s.mu.Unlock()
		return false
	}
	s.childSAOutboundBytes = addByteCount(s.childSAOutboundBytes, protectedBytes)
	if s.childSAByteRekeyAt != 0 && s.childSAOutboundBytes >= s.childSAByteRekeyAt && (s.childSARekeyAt.IsZero() || now.Before(s.childSARekeyAt)) {
		s.childSARekeyAt = now
		rekeyNow = true
	}
	expired := s.childSAByteExpiresAt != 0 && s.childSAOutboundBytes >= s.childSAByteExpiresAt
	s.mu.Unlock()
	if rekeyNow {
		s.notifyRekeyStateChanged()
	}
	return expired
}

func closeDataPlaneDone(ch chan struct{}) {
	if ch == nil {
		return
	}
	close(ch)
}

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
	s.pruneRetiredChildSAsLocked(now)
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

func (s *Session) LocalAddr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.connected && s.innerLocal != nil {
		return cloneUDPAddr(s.innerLocal)
	}
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

func (s *Session) RemoteAddr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.connected && s.innerRemote != nil {
		return cloneUDPAddr(s.innerRemote)
	}
	return cloneUDPAddr(s.outerRemote)
}

func (s *Session) Tunnel() Info {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Info{
		InnerIP:                   append(net.IP(nil), s.tunnel.InnerIP...),
		PCSCFIP:                   append(net.IP(nil), s.tunnel.PCSCFIP...),
		PCSCFIPs:                  cloneIPList(s.tunnel.PCSCFIPs),
		ESPInitiatorSPI:           s.tunnel.ESPInitiatorSPI,
		ESPResponderSPI:           s.tunnel.ESPResponderSPI,
		Encryption:                s.tunnel.Encryption,
		EncryptionKeyLen:          s.tunnel.EncryptionKeyLen,
		Integrity:                 s.tunnel.Integrity,
		InitiatorTrafficSelectors: cloneTrafficSelectors(s.tunnel.InitiatorTrafficSelectors),
		ResponderTrafficSelectors: cloneTrafficSelectors(s.tunnel.ResponderTrafficSelectors),
		PDUSessionID:              s.tunnel.PDUSessionID,
		SNSSAI:                    append([]byte(nil), s.tunnel.SNSSAI...),
		SNSSAIPlmnID:              append([]byte(nil), s.tunnel.SNSSAIPlmnID...),
	}
}

func (s *Session) Info() Info {
	return s.Tunnel()
}

func (s *Session) Logger() *slog.Logger {
	return s.logger
}
