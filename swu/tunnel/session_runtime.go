package tunnel

import (
	"context"
	"errors"
	"net"
	"time"
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
	s.useNATT = state.useNATT
	s.ikeFragmentationSupported = state.ikeFragmentationSupported
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
	if state.useNATT {
		s.natKeepaliveInterval = s.cfg.NATKeepaliveInterval
	} else {
		s.natKeepaliveInterval = 0
	}
	s.informWaiters = make(map[ikeMessageKey]chan inboundIKE)
	s.informResponses = make(map[uint32][][]byte)
	s.informResponseReqs = make(map[uint32][]byte)
	s.ikeFragments = make(map[ikeMessageKey]*ikeFragmentReassembly)
	s.outboundESP = state.outboundESPCodec()
	s.inboundESP = state.inboundESPCodec()
	s.retiredChildSAs = nil
	s.pendingChildSA = pendingChildSA{}
	s.dataPlaneDone = make(chan struct{})
	s.mu.Unlock()
}

func (s *Session) startBackgroundLoops() {
	s.startBackgroundLoop(s.readLoop)
	s.startBackgroundLoop(s.livenessLoop)
	s.startBackgroundLoop(s.natKeepaliveLoop)
	s.startBackgroundLoop(s.ikeSARekeyLoop)
	s.startBackgroundLoop(s.childSARekeyLoop)
}

func (s *Session) startBackgroundLoop(run func()) {
	s.wg.Add(1)
	go run()
}

func (s *Session) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultCloseTimeout)
	defer cancel()
	_ = s.sendDeleteRequest(ctx)
	s.closeSession()
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
	select {
	case <-s.closeCh:
		return true
	default:
		return false
	}
}

func (s *Session) closeSession() {
	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
}
