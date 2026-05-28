package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/damonto/ims-client/swu/esp"
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
	s.tunnelErr = nil
	s.initiatorSPI = state.initiatorSPI
	s.responderSPI = state.responderSPI
	s.nextMessageID = state.established.NextMessageID
	s.deviceIdentity = state.established.DeviceIdentity
	s.espSeq = 0
	s.inboundReplay.Reset()
	s.lastProtectedRx = time.Now()
	s.lastProtectedTx = time.Now()
	s.livenessTimeout = state.established.LivenessTimeout
	s.natKeepaliveInterval = s.cfg.NATKeepaliveInterval
	s.informWaiters = make(map[uint32]chan inboundIKE)
	s.informResponses = make(map[uint32][]byte)
	s.outboundESP = state.outboundESPCodec()
	s.inboundESP = state.inboundESPCodec()
	s.dataPlaneDone = make(chan struct{})
	s.mu.Unlock()
}

func (s *Session) startBackgroundLoops() {
	s.wg.Add(3)
	go s.readLoop()
	go s.livenessLoop()
	go s.natKeepaliveLoop()
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
	return s.conn == nil || (s.closeCtx != nil && s.closeCtx.Err() != nil)
}

func (s *Session) discardSecurityAssociations(cause error) {
	s.clearInformationalWaiters()
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
	s.ike = nil
	s.tunnelErr = nil
	s.initiatorSPI = 0
	s.responderSPI = 0
	s.deviceIdentity = ""
	s.nextMessageID = 0
	s.lastProtectedRx = time.Time{}
	s.lastProtectedTx = time.Time{}
	s.livenessTimeout = 0
	s.natKeepaliveInterval = 0
	s.informResponses = nil
	s.mu.Unlock()

	s.notifyDetachedAttachments(s.detachAllAttachments(), cause)
}

var errChildSAUnavailable = errors.New("child sa is unavailable")

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
		InnerIP:          append(net.IP(nil), s.tunnel.InnerIP...),
		PCSCFIP:          append(net.IP(nil), s.tunnel.PCSCFIP...),
		ESPInitiatorSPI:  s.tunnel.ESPInitiatorSPI,
		ESPResponderSPI:  s.tunnel.ESPResponderSPI,
		Encryption:       s.tunnel.Encryption,
		EncryptionKeyLen: s.tunnel.EncryptionKeyLen,
		Integrity:        s.tunnel.Integrity,
	}
}

func (s *Session) Info() Info {
	return s.Tunnel()
}

func (s *Session) Logger() *slog.Logger {
	return s.logger
}
