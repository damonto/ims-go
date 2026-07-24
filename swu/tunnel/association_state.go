package tunnel

import (
	"errors"
	"time"

	"github.com/damonto/ims-go/ipsec/esp"
)

var (
	errChildSAUnavailable = errors.New("child sa is unavailable")
	errChildSAExpired     = errors.New("child sa lifetime expired")
)

type tunnelConnection struct {
	connected            bool
	connecting           bool
	tunnel               Info
	tunnelErr            error
	livenessTimeout      time.Duration
	natKeepaliveInterval time.Duration
}

type ikeSAState uint8

const (
	ikeSAStateNone ikeSAState = iota
	ikeSAStateActive
	ikeSAStateRekeying
	ikeSAStatePendingInstall
)

type childSAState uint8

const (
	childSAStateNone childSAState = iota
	childSAStateActive
	childSAStateRekeying
	childSAStatePendingOutbound
)

func (s *Session) discardSecurityAssociations(cause error) {
	if cause == nil {
		cause = errSessionClosed
	}
	s.abortInformationalWaiters(cause)
	s.mu.Lock()
	s.connected = false
	s.connecting = false
	s.useNATT = false
	s.ikeFragmentationSupported = false
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
	s.ikeFragments = nil
	s.mu.Unlock()

	s.notifyDetachedAttachments(s.detachAllAttachments(), cause)
}

func (s *Session) discardChildSecurityAssociations(cause error) {
	if cause == nil {
		cause = errChildSAUnavailable
	}
	s.mu.Lock()
	s.connected = false
	s.connecting = false
	s.useNATT = false
	s.ikeFragmentationSupported = false
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
	s.ikeFragments = nil
	s.mu.Unlock()

	s.notifyDetachedAttachments(s.detachAllAttachments(), cause)
}

func (s *Session) failSecurityAssociations(cause error) {
	s.discardSecurityAssociations(cause)
	s.closeSession()
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

func (s *Session) disconnectedTunnelErr() error {
	if s.connected || s.ike == nil {
		return nil
	}
	if s.tunnelErr != nil {
		return s.tunnelErr
	}
	return errChildSAUnavailable
}

func (s *Session) currentDisconnectedTunnelErr() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.disconnectedTunnelErr()
}

func (s *Session) ikeSAState() ikeSAState {
	if s.ike == nil {
		return ikeSAStateNone
	}
	if s.pendingIKESAReady {
		return ikeSAStatePendingInstall
	}
	if s.ikeSARekeying {
		return ikeSAStateRekeying
	}
	return ikeSAStateActive
}

func (s *Session) childSAState() childSAState {
	if !s.connected {
		return childSAStateNone
	}
	if s.pendingChildSA.ready {
		return childSAStatePendingOutbound
	}
	if s.childSARekeying {
		return childSAStateRekeying
	}
	return childSAStateActive
}
