package voice

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/damonto/vowifi-go/ims/sip"
)

type outgoingInvite struct {
	target          string
	callID          string
	sessionID       string
	localTag        string
	localURI        string
	inviteSeq       int64
	localPort       int
	offer           []byte
	media           NegotiatedMedia
	invite          sip.Message
	currentLocation bool
}

func (s *Service) newOutgoingInvite(req DialRequest) (outgoingInvite, error) {
	target, err := s.initialInviteTarget(req)
	if err != nil {
		return outgoingInvite{}, err
	}

	localPort := s.reserveRTPPort()
	offer, media, err := buildSDPOffer(s.cfg, s.localIP(), localPort, req.Media)
	if err != nil {
		return outgoingInvite{}, err
	}

	callID, sessionID, tag, branch := sip.NewTransaction()
	state := s.reg.State()
	localURI := preferredIdentity(state)
	pidfURI := pidfEntityURI(s.cfg, state)
	includePIDF := includePIDFForInvite(s.cfg, req)
	includeCurrentLocation := includeCurrentLocationDiscoveryForInvite(s.cfg, req)
	inviteSeq := atomic.AddInt64(&s.cseq, 1)

	invite := sip.NewRequest("INVITE", target)
	invite.Headers.Add("Via", sip.BuildVia(sip.TransportToken(s.sess.LocalAddr()), state.ContactHost, state.MessagePort, branch))
	invite.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", localURI, tag))
	invite.Headers.Add("To", fmt.Sprintf("<%s>", target))
	invite.Headers.Add("Call-ID", callID)
	invite.Headers.Add("Session-ID", sessionID)
	invite.Headers.Add("CSeq", fmt.Sprintf("%d INVITE", inviteSeq))
	invite.Headers.Add("Accept-Contact", fmt.Sprintf(`*;+g.3gpp.icsi-ref="%s"`, mmtelICSIEncoded))
	invite.Headers.Add("P-Preferred-Service", mmtelICSI)
	invite.Headers.Add("P-Preferred-Identity", fmt.Sprintf("<%s>", localURI))
	invite.Headers.Add("P-Early-Media", "supported")
	invite.Headers.Add("Contact", contactValue(state))
	if includeCurrentLocation {
		invite.Headers.Add("Recv-Info", currentLocationDiscoveryInfoPackage)
	}
	invite.Headers.Add("Accept", callAcceptHeader(includePIDF, includeCurrentLocation))
	s.reg.RequestPolicy().Apply(&invite)
	addInviteFeatureTags(&invite, s.cfg)
	addInviteSessionTimer(&invite, s.cfg)
	if err := setInviteBody(&invite, s.cfg, pidfURI, includePIDF, offer); err != nil {
		return outgoingInvite{}, err
	}

	return outgoingInvite{
		target:          target,
		callID:          callID,
		sessionID:       sessionID,
		localTag:        tag,
		localURI:        localURI,
		inviteSeq:       inviteSeq,
		localPort:       localPort,
		offer:           offer,
		media:           media,
		invite:          invite,
		currentLocation: includeCurrentLocation,
	}, nil
}

func (s *Service) newOutgoingCall(req DialRequest, invite outgoingInvite) *Call {
	return &Call{
		service:         s,
		id:              invite.callID,
		sessionID:       invite.sessionID,
		direction:       CallDirectionOutgoing,
		state:           CallStateDialing,
		localURI:        invite.localURI,
		localTag:        invite.localTag,
		remoteURI:       invite.target,
		remoteTo:        fmt.Sprintf("<%s>", invite.target),
		targetURI:       invite.target,
		inviteSeq:       invite.inviteSeq,
		localCSeq:       invite.inviteSeq,
		inviteRequest:   invite.invite,
		localSDP:        append([]byte(nil), invite.offer...),
		localPort:       invite.localPort,
		media:           invite.media,
		earlyDialogs:    make(map[string]earlyDialog),
		rtcpSSRC:        randomRTCPSSRC(),
		emergency:       req.Emergency,
		currentLocation: invite.currentLocation,
	}
}

func (s *Service) initialInviteTarget(req DialRequest) (string, error) {
	if !req.Emergency {
		target := s.targetURI(req.To)
		if target == "" {
			return "", errors.New("dialing call: target is empty")
		}
		return target, nil
	}

	target := strings.TrimSpace(req.EmergencyURN)
	if target == "" && isEmergencyServiceURN(req.To) {
		target = strings.TrimSpace(req.To)
	}
	if target == "" {
		target = emergencyServiceURNSOS
	}
	if !isEmergencyServiceURN(target) {
		return "", fmt.Errorf("dialing emergency call: invalid service urn %q", target)
	}
	return target, nil
}
