package tunnel

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"

	"github.com/damonto/ims-go/swu/handshake"
	"github.com/damonto/ims-go/swu/ike"
)

func (state *connectState) buildIKESAInitRequest(outerLocal, outerRemote *net.UDPAddr) ([]byte, error) {
	payloads := defaultIKESAInitPayloads(state.input.Config, state.crypto, outerLocal, outerRemote)
	if len(state.ikeInitCookie) != 0 {
		payloads = append([]ike.Payload{
			&ike.NotifyPayload{
				NotifyType: notifyTypeCookie,
				Data:       append([]byte(nil), state.ikeInitCookie...),
			},
		}, payloads...)
	}
	header := ike.IKEHeader{
		InitiatorSPI: state.initiatorSPI,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeIKESAInit,
		Flags:        flagInitiator,
		MessageID:    0,
	}
	request, err := (ike.IKEPacket{Header: header, Payloads: payloads}).MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("building ike_sa_init request: %w", err)
	}
	return request, nil
}

func decodeIKESAInitPacket(raw []byte) (ike.IKEPacket, error) {
	var packet ike.IKEPacket
	if err := packet.UnmarshalBinary(raw); err != nil {
		return ike.IKEPacket{}, fmt.Errorf("parsing ike_sa_init response: %w", err)
	}
	return packet, nil
}

func (state *connectState) applyIKESAInitResponse(response ike.IKEPacket, request, responseRaw []byte, outerLocal, outerRemote *net.UDPAddr) error {
	if response.Header.ResponderSPI == 0 {
		return errors.New("responder spi is empty")
	}
	requestProposals := ikeSAProposals(state.input.Config)
	proposal, responderNonce, responderKE, err := negotiatedIKESAFromPayloads(response.Payloads, state.crypto.dhGroup, requestProposals)
	if err != nil {
		return err
	}
	nattSupported, natDetected, err := ikeSAInitNATDetection(response.Payloads, response.Header.InitiatorSPI, response.Header.ResponderSPI, outerLocal, outerRemote)
	if err != nil {
		return err
	}
	state.crypto.SetProposal(proposal.Encryption, proposal.EncryptionKeyLen, proposal.Integrity, proposal.PRF)
	state.crypto.SetSPIs(state.initiatorSPI, response.Header.ResponderSPI)
	state.crypto.SetNonces(state.nonceI, responderNonce)
	if err := state.crypto.DeriveIKEKeys(responderKE); err != nil {
		return fmt.Errorf("deriving ike keys: %w", err)
	}
	state.responderSPI = response.Header.ResponderSPI
	state.ikeInitRequest = append([]byte(nil), request...)
	state.ikeInitResponse = append([]byte(nil), responseRaw...)
	state.responderNonce = append([]byte(nil), responderNonce...)
	state.nattSupported = nattSupported
	state.natDetected = natDetected
	state.useNATT = natDetected || outerRemote.Port == state.input.Config.NATTPort
	state.ikeFragmentationSupported = hasNotifyPayload(response.Payloads, notifyTypeIKEV2FragmentationSupported)
	state.saInit.InitiatorSPI = state.initiatorSPI
	state.saInit.ResponderSPI = state.responderSPI
	state.saInit.NonceI = append([]byte(nil), state.nonceI...)
	state.saInit.ResponderNonce = append([]byte(nil), responderNonce...)
	state.saInit.IKEInitRequest = append([]byte(nil), request...)
	state.saInit.ChildInitiatorSPI = state.espInitiatorSPI
	return nil
}

func (s *Session) exchangeIKESAInit(ctx context.Context, state *connectState) error {
	triedGroups := map[uint16]struct{}{state.crypto.dhGroup: {}}
	cookieRetries := 0
	for {
		outerLocal, err := resolveOuterLocalAddr(s.conn, s.outerRemote)
		if err != nil {
			s.logger.Debug("resolving local outer address failed", "err", err)
		}
		state.input.OuterLocal = cloneUDPAddr(outerLocal)
		request, err := state.buildIKESAInitRequest(outerLocal, s.outerRemote)
		if err != nil {
			return err
		}
		responseRaw, _, err := s.exchangeIKE(ctx, s.outerRemote, request, s.outerRemote.Port == s.cfg.NATTPort, 0)
		if err != nil {
			if errors.Is(err, handshake.ErrIKETimeout) {
				return fmt.Errorf("%w: %w", ErrIKESAInitNoResponse, err)
			}
			return err
		}
		response, err := decodeIKESAInitPacket(responseRaw)
		if err != nil {
			return err
		}
		cookie, retryCookie, err := cookiePayloadData(response.Payloads)
		if err != nil {
			return err
		}
		if retryCookie {
			cookieRetries++
			if cookieRetries > maxIKESAInitCookieRetries {
				return errors.New("parsing ike_sa_init response: too many COOKIE retries")
			}
			s.logger.Info("retrying IKE_SA_INIT with COOKIE", "attempt", cookieRetries)
			state.ikeInitCookie = cookie
			continue
		}
		group, retry, err := invalidKEPayloadGroup(response.Payloads)
		if err != nil {
			return err
		}
		if err := ikeSAInitNotifyError(response.Payloads); err != nil {
			return err
		}
		if !retry {
			return state.applyIKESAInitResponse(response, request, responseRaw, outerLocal, s.outerRemote)
		}
		if _, ok := triedGroups[group]; ok {
			return fmt.Errorf("parsing ike_sa_init response: repeated INVALID_KE_PAYLOAD group %d", group)
		}
		if !slices.Contains(state.input.Config.DHGroups, group) {
			return fmt.Errorf("parsing ike_sa_init response: invalid ke dh group %d was not requested", group)
		}
		s.logger.Info("retrying IKE_SA_INIT with responder DH group", "dh_group", group)
		if err := state.resetDHGroup(group); err != nil {
			return fmt.Errorf("updating ike_sa_init dh group: %w", err)
		}
		triedGroups[group] = struct{}{}
	}
}

type negotiatedIKESA struct {
	Encryption       uint16
	EncryptionKeyLen uint16
	Integrity        uint16
	PRF              uint16
}

func negotiatedIKESAFromPayloads(payloads []ike.Payload, dhGroup uint16, requestProposals []ike.Proposal) (negotiatedIKESA, []byte, []byte, error) {
	nonce := ike.FindNoncePayload(payloads)
	sa := ike.FindSAPayload(payloads)
	ke := ike.FindKEPayload(payloads, dhGroup)
	if nonce == nil || sa == nil || ke == nil {
		return negotiatedIKESA{}, nil, nil, errors.New("parsing ike_sa_init response: required payload is missing")
	}
	if err := validateNonceData(nonce.Data); err != nil {
		return negotiatedIKESA{}, nil, nil, fmt.Errorf("parsing ike_sa_init response: %w", err)
	}
	if len(sa.Proposals) != 1 {
		return negotiatedIKESA{}, nil, nil, fmt.Errorf("parsing ike_sa_init response: negotiated proposal count %d", len(sa.Proposals))
	}
	if len(sa.Proposals[0].SPI) != 0 {
		return negotiatedIKESA{}, nil, nil, fmt.Errorf("parsing ike_sa_init response: invalid negotiated ike spi length %d", len(sa.Proposals[0].SPI))
	}
	if err := validateNegotiatedProposalFromRequests(sa.Proposals[0], requestProposals); err != nil {
		return negotiatedIKESA{}, nil, nil, fmt.Errorf("parsing ike_sa_init response: %w", err)
	}
	proposal, err := negotiatedIKESAFromProposal(sa.Proposals[0], dhGroup)
	if err != nil {
		return negotiatedIKESA{}, nil, nil, err
	}
	return proposal, nonce.Data, ke.Data, nil
}

func invalidKEPayloadGroup(payloads []ike.Payload) (uint16, bool, error) {
	group, retry, err := invalidKEPayloadGroupFor(payloads)
	if err != nil {
		return 0, false, fmt.Errorf("parsing ike_sa_init response: %w", err)
	}
	return group, retry, nil
}

func invalidKEPayloadGroupFor(payloads []ike.Payload) (uint16, bool, error) {
	notify := ike.FindNotifyPayload(payloads, notifyTypeInvalidKEPayload)
	if notify == nil {
		return 0, false, nil
	}
	if len(notify.Data) != 2 {
		return 0, false, fmt.Errorf("invalid INVALID_KE_PAYLOAD length %d", len(notify.Data))
	}
	return binary.BigEndian.Uint16(notify.Data), true, nil
}

func cookiePayloadData(payloads []ike.Payload) ([]byte, bool, error) {
	notify := ike.FindNotifyPayload(payloads, notifyTypeCookie)
	if notify == nil {
		return nil, false, nil
	}
	if len(notify.SPI) != 0 {
		return nil, false, fmt.Errorf("parsing ike_sa_init response: invalid COOKIE spi length %d", len(notify.SPI))
	}
	if len(notify.Data) == 0 || len(notify.Data) > maxCookieNotifyDataLength {
		return nil, false, fmt.Errorf("parsing ike_sa_init response: invalid COOKIE length %d", len(notify.Data))
	}
	return append([]byte(nil), notify.Data...), true, nil
}

func ikeSAInitNotifyError(payloads []ike.Payload) error {
	for _, payload := range payloads {
		notify, ok := payload.(*ike.NotifyPayload)
		if !ok || notify.NotifyType >= notifyTypeStatusMin || notify.NotifyType == notifyTypeInvalidKEPayload {
			continue
		}
		return fmt.Errorf("parsing ike_sa_init response: received %s (%d)", ikeNotifyName(notify.NotifyType), notify.NotifyType)
	}
	return nil
}

func ikeSAInitNATDetection(payloads []ike.Payload, initiatorSPI, responderSPI uint64, local, remote *net.UDPAddr) (bool, bool, error) {
	natSources, natDest, err := ikeSAInitNATDetectionPayloads(payloads)
	if err != nil {
		return false, false, err
	}
	if len(natSources) == 0 && natDest == nil {
		return false, false, nil
	}
	if len(natSources) == 0 || natDest == nil {
		return false, false, errors.New("parsing ike_sa_init response: missing source or destination NAT detection notification")
	}
	for _, source := range natSources {
		if len(source.Data) != sha1.Size {
			return false, false, fmt.Errorf("parsing ike_sa_init response: invalid NAT_DETECTION_SOURCE_IP length %d", len(source.Data))
		}
	}
	if len(natDest.Data) != sha1.Size {
		return false, false, fmt.Errorf("parsing ike_sa_init response: invalid NAT_DETECTION_DESTINATION_IP length %d", len(natDest.Data))
	}
	expectedLocal := natDetectionHash(initiatorSPI, responderSPI, local)
	localNATDetected := !slices.Equal(expectedLocal[:], natDest.Data)
	expectedRemote := natDetectionHash(initiatorSPI, responderSPI, remote)
	remoteNATDetected := true
	for _, source := range natSources {
		if slices.Equal(expectedRemote[:], source.Data) {
			remoteNATDetected = false
			break
		}
	}
	return true, localNATDetected || remoteNATDetected, nil
}

func ikeSAInitNATDetectionPayloads(payloads []ike.Payload) ([]*ike.NotifyPayload, *ike.NotifyPayload, error) {
	var natSources []*ike.NotifyPayload
	var natDest *ike.NotifyPayload
	for _, payload := range payloads {
		notify, ok := payload.(*ike.NotifyPayload)
		if !ok {
			continue
		}
		switch notify.NotifyType {
		case notifyTypeNATDetectionSourceIP:
			natSources = append(natSources, notify)
		case notifyTypeNATDetectionDestIP:
			if natDest != nil {
				return nil, nil, errors.New("parsing ike_sa_init response: multiple NAT_DETECTION_DESTINATION_IP notifications")
			}
			natDest = notify
		}
	}
	return natSources, natDest, nil
}

func negotiatedIKESAFromProposal(proposal ike.Proposal, dhGroup uint16) (negotiatedIKESA, error) {
	if proposal.ProtocolID != proposalProtocolIKE {
		return negotiatedIKESA{}, fmt.Errorf("parsing negotiated ike proposal: invalid protocol id %d", proposal.ProtocolID)
	}
	parsed := negotiatedIKESA{}
	negotiatedDH := uint16(0)
	for _, transform := range proposal.Transforms {
		switch transform.TransformType {
		case transformTypeENCR:
			if parsed.Encryption != 0 {
				return negotiatedIKESA{}, errors.New("parsing negotiated ike proposal: duplicate encryption transform")
			}
			if !supportedEncryptionTransform(transform.ID) {
				return negotiatedIKESA{}, fmt.Errorf("parsing negotiated ike proposal: unsupported encryption transform %d", transform.ID)
			}
			parsed.Encryption = transform.ID
			for _, attr := range transform.Attributes {
				if attr.Type == transformAttrKeyLength {
					if value, ok := attr.Uint16(); ok {
						parsed.EncryptionKeyLen = value
					}
				}
			}
		case transformTypeINTEG:
			if parsed.Integrity != 0 {
				return negotiatedIKESA{}, errors.New("parsing negotiated ike proposal: duplicate integrity transform")
			}
			parsed.Integrity = transform.ID
		case transformTypePRF:
			if parsed.PRF != 0 {
				return negotiatedIKESA{}, errors.New("parsing negotiated ike proposal: duplicate prf transform")
			}
			parsed.PRF = transform.ID
		case transformTypeDH:
			if negotiatedDH != 0 {
				return negotiatedIKESA{}, errors.New("parsing negotiated ike proposal: duplicate dh transform")
			}
			negotiatedDH = transform.ID
		default:
			return negotiatedIKESA{}, fmt.Errorf("parsing negotiated ike proposal: unsupported transform type %d", transform.TransformType)
		}
	}
	if parsed.Encryption == 0 || parsed.EncryptionKeyLen == 0 || parsed.Integrity == 0 || parsed.PRF == 0 {
		return negotiatedIKESA{}, errors.New("parsing negotiated ike proposal: transform is incomplete")
	}
	if negotiatedDH != dhGroup {
		return negotiatedIKESA{}, fmt.Errorf("parsing negotiated ike proposal: dh group %d does not match ke group %d", negotiatedDH, dhGroup)
	}
	return parsed, nil
}

func ikeSAProposals(cfg handshake.Config) []ike.Proposal {
	encryption := encryptionTransforms(
		uint16ValuesOrDefault(cfg.IKEEncryption, defaultEncryption),
		uint16ValuesOrDefault(cfg.IKEEncryptionKeyLens, defaultEncryptionKeyLens),
		uint16ValuesOrDefault(cfg.IKEEncryptionAESCTRKeyLens, defaultEncryptionKeyLens),
	)
	integrity := uint16ValuesOrDefault(cfg.IKEIntegrity, defaultIKEIntegrity)
	prfs := uint16ValuesOrDefault(cfg.IKEPRF, defaultIKEPRF)
	dhGroups := uint16ValuesOrDefault(cfg.DHGroups, defaultDHGroups)
	transforms := make([]ike.Transform, 0, len(encryption)+len(integrity)+len(prfs)+len(dhGroups))
	transforms = append(transforms, encryption...)
	for _, integ := range integrity {
		transforms = append(transforms, ike.Transform{TransformType: transformTypeINTEG, ID: integ})
	}
	for _, prf := range prfs {
		transforms = append(transforms, ike.Transform{TransformType: transformTypePRF, ID: prf})
	}
	for _, dhGroup := range dhGroups {
		transforms = append(transforms, ike.Transform{TransformType: transformTypeDH, ID: dhGroup})
	}
	return []ike.Proposal{
		{
			Number:     1,
			ProtocolID: proposalProtocolIKE,
			Transforms: transforms,
		},
	}
}

func defaultIKESAInitPayloads(cfg handshake.Config, crypto *ikeCrypto, local, remote *net.UDPAddr) []ike.Payload {
	proposals := ikeSAProposals(cfg)
	natSourceHash := natDetectionHash(crypto.initiatorSPI, crypto.responderSPI, local)
	natDestHash := natDetectionHash(crypto.initiatorSPI, crypto.responderSPI, remote)
	return []ike.Payload{
		&ike.SecurityAssociationPayload{Proposals: proposals},
		&ike.KeyExchangePayload{DHGroup: crypto.dhGroup, Data: crypto.PublicKey()},
		&ike.NoncePayload{Data: append([]byte(nil), crypto.nonceI...)},
		&ike.NotifyPayload{ProtocolID: protocolIDUnset, NotifyType: notifyTypeNATDetectionSourceIP, Data: natSourceHash[:]},
		&ike.NotifyPayload{ProtocolID: protocolIDUnset, NotifyType: notifyTypeNATDetectionDestIP, Data: natDestHash[:]},
		&ike.NotifyPayload{ProtocolID: protocolIDUnset, NotifyType: notifyTypeIKEV2FragmentationSupported},
	}
}

func resolveOuterLocalAddr(conn net.PacketConn, remote *net.UDPAddr) (*net.UDPAddr, error) {
	if conn == nil {
		return nil, errors.New("resolving outer local addr: conn is nil")
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("resolving outer local addr: local addr has type %T", conn.LocalAddr())
	}
	resolved := cloneUDPAddr(local)
	if resolved != nil && resolved.IP != nil && !resolved.IP.IsUnspecified() {
		return resolved, nil
	}
	if remote == nil {
		return resolved, nil
	}
	discovered, err := discoverOutboundIP(remote)
	if err != nil {
		return resolved, fmt.Errorf("resolving outer local addr: discovering outbound ip: %w", err)
	}
	if len(discovered) == 0 {
		return resolved, nil
	}
	resolved.IP = discovered
	return resolved, nil
}

func discoverOutboundIP(remote *net.UDPAddr) (net.IP, error) {
	if remote == nil {
		return nil, nil
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil {
		return nil, nil
	}
	return append(net.IP(nil), local.IP...), nil
}

func natDetectionHash(initiatorSPI, responderSPI uint64, addr *net.UDPAddr) [sha1.Size]byte {
	seed := make([]byte, ikeSPISeedLength)
	binary.BigEndian.PutUint64(seed[0:8], initiatorSPI)
	binary.BigEndian.PutUint64(seed[8:16], responderSPI)
	if addr != nil {
		ip := addr.IP
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		} else {
			ip = ip.To16()
		}
		if len(ip) != 0 {
			seed = append(seed, ip...)
			seed = append(seed, byte(addr.Port>>8), byte(addr.Port))
		}
	}
	return sha1.Sum(seed)
}
