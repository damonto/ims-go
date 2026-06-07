package tunnel

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/damonto/uicc-go/usim"
	"github.com/damonto/vowifi-go/eapaka"
)

func akaPrimeNetworkNamesMatch(peerNetworkName, serverNetworkName string) bool {
	if peerNetworkName == "" || serverNetworkName == "" {
		return true
	}
	peerFields := strings.Split(peerNetworkName, ":")
	serverFields := strings.Split(serverNetworkName, ":")
	for i := range min(len(peerFields), len(serverFields)) {
		if peerFields[i] != serverFields[i] {
			return false
		}
	}
	return true
}

func akaPrimeKDFValues(attrs []eapaka.AKAAttribute) ([]uint16, error) {
	values := make([]uint16, 0, 1)
	for _, attr := range attrs {
		if attr.Type != akaAttrKDF {
			continue
		}
		kdf, err := eapaka.KDFFromAttribute(&attr)
		if err != nil {
			return nil, err
		}
		values = append(values, kdf.Version)
	}
	return values, nil
}

func uint16sContain(values []uint16, value uint16) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func uint16sHaveDuplicate(values []uint16) bool {
	seen := make(map[uint16]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func uint16sEqual(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sanitizedAKAPrimeChallengeData(message eapaka.AKAMessage) ([]byte, bool, error) {
	if message.EAPType != eapTypeAKAPrime || message.Subtype != akaSubtypeChallenge {
		return nil, false, nil
	}
	seenKDF := false
	attrs := make([]eapaka.AKAAttribute, 0, len(message.Attributes))
	for _, attr := range message.Attributes {
		if attr.Type == akaAttrKDF {
			if seenKDF {
				continue
			}
			seenKDF = true
		}
		attrs = append(attrs, attr)
	}
	if !seenKDF {
		return nil, false, nil
	}
	message.Attributes = attrs
	data, err := message.MarshalBinary()
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func (f *akaAuthFlow) validateAKAPrimeNetworkName(serverNetworkName []byte) bool {
	server := string(serverNetworkName)
	if akaPrimeNetworkNamesMatch(f.akaPrimeNetworkName, server) {
		return true
	}
	if f.allowAKAPrimeNetworkNameMismatch {
		f.logger().Warn("AKA' network name mismatch", "peer_network_name", f.akaPrimeNetworkName, "server_network_name", server)
		return true
	}
	return false
}

func (f *akaAuthFlow) akaPrimeKDFNegotiationResponse(message eapaka.AKAMessage) (akaResponse, bool, error) {
	if message.EAPType != eapTypeAKAPrime || message.Subtype != akaSubtypeChallenge {
		return akaResponse{}, false, nil
	}
	kdfs, err := akaPrimeKDFValues(message.Attributes)
	if err != nil {
		return f.buildAKAPrimeAuthenticationReject(message.Identifier)
	}
	if len(kdfs) == 0 {
		return akaResponse{}, false, nil
	}
	if len(f.akaPrimeKDFOffer) != 0 {
		want := make([]uint16, 0, len(f.akaPrimeKDFOffer)+1)
		want = append(want, akaPrimeKDFDefault)
		want = append(want, f.akaPrimeKDFOffer...)
		if !uint16sEqual(kdfs, want) {
			return f.buildAKAPrimeAuthenticationReject(message.Identifier)
		}
		return akaResponse{}, false, nil
	}
	if uint16sHaveDuplicate(kdfs) {
		return f.buildAKAPrimeAuthenticationReject(message.Identifier)
	}
	if kdfs[0] == akaPrimeKDFDefault {
		return akaResponse{}, false, nil
	}
	if !uint16sContain(kdfs[1:], akaPrimeKDFDefault) {
		return f.buildAKAPrimeAuthenticationReject(message.Identifier)
	}
	data, err := eapaka.BuildAKAPrimeKDFSelection(message.Identifier, akaPrimeKDFDefault)
	if err != nil {
		return akaResponse{}, false, fmt.Errorf("connecting swu session: building aka prime kdf selection: %w", err)
	}
	f.akaPrimeKDFOffer = append([]uint16(nil), kdfs...)
	return akaResponse{data: data}, true, nil
}

func (f *akaAuthFlow) buildAKAPrimeAuthenticationReject(identifier byte) (akaResponse, bool, error) {
	data, err := eapaka.BuildAKAPrimeAuthenticationReject(identifier)
	if err != nil {
		return akaResponse{}, false, fmt.Errorf("connecting swu session: building aka prime authentication reject: %w", err)
	}
	return akaResponse{data: data}, true, nil
}

func (f *akaAuthFlow) akaPrimeChallengeIdentity() string {
	identity := normalizeAKAIdentity(f.eapIdentity, f.realm)
	if identity != akaPermanentIdentity(f.card, f.realm, eapTypeAKA) {
		return identity
	}
	return akaPermanentIdentity(f.card, f.realm, eapTypeAKAPrime)
}

func (f *akaAuthFlow) buildChallengeResponse(ctx context.Context, message eapaka.AKAMessage, eapData []byte) (akaResponse, error) {
	if response, ok, err := f.akaPrimeKDFNegotiationResponse(message); ok || err != nil {
		return response, err
	}
	challengeData := eapData
	if data, ok, err := sanitizedAKAPrimeChallengeData(message); err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: sanitizing aka prime challenge: %w", err)
	} else if ok {
		challengeData = data
	}
	var challenge eapaka.AKAChallenge
	if err := challenge.UnmarshalBinary(challengeData); err != nil {
		if errors.Is(err, eapaka.ErrAKAPrimeAuthenticationFailure) {
			data, buildErr := eapaka.BuildAKAPrimeAuthenticationReject(message.Identifier)
			if buildErr != nil {
				return akaResponse{}, fmt.Errorf("connecting swu session: building aka prime authentication reject: %w", buildErr)
			}
			return akaResponse{data: data}, nil
		}
		return f.clientErrorResponse(message.Identifier, fmt.Errorf("parsing aka challenge: %w", err))
	}
	if message.EAPType == eapTypeAKAPrime && !f.validateAKAPrimeNetworkName(challenge.NetworkName) {
		data, err := eapaka.BuildAKAPrimeAuthenticationReject(message.Identifier)
		if err != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: building aka prime authentication reject: %w", err)
		}
		return akaResponse{data: data}, nil
	}
	if message.EAPType == eapTypeAKAPrime && !challenge.AMFSeparationBitSet() {
		data, err := eapaka.BuildAKAPrimeAuthenticationReject(message.Identifier)
		if err != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: building aka prime authentication reject: %w", err)
		}
		return akaResponse{data: data}, nil
	}
	aka, err := f.card.AKA(ctx, challenge.RAND, challenge.AUTN)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: calculating aka response: %w", err)
	}
	if aka.IsSynchronizationFailure() {
		var data []byte
		if message.EAPType == eapTypeAKAPrime {
			kdfs, parseErr := akaPrimeKDFValues(message.Attributes)
			if parseErr != nil {
				return f.clientErrorResponse(message.Identifier, fmt.Errorf("parsing aka prime kdf attributes: %w", parseErr))
			}
			data, err = eapaka.BuildAKAPrimeSynchronizationFailure(message.Identifier, aka.AUTS, kdfs)
		} else {
			data, err = eapaka.BuildAKASynchronizationFailure(message.Identifier, aka.AUTS)
		}
		if err != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: building aka synchronization failure: %w", err)
		}
		return akaResponse{data: data}, nil
	}
	if aka.IsAuthenticationReject() {
		var data []byte
		if message.EAPType == eapTypeAKAPrime {
			data, err = eapaka.BuildAKAPrimeAuthenticationReject(message.Identifier)
		} else {
			data, err = eapaka.BuildAKAAuthenticationReject(message.Identifier)
		}
		if err != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: building aka authentication reject: %w", err)
		}
		return akaResponse{data: data}, nil
	}
	if !aka.IsSuccess() {
		return f.clientErrorResponse(message.Identifier, errors.New("processing aka result: aka result is incomplete"))
	}
	f.logger().Debug(
		"calculated AKA response",
		"res_len", len(aka.RES),
		"ck_len", len(aka.CK),
		"ik_len", len(aka.IK),
		"challenge_has_result_ind", eapaka.HasAttribute(message.Attributes, akaAttrResultInd),
		"challenge_has_checkcode", eapaka.HasAttribute(message.Attributes, akaAttrCheckcode),
	)
	if message.EAPType == eapTypeAKAPrime {
		f.eapIdentity = f.akaPrimeChallengeIdentity()
		sqnXorAK := challenge.AUTN[:akaPrimeSQNXorAKLen]
		if err := f.crypto.DeriveAKAPrimeEAPKeys([]byte(f.eapIdentity), aka.RES, aka.CK, aka.IK, challenge.NetworkName, sqnXorAK); err != nil {
			return f.clientErrorResponse(message.Identifier, fmt.Errorf("deriving aka prime eap keys: %w", err))
		}
	} else if err := f.crypto.DeriveEAPKeys([]byte(f.eapIdentity), aka.RES, aka.IK, aka.CK); err != nil {
		return f.clientErrorResponse(message.Identifier, fmt.Errorf("deriving eap keys: %w", err))
	}
	if err := f.verifyMessageMAC(message.EAPType, eapData, f.crypto.eap.AUT, nil); err != nil {
		return f.clientErrorResponse(message.Identifier, fmt.Errorf("verifying aka challenge mac: %w", err))
	}
	if err := f.verifyCheckcode(message.Attributes, message.EAPType); err != nil {
		return f.clientErrorResponse(message.Identifier, fmt.Errorf("verifying aka checkcode: %w", err))
	}
	if response, ok, err := f.biddingDownRejectResponse(message); ok || err != nil {
		return response, err
	}
	nested, err := f.challengeAttributes(message)
	if err != nil {
		return f.clientErrorResponse(message.Identifier, fmt.Errorf("decrypting aka challenge attrs: %w", err))
	}
	f.pendingState = usim.AKAIdentityState{}
	if attr := eapaka.FindAttribute(nested, akaAttrNextPseudonym); attr != nil {
		f.pendingState.Pseudonym, err = eapaka.StringValue(attr)
		if err != nil {
			return f.clientErrorResponse(message.Identifier, fmt.Errorf("parsing next pseudonym: %w", err))
		}
	}
	if attr := eapaka.FindAttribute(nested, akaAttrNextReauthID); attr != nil {
		f.pendingState.ReauthIdentity, err = eapaka.StringValue(attr)
		if err != nil {
			return f.clientErrorResponse(message.Identifier, fmt.Errorf("parsing next reauth id: %w", err))
		}
		f.pendingState.Counter = 0
		f.pendingState.MK = append([]byte(nil), f.crypto.eap.MK...)
		f.pendingState.KEncr = append([]byte(nil), f.crypto.eap.ENCR...)
		f.pendingState.KAut = append([]byte(nil), f.crypto.eap.AUT...)
	}
	responseCheckcode := f.challengeResponseCheckcode(message.Attributes, message.EAPType)
	useResultInd := eapaka.HasAttribute(message.Attributes, akaAttrResultInd)
	ipmsSupport := eapaka.IPMSSupport(0)
	if useResultInd {
		ipmsSupport = eapaka.IPMSSupportNBMOnly
	}
	data, err := eapaka.BuildChallengeResponsePacketWithOptions(eapaka.ChallengeResponseOptions{
		Identifier:   message.Identifier,
		EAPType:      message.EAPType,
		RES:          aka.RES,
		AUTKey:       f.crypto.eap.AUT,
		UseResultInd: useResultInd,
		Checkcode:    responseCheckcode,
		IPMSSupport:  ipmsSupport,
	})
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building aka response: %w", err)
	}
	f.currentAuthKey = append([]byte(nil), f.crypto.eap.AUT...)
	f.currentEncrKey = append([]byte(nil), f.crypto.eap.ENCR...)
	f.currentEAPType = message.EAPType
	f.currentCounter = 0
	f.fastReauth = false
	f.ipmsIndicated = ipmsSupport != 0
	f.markAKAAuthenticated(useResultInd)
	return akaResponse{data: data}, nil
}

func (f *akaAuthFlow) challengeAttributes(message eapaka.AKAMessage) ([]eapaka.AKAAttribute, error) {
	if !eapaka.HasAttribute(message.Attributes, akaAttrIV) && !eapaka.HasAttribute(message.Attributes, akaAttrEncryptedData) {
		return nil, nil
	}
	nested, err := eapaka.DecryptAttributes(message.Attributes, f.crypto.eap.ENCR)
	if err != nil {
		return nil, err
	}
	return nested, nil
}
