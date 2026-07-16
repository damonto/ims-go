package tunnel

import (
	"errors"
	"fmt"
	"strings"

	"github.com/damonto/ims-go/eapaka"
	usim "github.com/damonto/wwan-go/sim"
)

type akaIdentityStateProvider interface {
	AKAIdentityState() usim.AKAIdentityState
}

type akaIdentityStateStore interface {
	SetAKAIdentityState(usim.AKAIdentityState)
}

const (
	mccDigitCount      = 3
	mncShortDigitCount = 2
	mncLongDigitCount  = 3
)

func cloneAKAIdentityState(state usim.AKAIdentityState) usim.AKAIdentityState {
	return usim.AKAIdentityState{
		Pseudonym:      state.Pseudonym,
		ReauthIdentity: state.ReauthIdentity,
		Counter:        state.Counter,
		MK:             append([]byte(nil), state.MK...),
		KEncr:          append([]byte(nil), state.KEncr...),
		KAut:           append([]byte(nil), state.KAut...),
	}
}

func loadAKAIdentityState(card Card) usim.AKAIdentityState {
	provider, ok := card.(akaIdentityStateProvider)
	if !ok {
		return usim.AKAIdentityState{}
	}
	return cloneAKAIdentityState(provider.AKAIdentityState())
}

func validAKAReauthState(state usim.AKAIdentityState) bool {
	return state.ReauthIdentity != "" && len(state.MK) != 0 && len(state.KAut) != 0 && len(state.KEncr) != 0
}

func normalizedAKAReauthIdentity(state usim.AKAIdentityState, realm string) (string, bool) {
	if !validAKAReauthState(state) {
		return "", false
	}
	return normalizeAKAIdentity(state.ReauthIdentity, realm), true
}

func akaPermanentIdentity(card Card, realm string, eapType byte) string {
	prefix := "0"
	if eapType == eapTypeAKAPrime {
		prefix = "6"
	}
	return normalizeAKAIdentity(prefix+card.IMSI(), realm)
}

func storeAKAIdentityState(card Card, state usim.AKAIdentityState) {
	storer, ok := card.(akaIdentityStateStore)
	if !ok {
		return
	}
	storer.SetAKAIdentityState(cloneAKAIdentityState(state))
}

func withoutAKAReauthState(state usim.AKAIdentityState) usim.AKAIdentityState {
	state = cloneAKAIdentityState(state)
	state.ReauthIdentity = ""
	state.Counter = 0
	state.MK = nil
	state.KEncr = nil
	state.KAut = nil
	return state
}

func discardStoredAKAReauthState(card Card, state usim.AKAIdentityState) {
	storeAKAIdentityState(card, withoutAKAReauthState(state))
}

func hasAKATemporaryIdentity(state usim.AKAIdentityState) bool {
	return validAKAReauthState(state) || state.Pseudonym != ""
}

func withoutAKATemporaryIdentity(state usim.AKAIdentityState) usim.AKAIdentityState {
	state = withoutAKAReauthState(state)
	state.Pseudonym = ""
	return state
}

func discardStoredAKATemporaryIdentity(card Card, state usim.AKAIdentityState) {
	storeAKAIdentityState(card, withoutAKATemporaryIdentity(state))
}

func normalizeAKAIdentity(identity, realm string) string {
	identity = strings.TrimSpace(identity)
	if identity == "" || strings.Contains(identity, "@") {
		return identity
	}
	if realm == "" {
		return identity
	}
	return identity + "@" + realm
}

func normalizedPLMNDigits(card Card) (string, string, error) {
	mcc := strings.TrimSpace(card.MCC())
	if len(mcc) != mccDigitCount {
		return "", "", fmt.Errorf("mcc %q must be 3 digits", mcc)
	}

	mnc := strings.TrimSpace(card.MNC())
	switch len(mnc) {
	case mncShortDigitCount:
		mnc = "0" + mnc
	case mncLongDigitCount:
	default:
		return "", "", fmt.Errorf("mnc %q must be 2 or 3 digits", mnc)
	}
	return mcc, mnc, nil
}

func initialAKAIdentity(card Card) (string, string, usim.AKAIdentityState, error) {
	mcc, mnc, err := normalizedPLMNDigits(card)
	if err != nil {
		return "", "", usim.AKAIdentityState{}, err
	}
	realm := fmt.Sprintf("nai.epc.mnc%s.mcc%s.3gppnetwork.org", mnc, mcc)
	state := loadAKAIdentityState(card)
	if identity, ok := normalizedAKAReauthIdentity(state, realm); ok {
		return identity, realm, state, nil
	}
	if state.Pseudonym != "" {
		return normalizeAKAIdentity(state.Pseudonym, realm), realm, state, nil
	}
	return fmt.Sprintf("0%s@%s", card.IMSI(), realm), realm, state, nil
}

func identityRequestType(attrs []eapaka.AKAAttribute) (byte, bool, error) {
	requestType := byte(0)
	requests := 0
	extended := false
	for _, attr := range attrs {
		switch attr.Type {
		case akaAttrPermanentIDReq, akaAttrFullAuthIDReq, akaAttrAnyIDReq:
			if len(attr.Value) != 2 {
				return 0, false, fmt.Errorf("selecting aka identity: invalid identity request attribute length %d", len(attr.Value))
			}
			requests++
			if requests == 1 {
				requestType = attr.Type
				continue
			}
			return 0, false, errors.New("selecting aka identity: duplicate or conflicting identity request attributes")
		case akaAttrMAC, akaAttrIV, akaAttrEncryptedData:
			return 0, false, fmt.Errorf("selecting aka identity: forbidden attribute %d", attr.Type)
		default:
			if attr.Type >= akaSkippableAttributeStart && !isKnownAKAAttribute(attr.Type) {
				extended = true
				continue
			}
			return 0, false, fmt.Errorf("selecting aka identity: unexpected attribute %d", attr.Type)
		}
	}
	if requests != 1 {
		return 0, false, errors.New("selecting aka identity: expected exactly one identity request attribute")
	}
	return requestType, extended, nil
}

func isKnownAKAAttribute(attrType byte) bool {
	switch attrType {
	case akaAttrRAND,
		akaAttrAUTN,
		akaAttrRES,
		akaAttrAUTS,
		akaAttrPadding,
		akaAttrMAC,
		akaAttrNotification,
		akaAttrPermanentIDReq,
		akaAttrAnyIDReq,
		akaAttrIdentity,
		akaAttrFullAuthIDReq,
		akaAttrCounter,
		akaAttrCounterTooSmall,
		akaAttrNonceS,
		akaAttrClientErrorCode,
		akaAttrKDFInput,
		akaAttrKDF,
		akaAttrIV,
		akaAttrEncryptedData,
		akaAttrNextPseudonym,
		akaAttrNextReauthID,
		akaAttrCheckcode,
		akaAttrResultInd,
		akaAttrBidding,
		akaAttrIPMSInd,
		akaAttrIPMSRes,
		akaAttrTrustInd:
		return true
	default:
		return false
	}
}

func selectAKAIdentity(card Card, realm string, state usim.AKAIdentityState, requestType, eapType byte) (string, error) {
	if requestType == akaAttrPermanentIDReq {
		return akaPermanentIdentity(card, realm, eapType), nil
	}
	if requestType == akaAttrFullAuthIDReq {
		if state.Pseudonym != "" {
			return normalizeAKAIdentity(state.Pseudonym, realm), nil
		}
		return akaPermanentIdentity(card, realm, eapType), nil
	}
	if requestType != akaAttrAnyIDReq {
		return "", fmt.Errorf("selecting aka identity: unsupported request type %d", requestType)
	}
	if identity, ok := normalizedAKAReauthIdentity(state, realm); ok {
		return identity, nil
	}
	if state.Pseudonym != "" {
		return normalizeAKAIdentity(state.Pseudonym, realm), nil
	}
	return akaPermanentIdentity(card, realm, eapType), nil
}

func (f *akaAuthFlow) validateIdentityRequest(requestType byte) error {
	switch {
	case f.identityRounds >= 3:
		return errors.New("validating aka identity request: too many identity rounds")
	case f.lastIdentityReq == akaAttrPermanentIDReq:
		return errors.New("validating aka identity request: AT_PERMANENT_ID_REQ must be the final identity request")
	case f.lastIdentityReq == akaAttrAnyIDReq && requestType == akaAttrAnyIDReq:
		return errors.New("validating aka identity request: AT_ANY_ID_REQ is only valid in the first round")
	case f.lastIdentityReq == akaAttrFullAuthIDReq && (requestType == akaAttrAnyIDReq || requestType == akaAttrFullAuthIDReq):
		return errors.New("validating aka identity request: AT_ANY_ID_REQ or AT_FULLAUTH_ID_REQ cannot follow AT_FULLAUTH_ID_REQ")
	default:
		return nil
	}
}

func (f *akaAuthFlow) recordIdentityRequest(requestType byte, extended bool) {
	f.identityRounds++
	f.lastIdentityReq = requestType
	f.identityExtended = f.identityExtended || extended
}

func (f *akaAuthFlow) recordIdentityExchange(request, response []byte) {
	f.identityPackets = append(f.identityPackets, append([]byte(nil), request...), append([]byte(nil), response...))
}
