package tunnel

import (
	"errors"
	"fmt"
	"strings"

	"github.com/damonto/ims-go/eapaka"
	usim "github.com/damonto/wwan-go/sim"
)

// Temporary identities are usable only when they can also be invalidated or
// replaced, so reading and writing the state are one capability.
type akaIdentityStateStorage interface {
	AKAIdentityState() usim.AKAIdentityState
	SetAKAIdentityState(usim.AKAIdentityState)
}

type akaIdentityType uint8

const (
	akaIdentityUnknown akaIdentityType = iota
	akaIdentityPermanent
	akaIdentityPseudonym
	akaIdentityFastReauth
)

func (t akaIdentityType) String() string {
	switch t {
	case akaIdentityPermanent:
		return "permanent"
	case akaIdentityPseudonym:
		return "pseudonym"
	case akaIdentityFastReauth:
		return "fast_reauth"
	default:
		return "unknown"
	}
}

type akaIdentitySelection struct {
	identity     string
	realm        string
	identityType akaIdentityType
	state        usim.AKAIdentityState
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
	storage, ok := card.(akaIdentityStateStorage)
	if !ok {
		return usim.AKAIdentityState{}
	}
	return cloneAKAIdentityState(storage.AKAIdentityState())
}

func normalizedAKAReauthIdentity(state usim.AKAIdentityState, realm string) (string, bool) {
	if !state.HasReauth() {
		return "", false
	}
	identity := normalizeAKAIdentity(state.ReauthIdentity, realm)
	return identity, identity != ""
}

func normalizedAKAPseudonym(state usim.AKAIdentityState, realm string) (string, bool) {
	if !state.HasPseudonym() {
		return "", false
	}
	identity := normalizeAKAIdentity(state.Pseudonym, realm)
	return identity, identity != ""
}

func akaPermanentIdentity(card Card, realm string, eapType byte) string {
	prefix := "0"
	if eapType == eapTypeAKAPrime {
		prefix = "6"
	}
	return normalizeAKAIdentity(prefix+card.IMSI(), realm)
}

func storeAKAIdentityState(card Card, state usim.AKAIdentityState) bool {
	storage, ok := card.(akaIdentityStateStorage)
	if !ok {
		return false
	}
	storage.SetAKAIdentityState(cloneAKAIdentityState(state))
	return true
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

func discardStoredAKAReauthState(card Card, state usim.AKAIdentityState) bool {
	return storeAKAIdentityState(card, withoutAKAReauthState(state))
}

func withoutAKATemporaryIdentities(state usim.AKAIdentityState) usim.AKAIdentityState {
	state = withoutAKAReauthState(state)
	state.Pseudonym = ""
	return state
}

func discardStoredAKATemporaryIdentities(card Card, state usim.AKAIdentityState) bool {
	return storeAKAIdentityState(card, withoutAKATemporaryIdentities(state))
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

func isASCIIDigits(value string) bool {
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func normalizedPLMNDigits(card Card) (string, string, error) {
	mcc := strings.TrimSpace(card.MCC())
	if len(mcc) != mccDigitCount || !isASCIIDigits(mcc) {
		return "", "", fmt.Errorf("mcc %q must be 3 digits", mcc)
	}

	mnc := strings.TrimSpace(card.MNC())
	if !isASCIIDigits(mnc) {
		return "", "", fmt.Errorf("mnc %q must be 2 or 3 digits", mnc)
	}
	switch len(mnc) {
	case mncShortDigitCount:
		mnc = "0" + mnc
	case mncLongDigitCount:
	default:
		return "", "", fmt.Errorf("mnc %q must be 2 or 3 digits", mnc)
	}
	return mcc, mnc, nil
}

func selectInitialAKAIdentity(card Card) (akaIdentitySelection, error) {
	mcc, mnc, err := normalizedPLMNDigits(card)
	if err != nil {
		return akaIdentitySelection{}, err
	}
	realm := fmt.Sprintf("nai.epc.mnc%s.mcc%s.3gppnetwork.org", mnc, mcc)
	state := loadAKAIdentityState(card)
	if identity, ok := normalizedAKAReauthIdentity(state, realm); ok {
		return akaIdentitySelection{
			identity:     identity,
			realm:        realm,
			identityType: akaIdentityFastReauth,
			state:        state,
		}, nil
	}
	if identity, ok := normalizedAKAPseudonym(state, realm); ok {
		return akaIdentitySelection{
			identity:     identity,
			realm:        realm,
			identityType: akaIdentityPseudonym,
			state:        state,
		}, nil
	}
	return akaIdentitySelection{
		identity:     akaPermanentIdentity(card, realm, eapTypeAKA),
		realm:        realm,
		identityType: akaIdentityPermanent,
		state:        state,
	}, nil
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
		if identity, ok := normalizedAKAPseudonym(state, realm); ok {
			return identity, nil
		}
		return akaPermanentIdentity(card, realm, eapType), nil
	}
	if requestType != akaAttrAnyIDReq {
		return "", fmt.Errorf("selecting aka identity: unsupported request type %d", requestType)
	}
	if identity, ok := normalizedAKAReauthIdentity(state, realm); ok {
		return identity, nil
	}
	if identity, ok := normalizedAKAPseudonym(state, realm); ok {
		return identity, nil
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
