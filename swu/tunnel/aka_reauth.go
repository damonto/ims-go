package tunnel

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/eapaka"
)

func (f *akaAuthFlow) buildReauthenticationResponse(message eapaka.AKAMessage, eapData []byte) (akaResponse, error) {
	if !validAKAReauthState(f.currentState) {
		return f.clientErrorResponse(message.Identifier, errors.New("validating reauth state: reauth state is unavailable"))
	}
	if f.reauthIdentity == "" {
		return f.clientErrorResponse(message.Identifier, errors.New("validating reauth state: reauth identity is unavailable"))
	}
	discardStoredAKAReauthState(f.card, f.currentState)
	if err := f.verifyMessageMAC(message.EAPType, eapData, f.currentState.KAut, nil); err != nil {
		return f.clientErrorResponse(message.Identifier, fmt.Errorf("verifying reauth mac: %w", err))
	}
	if err := f.verifyCheckcode(message.Attributes, message.EAPType); err != nil {
		return f.clientErrorResponse(message.Identifier, fmt.Errorf("verifying reauth checkcode: %w", err))
	}
	if response, ok, err := f.biddingDownRejectResponse(message); ok || err != nil {
		return response, err
	}
	var reauth eapaka.AKAReauthentication
	if err := reauth.UnmarshalMessage(message, f.currentState.KEncr); err != nil {
		return f.clientErrorResponse(message.Identifier, fmt.Errorf("parsing reauth request: %w", err))
	}
	if reauth.Counter <= f.currentState.Counter {
		data, err := eapaka.BuildReauthenticationResponsePacketForType(message.Identifier, message.EAPType, reauth.Counter, true, reauth.UseResultInd, f.currentState.KAut, f.currentState.KEncr, reauth.NonceS)
		if err != nil {
			return akaResponse{}, fmt.Errorf("building reauth counter-too-small response: %w", err)
		}
		return akaResponse{data: data}, nil
	}
	f.currentAuthKey = append([]byte(nil), f.currentState.KAut...)
	f.currentEncrKey = append([]byte(nil), f.currentState.KEncr...)
	f.currentEAPType = message.EAPType
	f.currentCounter = reauth.Counter
	f.fastReauth = true
	var msk, emsk []byte
	var err error
	if message.EAPType == eapTypeAKAPrime {
		msk, emsk, err = eapaka.DeriveAKAPrimeFastReauthKeysFromMK([]byte(f.reauthIdentity), reauth.Counter, reauth.NonceS, f.currentState.MK)
	} else {
		msk, emsk, err = eapaka.DeriveFastReauthKeys([]byte(f.reauthIdentity), reauth.Counter, reauth.NonceS, f.currentState.MK)
	}
	if err != nil {
		return f.clientErrorResponse(message.Identifier, fmt.Errorf("deriving fast reauth keys: %w", err))
	}
	f.crypto.eap.MK = append([]byte(nil), f.currentState.MK...)
	f.crypto.eap.AUT = append([]byte(nil), f.currentState.KAut...)
	f.crypto.eap.ENCR = append([]byte(nil), f.currentState.KEncr...)
	f.crypto.eap.MSK = msk
	f.crypto.eap.EMSK = emsk
	f.pendingState = cloneAKAIdentityState(f.currentState)
	f.pendingState.Counter = reauth.Counter
	if reauth.NextReauthID != "" {
		f.pendingState.ReauthIdentity = reauth.NextReauthID
	} else {
		f.pendingState.ReauthIdentity = ""
		f.pendingState.Counter = 0
		f.pendingState.MK = nil
		f.pendingState.KEncr = nil
		f.pendingState.KAut = nil
	}
	data, err := eapaka.BuildReauthenticationResponsePacketForType(message.Identifier, message.EAPType, reauth.Counter, false, reauth.UseResultInd, f.currentState.KAut, f.currentState.KEncr, reauth.NonceS)
	if err != nil {
		return akaResponse{}, fmt.Errorf("building reauth response: %w", err)
	}
	f.markAKAAuthenticated(reauth.UseResultInd)
	return akaResponse{data: data}, nil
}
