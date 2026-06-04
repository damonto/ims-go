package tunnel

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/damonto/vowifi-go/swu/ike"
)

func responderIDRawFromPayloads(payloads []ike.Payload) ([]byte, error) {
	idr := ike.FindIDPayload(payloads, payloadTypeIDr)
	if idr == nil {
		return nil, errors.New("connecting swu session: ike_auth response idr is missing")
	}
	if err := validateResponderID(idr); err != nil {
		return nil, fmt.Errorf("connecting swu session: ike_auth response idr: %w", err)
	}
	idrRaw, err := idr.RawData()
	if err != nil {
		return nil, fmt.Errorf("connecting swu session: ike_auth response idr: %w", err)
	}
	return idrRaw, nil
}

func validateResponderID(idr *ike.IDPayload) error {
	switch idr.IDType {
	case idTypeIPv4Addr:
		if len(idr.Data) != 4 {
			return fmt.Errorf("ID_IPV4_ADDR length %d, want 4", len(idr.Data))
		}
	case idTypeIPv6Addr:
		if len(idr.Data) != 16 {
			return fmt.Errorf("ID_IPV6_ADDR length %d, want 16", len(idr.Data))
		}
	case idTypeFQDN, idTypeRFC822Addr, idTypeDERASN1DN, idTypeKeyID:
		return nil
	default:
		return fmt.Errorf("unsupported type %d", idr.IDType)
	}
	return nil
}

func (f *akaAuthFlow) finishSuccess(ctx context.Context, serverPayloads []ike.Payload) ([]ike.Payload, uint32, error) {
	if err := f.validateEAPSuccess(); err != nil {
		return nil, 0, err
	}
	storeAKAIdentityState(f.card, f.pendingState)
	authValue, err := f.crypto.ComputeInitiatorAuth(f.ikeInitRequest, f.responderNonce, f.idiRaw)
	if err != nil {
		return nil, 0, fmt.Errorf("connecting swu session: computing initiator auth: %w", err)
	}
	finalAuthPayloads := []ike.Payload{&ike.AuthPayload{Method: authMethodSharedKeyMIC, Data: authValue}}
	finalAuthPayloads, err = appendDeviceIdentityResponsePayload(finalAuthPayloads, serverPayloads, f.imei, true)
	if err != nil {
		return nil, 0, fmt.Errorf("connecting swu session: building final auth device identity: %w", err)
	}
	header := ike.IKEHeader{InitiatorSPI: f.initiatorSPI, ResponderSPI: f.responderSPI, Version: ikeVersion20, ExchangeType: exchangeTypeIKEAuth, Flags: flagInitiator, MessageID: f.nextRequestID}
	request, err := f.crypto.SealIKE(header, finalAuthPayloads, true)
	if err != nil {
		return nil, 0, fmt.Errorf("connecting swu session: sealing final ike_auth: %w", err)
	}
	responseRaw, _, err := f.session.exchangeIKE(ctx, f.session.outerNAT, request, true, f.nextRequestID)
	if err != nil {
		return nil, 0, err
	}
	var responsePacket ike.IKEPacket
	if err := responsePacket.UnmarshalBinary(responseRaw); err != nil {
		return nil, 0, fmt.Errorf("connecting swu session: parsing final ike_auth response: %w", err)
	}
	payloads, err := openIKEAuthResponse(responsePacket, f.crypto, "connecting swu session: opening final ike_auth response")
	if err != nil {
		return nil, 0, err
	}
	if err := f.verifyResponderPostEAPAuth(payloads); err != nil {
		return nil, 0, err
	}
	return payloads, f.nextRequestID + 1, nil
}

func (f *akaAuthFlow) verifyResponderPostEAPAuth(payloads []ike.Payload) error {
	auth := findAuthPayload(payloads)
	if auth == nil {
		return errors.New("connecting swu session: final ike_auth response auth is missing")
	}
	if auth.Method != authMethodSharedKeyMIC {
		return fmt.Errorf("connecting swu session: final ike_auth response auth method %d", auth.Method)
	}
	want, err := f.crypto.ComputeResponderAuth(f.ikeInitResponse, f.initiatorNonce, f.idrRaw)
	if err != nil {
		return fmt.Errorf("connecting swu session: verifying responder auth: %w", err)
	}
	if !hmac.Equal(auth.Data, want) {
		return errors.New("connecting swu session: responder auth verification failed")
	}
	return nil
}

func findAuthPayload(payloads []ike.Payload) *ike.AuthPayload {
	for _, payload := range payloads {
		auth, ok := payload.(*ike.AuthPayload)
		if ok {
			return auth
		}
	}
	return nil
}

func (f *akaAuthFlow) exchangeResponse(ctx context.Context, serverPayloads []ike.Payload, responseData []byte) ([]ike.Payload, error) {
	nextPayloads, err := f.session.exchangeAKAResponse(ctx, f.crypto, f.initiatorSPI, f.responderSPI, f.nextRequestID, serverPayloads, f.imei, f.akaAuthenticated, responseData)
	if err != nil {
		return nil, err
	}
	return nextPayloads, nil
}

func (s *Session) exchangeAKAResponse(ctx context.Context, crypto *ikeCrypto, initiatorSPI, responderSPI uint64, messageID uint32, serverPayloads []ike.Payload, imei string, allowDeviceIdentity bool, responseData []byte) ([]ike.Payload, error) {
	requestPayloads := []ike.Payload{&ike.EAPPayload{Data: responseData}}
	requestPayloads, err := appendDeviceIdentityResponsePayload(requestPayloads, serverPayloads, imei, allowDeviceIdentity)
	if err != nil {
		return nil, fmt.Errorf("connecting swu session: building device identity response: %w", err)
	}
	logEAPPacket(s.logger, "sending EAP packet", "outbound", messageID, responseData)
	header := ike.IKEHeader{InitiatorSPI: initiatorSPI, ResponderSPI: responderSPI, Version: ikeVersion20, ExchangeType: exchangeTypeIKEAuth, Flags: flagInitiator, MessageID: messageID}
	request, err := crypto.SealIKE(header, requestPayloads, true)
	if err != nil {
		return nil, fmt.Errorf("connecting swu session: sealing aka response: %w", err)
	}
	responseRaw, _, err := s.exchangeIKE(ctx, s.outerNAT, request, true, messageID)
	if err != nil {
		return nil, err
	}
	var responsePacket ike.IKEPacket
	if err := responsePacket.UnmarshalBinary(responseRaw); err != nil {
		return nil, fmt.Errorf("connecting swu session: parsing aka response message: %w", err)
	}
	payloads, err := openIKEAuthResponse(responsePacket, crypto, "connecting swu session: opening aka response message")
	if err != nil {
		return nil, err
	}
	return payloads, nil
}

func appendDeviceIdentityResponsePayload(payloads []ike.Payload, serverPayloads []ike.Payload, imei string, allowed bool) ([]ike.Payload, error) {
	if !allowed {
		return payloads, nil
	}
	deviceIdentityPayload, ok, err := buildDeviceIdentityResponsePayload(serverPayloads, imei)
	if err != nil {
		return nil, err
	}
	if ok {
		payloads = append(payloads, deviceIdentityPayload)
	}
	return payloads, nil
}

func openIKEAuthResponse(packet ike.IKEPacket, crypto *ikeCrypto, action string) ([]ike.Payload, error) {
	payloads, err := crypto.OpenIKE(packet, false)
	if err == nil {
		if notifyErr := protectedIKENotifyError(payloads); notifyErr != nil {
			return nil, fmt.Errorf("%s: %w", action, notifyErr)
		}
		return payloads, nil
	}
	if !hasEncryptedPayload(packet.Payloads) {
		if notifyErr := plaintextIKENotifyError(packet.Payloads); notifyErr != nil {
			return nil, fmt.Errorf("%s: %w", action, notifyErr)
		}
	}
	return nil, fmt.Errorf("%s: %w", action, err)
}

func hasEncryptedPayload(payloads []ike.Payload) bool {
	for _, payload := range payloads {
		if _, ok := payload.(*ike.EncryptedPayload); ok {
			return true
		}
	}
	return false
}

func plaintextIKENotifyError(payloads []ike.Payload) error {
	return ikeAuthNotifyError(payloads, "unencrypted", false)
}

func protectedIKENotifyError(payloads []ike.Payload) error {
	return ikeAuthNotifyError(payloads, "protected", true)
}

func ikeAuthNotifyError(payloads []ike.Payload, protection string, requireErrorNotify bool) error {
	if len(payloads) == 0 {
		if requireErrorNotify {
			return nil
		}
		return fmt.Errorf("received %s ike_auth response without payloads", protection)
	}
	notifies := make([]string, 0, len(payloads))
	var backoffDelay time.Duration
	var backoffDeactivated bool
	var backoffSeen bool
	var backoffMalformed bool
	var errorNotifySeen bool
	var networkFailureSeen bool
	var backoffCause uint16
	var accessRejection uint16
	for _, payload := range payloads {
		notify, ok := payload.(*ike.NotifyPayload)
		if !ok {
			continue
		}
		if notify.NotifyType == notifyTypeBackoffTimer {
			delay, deactivated, ok := backoffTimerValue(notify)
			if ok {
				backoffDelay = delay
				backoffDeactivated = deactivated
				backoffSeen = true
			} else {
				backoffMalformed = true
			}
		}
		if ikeErrorNotify(notify.NotifyType) {
			errorNotifySeen = true
			if backoffCause == 0 {
				backoffCause = notify.NotifyType
			}
		}
		if notify.NotifyType == notifyTypeNetworkFailure {
			networkFailureSeen = true
		}
		if accessRejectedNotify(notify.NotifyType) {
			accessRejection = notify.NotifyType
		}
		notifies = append(notifies, fmt.Sprintf("%s (%d)", ikeNotifyName(notify.NotifyType), notify.NotifyType))
	}
	if len(notifies) == 0 || requireErrorNotify && !errorNotifySeen {
		return nil
	}
	err := fmt.Errorf("received %s ike_auth notify %s", protection, strings.Join(notifies, ", "))
	if networkFailureSeen {
		err = networkFailureErrorFor(err)
	}
	if accessRejection != 0 {
		err = accessRejectionErrorFor(accessRejection, err)
	}
	if backoffMalformed && errorNotifySeen {
		return fmt.Errorf("received malformed BACKOFF_TIMER notify: %w", err)
	}
	if backoffSeen && errorNotifySeen {
		return &backoffTimerError{delay: backoffDelay, deactivated: backoffDeactivated, cause: backoffCause, err: err}
	}
	return err
}
