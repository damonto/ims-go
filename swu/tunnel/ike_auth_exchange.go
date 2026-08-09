package tunnel

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/damonto/ims-go/swu/ike"
)

// protectedIKEAuthenticationFailedError never marks a plaintext Notify. It
// proves only that the sender participated in IKE_SA_INIT, not the sender's
// identity, so callers must limit recovery to tearing down and rebuilding state.
type protectedIKEAuthenticationFailedError struct {
	err error
}

func (e *protectedIKEAuthenticationFailedError) Error() string {
	return e.err.Error()
}

func (e *protectedIKEAuthenticationFailedError) Unwrap() error {
	return e.err
}

func isProtectedIKEAuthenticationFailed(err error) bool {
	_, ok := errors.AsType[*protectedIKEAuthenticationFailedError](err)
	return ok
}

func responderIDRawFromPayloads(payloads []ike.Payload, requestedAPN string, requestedDefaultAPN bool) ([]byte, string, error) {
	idr := ike.FindIDPayload(payloads, payloadTypeIDr)
	if idr == nil {
		return nil, "", errors.New("ike_auth response idr is missing")
	}
	if err := validateResponderID(idr); err != nil {
		return nil, "", fmt.Errorf("ike_auth response idr: %w", err)
	}
	idrRaw, err := idr.RawData()
	if err != nil {
		return nil, "", fmt.Errorf("ike_auth response idr: %w", err)
	}
	responderAPN, err := responderAPNFromID(idr, requestedAPN, requestedDefaultAPN)
	if err != nil {
		return nil, "", fmt.Errorf("ike_auth response idr: %w", err)
	}
	return idrRaw, responderAPN, nil
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

func responderAPNFromID(idr *ike.IDPayload, requestedAPN string, requestedDefaultAPN bool) (string, error) {
	if idr.IDType != idTypeFQDN {
		if requestedDefaultAPN {
			return "", nil
		}
		requestedAPN = strings.TrimSpace(requestedAPN)
		if requestedAPN == "" {
			requestedAPN = DefaultAPN
		}
		return requestedAPN, nil
	}
	if len(idr.Data) == 0 {
		return "", errors.New("data is empty")
	}
	for _, char := range idr.Data {
		if char < 0x21 || char > 0x7e {
			return "", errors.New("fqdn contains a non-printable or non-ASCII character")
		}
	}
	if requestedDefaultAPN {
		return string(idr.Data), nil
	}
	requestedAPN = strings.TrimSpace(requestedAPN)
	if requestedAPN == "" {
		requestedAPN = DefaultAPN
	}
	// RFC 7296 allows the responder to assert an IDr different from the one
	// proposed by the initiator. Some ePDGs use their node FQDN here instead of
	// echoing the APN required by TS 24.302, so keep the requested APN separate
	// from the responder identity used to verify AUTH.
	return requestedAPN, nil
}

func (f *akaAuthFlow) finishSuccess(ctx context.Context, serverPayloads []ike.Payload) ([]ike.Payload, uint32, error) {
	if err := f.validateEAPSuccess(); err != nil {
		return nil, 0, err
	}
	storeAKAIdentityState(f.card, f.pendingState)
	authValue, err := f.crypto.ComputeInitiatorAuth(f.ikeInitRequest, f.responderNonce, f.idiRaw)
	if err != nil {
		return nil, 0, fmt.Errorf("computing initiator auth: %w", err)
	}
	finalAuthPayloads := []ike.Payload{&ike.AuthPayload{Method: authMethodSharedKeyMIC, Data: authValue}}
	finalAuthPayloads, err = appendDeviceIdentityResponsePayload(finalAuthPayloads, serverPayloads, f.imei, true)
	if err != nil {
		return nil, 0, fmt.Errorf("building final auth device identity: %w", err)
	}
	header := ike.IKEHeader{InitiatorSPI: f.initiatorSPI, ResponderSPI: f.responderSPI, Version: ikeVersion20, ExchangeType: exchangeTypeIKEAuth, Flags: flagInitiator, MessageID: f.nextRequestID}
	requests, err := sealIKEPackets(f.crypto, header, finalAuthPayloads, true, f.ikeFragmentationSupported)
	if err != nil {
		return nil, 0, fmt.Errorf("sealing final ike_auth: %w", err)
	}
	payloads, _, err := f.session.exchangeProtectedIKE(ctx, protectedIKEExchange{
		peer:                   f.ikePeer,
		requests:               requests,
		useNATT:                f.useNATT,
		messageID:              f.nextRequestID,
		crypto:                 f.crypto,
		fragmentationSupported: f.ikeFragmentationSupported,
		action:                 ikeActionOpenFinalIKEAuthResponse,
	})
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
		return errors.New("final ike_auth response auth is missing")
	}
	if auth.Method != authMethodSharedKeyMIC {
		return fmt.Errorf("final ike_auth response auth method %d", auth.Method)
	}
	want, err := f.crypto.ComputeResponderAuth(f.ikeInitResponse, f.initiatorNonce, f.idrRaw)
	if err != nil {
		return fmt.Errorf("verifying responder auth: %w", err)
	}
	if !hmac.Equal(auth.Data, want) {
		return errors.New("responder auth verification failed")
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
	requestPayloads := []ike.Payload{&ike.EAPPayload{Data: responseData}}
	requestPayloads, err := appendDeviceIdentityResponsePayload(requestPayloads, serverPayloads, f.imei, f.akaAuthenticated)
	if err != nil {
		return nil, fmt.Errorf("building device identity response: %w", err)
	}
	logEAPPacket(f.logger(), "sending EAP packet", "outbound", f.nextRequestID, responseData)
	header := ike.IKEHeader{InitiatorSPI: f.initiatorSPI, ResponderSPI: f.responderSPI, Version: ikeVersion20, ExchangeType: exchangeTypeIKEAuth, Flags: flagInitiator, MessageID: f.nextRequestID}
	requests, err := sealIKEPackets(f.crypto, header, requestPayloads, true, f.ikeFragmentationSupported)
	if err != nil {
		return nil, fmt.Errorf("sealing aka response: %w", err)
	}
	payloads, _, err := f.session.exchangeProtectedIKE(ctx, protectedIKEExchange{
		peer:                   f.ikePeer,
		requests:               requests,
		useNATT:                f.useNATT,
		messageID:              f.nextRequestID,
		crypto:                 f.crypto,
		fragmentationSupported: f.ikeFragmentationSupported,
		action:                 ikeActionConnectOpenAKAResponseMessage,
	})
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

func openIKEAuthResponse(packet ike.IKEPacket, crypto *ikeCrypto, action ikeAction) ([]ike.Payload, error) {
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
		if _, ok := payload.(*ike.EncryptedFragmentPayload); ok {
			return true
		}
	}
	return false
}

func plaintextIKENotifyError(payloads []ike.Payload) error {
	return ikeAuthNotifyError(payloads, false)
}

func protectedIKENotifyError(payloads []ike.Payload) error {
	return ikeAuthNotifyError(payloads, true)
}

func protectedIKEAuthNotifyError(action ikeAction, payloads []ike.Payload) error {
	switch action {
	case ikeActionOpenFinalIKEAuthResponse,
		ikeActionConnectOpenAKAResponseMessage,
		ikeActionOpenAKAResponseMessage,
		ikeActionOpenIKEAuthChallenge:
		if err := protectedIKENotifyError(payloads); err != nil {
			return fmt.Errorf("%s: %w", action, err)
		}
	}
	return nil
}

func ikeAuthNotifyError(payloads []ike.Payload, protected bool) error {
	protection := "unencrypted"
	if protected {
		protection = "protected"
	}
	if len(payloads) == 0 {
		if protected {
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
	var authenticationFailureSeen bool
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
		if notify.NotifyType == notifyTypeAuthenticationFailed {
			authenticationFailureSeen = true
		}
		if accessRejectedNotify(notify.NotifyType) {
			accessRejection = notify.NotifyType
		}
		notifies = append(notifies, fmt.Sprintf("%s (%d)", ikeNotifyName(notify.NotifyType), notify.NotifyType))
	}
	if len(notifies) == 0 || (protected && !errorNotifySeen) {
		return nil
	}
	err := fmt.Errorf("received %s ike_auth notify %s", protection, strings.Join(notifies, ", "))
	if protected && authenticationFailureSeen {
		err = &protectedIKEAuthenticationFailedError{err: err}
	}
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
