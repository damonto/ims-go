package tunnel

import (
	"errors"
	"fmt"

	"github.com/damonto/vowifi-go/eapaka"
)

func (f *akaAuthFlow) markAKAAuthenticated(useProtectedSuccess bool) {
	f.akaAuthenticated = true
	f.protectedSuccessExpected = useProtectedSuccess
	f.protectedSuccessReceived = false
}

func (f *akaAuthFlow) validateEAPSuccess() error {
	if !f.akaAuthenticated {
		return errors.New("connecting swu session: eap success before aka authentication")
	}
	if f.protectedSuccessExpected && !f.protectedSuccessReceived {
		return errors.New("connecting swu session: eap success before protected success notification")
	}
	return nil
}

func (f *akaAuthFlow) buildNotificationResponse(message eapaka.AKAMessage, eapData []byte) (akaResponse, error) {
	var notification eapaka.AKANotification
	if err := notification.UnmarshalAttributes(message.Attributes); err != nil {
		return f.clientErrorResponse(message.Identifier, fmt.Errorf("parsing notification: %w", err))
	}
	if f.notificationReceived {
		return f.clientErrorResponse(message.Identifier, errors.New("validating notification: multiple aka notification rounds"))
	}
	f.notificationReceived = true
	if !notification.Protected && eapaka.HasAttribute(message.Attributes, akaAttrMAC) {
		return f.clientErrorResponse(message.Identifier, errors.New("validating notification: pre-challenge notification must not include AT_MAC"))
	}
	if notification.Protected {
		if len(f.currentAuthKey) == 0 {
			return f.clientErrorResponse(message.Identifier, errors.New("verifying notification mac: notification mac key is unavailable"))
		}
		if err := f.verifyMessageMAC(f.currentEAPType, eapData, f.currentAuthKey, nil); err != nil {
			return f.clientErrorResponse(message.Identifier, fmt.Errorf("verifying notification mac: %w", err))
		}
		if err := f.validateIPMSResult(message, notification); err != nil {
			return f.clientErrorResponse(message.Identifier, fmt.Errorf("validating ipms result: %w", err))
		}
		if f.fastReauth {
			nested, err := eapaka.DecryptAttributes(message.Attributes, f.currentEncrKey)
			if err != nil {
				return f.clientErrorResponse(message.Identifier, fmt.Errorf("decrypting notification attrs: %w", err))
			}
			if len(nested) != 1 || nested[0].Type != akaAttrCounter {
				return f.clientErrorResponse(message.Identifier, errors.New("validating notification attrs: expected encrypted AT_COUNTER only"))
			}
			counter, err := eapaka.Uint16Value(&nested[0])
			if err != nil {
				return f.clientErrorResponse(message.Identifier, fmt.Errorf("parsing notification counter: %w", err))
			}
			if counter != f.currentCounter {
				return f.clientErrorResponse(message.Identifier, fmt.Errorf("validating notification counter: counter %d does not match %d", counter, f.currentCounter))
			}
		}
	}
	data, err := eapaka.BuildNotificationResponsePacketForType(message.Identifier, f.currentEAPType, notification, f.fastReauth, f.currentCounter, f.currentAuthKey, f.currentEncrKey)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building notification response: %w", err)
	}
	if !notification.Success {
		return akaResponse{data: data, afterSend: fmt.Errorf("connecting swu session: notification code %d", notification.Code)}, nil
	}
	if notification.Code != akaNotificationSuccess {
		return f.clientErrorResponse(message.Identifier, fmt.Errorf("validating success notification: unexpected success notification code %d", notification.Code))
	}
	if !f.akaAuthenticated {
		return f.clientErrorResponse(message.Identifier, errors.New("validating success notification: aka authentication is incomplete"))
	}
	if !f.protectedSuccessExpected {
		return f.clientErrorResponse(message.Identifier, errors.New("validating success notification: protected success was not negotiated"))
	}
	f.protectedSuccessReceived = true
	return akaResponse{data: data}, nil
}

func (f *akaAuthFlow) validateIPMSResult(message eapaka.AKAMessage, notification eapaka.AKANotification) error {
	selection, ok, err := eapaka.IPMSSelectionFromAttributes(message.Attributes)
	if err != nil {
		return err
	}
	if !notification.Success {
		return nil
	}
	if !f.ipmsIndicated {
		return nil
	}
	if !ok {
		return errors.New("AT_IPMS_RES is missing after AT_IPMS_IND")
	}
	if selection != eapaka.IPMSSelectionNBM {
		return fmt.Errorf("selected mobility protocol %d is unsupported", selection)
	}
	return nil
}
