package ussd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/damonto/vowifi-go/ims/sip"
)

func validateInviteOK(msg sip.Message) error {
	if !sip.TokenListContains(msg.Header("Recv-Info"), infoPackage) {
		return fmt.Errorf("missing Recv-Info %q", infoPackage)
	}
	if err := validateMessageSDP(msg); err != nil {
		return fmt.Errorf("validating SDP answer: %w", err)
	}
	return nil
}

func validateIncomingInvite(msg sip.Message) (Message, error) {
	if !sip.TokenListContains(msg.Header("Recv-Info"), infoPackage) {
		return Message{}, fmt.Errorf("missing Recv-Info %q", infoPackage)
	}
	if !acceptsMedia(msg.Header("Accept")) {
		return Message{}, errors.New("missing required Accept media types")
	}
	payload, hasSDP, err := decodeInvitePayload(msg)
	if err != nil {
		return Message{}, err
	}
	if !hasSDP {
		return Message{}, errors.New("missing SDP offer")
	}
	if !payload.Request && !payload.Notify {
		return Message{}, errors.New("missing network initiated USSD marker")
	}
	return payload, nil
}

func decodeInvitePayload(msg sip.Message) (Message, bool, error) {
	mediaType, params, err := splitContentTypeHeader(payloadContextUSSDInvite, msg.Header("Content-Type"))
	if err != nil {
		return Message{}, false, err
	}
	if mediaType != mixedMultipartType {
		return Message{}, false, fmt.Errorf("%w: parsing USSD INVITE: unsupported content type %q", errUnsupportedMediaType, mediaType)
	}
	body, err := readMultipartMessageBody(payloadContextUSSDInvite, params, msg.Body)
	if err != nil {
		return Message{}, false, err
	}
	if err := body.rejectUnsupportedRequiredParts(payloadContextUSSDInvite, xmlContentType, sdpContentType); err != nil {
		return Message{}, false, err
	}
	payload, err := decodeMultipartPayload(payloadContextUSSDInvite, body)
	if err != nil {
		return Message{}, false, err
	}
	hasSDP, err := validateOptionalMultipartSDP(body)
	if err != nil {
		return Message{}, false, err
	}
	return payload, hasSDP, nil
}

func looksLikeInvite(msg sip.Message) bool {
	if !strings.EqualFold(msg.Method(), "INVITE") {
		return false
	}
	return sip.TokenListContains(msg.Header("Recv-Info"), infoPackage) || acceptsMedia(msg.Header("Accept"))
}
