package ussd

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/damonto/vowifi-go/ims/sip"
	"mime"
	"mime/multipart"
	"strings"
)

func validateInboundInfo(msg sip.Message, requireRequestMarker bool) (Message, error) {
	if !sip.TokenListContains(msg.Header("Info-Package"), infoPackage) {
		return Message{}, fmt.Errorf("missing Info-Package %q", infoPackage)
	}
	if !strings.EqualFold(contentDispositionType(msg.Header("Content-Disposition")), "info-package") {
		return Message{}, errors.New("missing Content-Disposition info-package")
	}
	payload, err := decodeSinglePayload("parsing USSD INFO", msg)
	if err != nil {
		return Message{}, err
	}
	if requireRequestMarker && !payload.Request && !payload.Notify {
		return Message{}, errors.New("missing network initiated USSD marker")
	}
	return payload, nil
}

func splitContentTypeHeader(action, rawContentType string) (string, map[string]string, error) {
	rawContentType = strings.TrimSpace(rawContentType)
	if rawContentType == "" {
		return "", nil, fmt.Errorf("%s: content type is empty", action)
	}
	mediaType, params, err := mime.ParseMediaType(rawContentType)
	if err != nil {
		return "", nil, fmt.Errorf("%s: content type: %w", action, err)
	}
	return strings.ToLower(mediaType), params, nil
}

func readMultipartMessageBody(action string, params map[string]string, data []byte) (multipartBody, error) {
	boundary := params["boundary"]
	if boundary == "" {
		return multipartBody{}, fmt.Errorf("%s: multipart boundary is empty", action)
	}
	body := multipartBody{Boundary: boundary}
	if err := body.UnmarshalBinary(data); err != nil {
		return multipartBody{}, err
	}
	return body, nil
}

func decodeMultipartPayload(action string, body multipartBody) (Message, error) {
	payload, ok, err := body.ussdPayload()
	if err != nil {
		return Message{}, err
	}
	if !ok {
		return Message{}, fmt.Errorf("%s: %s part not found", action, xmlContentType)
	}
	return payload, nil
}

func validateOptionalMultipartSDP(body multipartBody) (bool, error) {
	part, ok := body.part("application/sdp")
	if !ok {
		return false, nil
	}
	if err := validateSDPBody(part.Body); err != nil {
		return true, err
	}
	return true, nil
}

func validateMultipartMessageSDP(action string, body multipartBody) error {
	part, ok := body.part("application/sdp")
	if !ok {
		return fmt.Errorf("%s: application/sdp part not found", action)
	}
	return validateSDPBody(part.Body)
}

func validateMessageSDP(msg sip.Message) error {
	mediaType, params, err := splitContentTypeHeader("validating SDP", msg.Header("Content-Type"))
	if err != nil {
		return err
	}
	switch mediaType {
	case "application/sdp":
		return validateSDPBody(msg.Body)
	case mixedMultipartType:
		body, err := readMultipartMessageBody("validating SDP", params, msg.Body)
		if err != nil {
			return err
		}
		return validateMultipartMessageSDP("validating SDP", body)
	default:
		return fmt.Errorf("unsupported content type %q", mediaType)
	}
}

func validateSDPBody(body []byte) error {
	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	mediaCount := 0
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "m=") {
			continue
		}
		mediaCount++
		fields := strings.Fields(strings.TrimPrefix(line, "m="))
		if len(fields) < 2 {
			return errors.New("malformed media description")
		}
		if fields[1] != "0" {
			return fmt.Errorf("media port %q is not zero", fields[1])
		}
	}
	switch mediaCount {
	case 0:
		return errors.New("missing media description")
	case 1:
		return nil
	default:
		return fmt.Errorf("expected one media description, got %d", mediaCount)
	}
}

func decodePayload(msg sip.Message) (Message, error) {
	rawContentType := strings.TrimSpace(msg.Header("Content-Type"))
	if rawContentType == "" {
		if len(msg.Body) == 0 {
			return Message{}, nil
		}
		return Message{}, errors.New("parsing USSD payload: content type is empty")
	}
	mediaType, params, err := splitContentTypeHeader("parsing USSD payload", rawContentType)
	if err != nil {
		return Message{}, err
	}
	switch mediaType {
	case xmlContentType:
		return decodeXML(msg.Body)
	case mixedMultipartType:
		body, err := readMultipartMessageBody("parsing USSD payload", params, msg.Body)
		if err != nil {
			return Message{}, err
		}
		return decodeMultipartPayload("parsing USSD payload", body)
	default:
		return Message{}, fmt.Errorf("parsing USSD payload: unsupported content type %q", mediaType)
	}
}

func decodeSinglePayload(action string, msg sip.Message) (Message, error) {
	mediaType, _, err := splitContentTypeHeader(action, msg.Header("Content-Type"))
	if err != nil {
		return Message{}, err
	}
	if mediaType != xmlContentType {
		return Message{}, fmt.Errorf("%s: unsupported content type %q", action, mediaType)
	}
	return decodeXML(msg.Body)
}

func decodeXML(data []byte) (Message, error) {
	var payload xmlBody
	if err := payload.UnmarshalText(data); err != nil {
		return Message{}, err
	}
	return payload.Message, nil
}

func normalizeErrorCode(code int) int {
	switch code {
	case 0, 1, 2, 3:
		return code
	default:
		return 1
	}
}

func contentDispositionType(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ";")
	return strings.TrimSpace(parts[0])
}

func acceptsMedia(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, xmlContentType) && strings.Contains(lower, "application/sdp") && strings.Contains(lower, mixedMultipartType)
}

func ioReadAll(part *multipart.Part) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(part); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
