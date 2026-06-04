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

var errBadInfoPackage = errors.New("bad info package")
var errUnsupportedMediaType = errors.New("unsupported media type")

func validateInboundInfo(msg sip.Message, requireRequestMarker bool) (Message, error) {
	if !sip.TokenListContains(msg.Header("Info-Package"), infoPackage) {
		return Message{}, fmt.Errorf("%w: missing Info-Package %q", errBadInfoPackage, infoPackage)
	}
	if !validInfoContentDisposition(msg.Header("Content-Disposition")) {
		return Message{}, errors.New("bad Content-Disposition info-package")
	}
	payload, err := decodeSinglePayload("parsing USSD INFO", msg)
	if err != nil {
		return Message{}, err
	}
	if requireRequestMarker && payload.ErrorCode == 0 && !payload.Request && !payload.Notify {
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
	payload, ok, err := body.payload()
	if err != nil {
		return Message{}, err
	}
	if !ok {
		return Message{}, fmt.Errorf("%s: %s part not found", action, xmlContentType)
	}
	return payload, nil
}

func validateOptionalMultipartSDP(body multipartBody) (bool, error) {
	found := false
	for _, part := range body.Parts {
		partType, err := part.mediaType()
		if err != nil || !strings.EqualFold(partType, sdpContentType) {
			continue
		}
		if found {
			return true, fmt.Errorf("multiple %s parts", sdpContentType)
		}
		found = true
		if err := validateSDPBody(part.Body); err != nil {
			return true, err
		}
	}
	return found, nil
}

func validateMultipartMessageSDP(action string, body multipartBody) error {
	part, ok := body.part(sdpContentType)
	if !ok {
		return fmt.Errorf("%s: %s part not found", action, sdpContentType)
	}
	return validateSDPBody(part.Body)
}

func validateMessageSDP(msg sip.Message) error {
	mediaType, params, err := splitContentTypeHeader("validating SDP", msg.Header("Content-Type"))
	if err != nil {
		return err
	}
	switch mediaType {
	case sdpContentType:
		return validateSDPBody(msg.Body)
	case mixedMultipartType:
		body, err := readMultipartMessageBody("validating SDP", params, msg.Body)
		if err != nil {
			return err
		}
		if err := body.rejectUnsupportedRequiredParts("validating SDP", sdpContentType, xmlContentType); err != nil {
			return err
		}
		return validateMultipartMessageSDP("validating SDP", body)
	default:
		return fmt.Errorf("%w: unsupported content type %q", errUnsupportedMediaType, mediaType)
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
		if err := body.rejectUnsupportedRequiredParts("parsing USSD payload", xmlContentType, sdpContentType); err != nil {
			return Message{}, err
		}
		return decodeMultipartPayload("parsing USSD payload", body)
	default:
		return Message{}, fmt.Errorf("%w: parsing USSD payload: unsupported content type %q", errUnsupportedMediaType, mediaType)
	}
}

func decodeSinglePayload(action string, msg sip.Message) (Message, error) {
	mediaType, _, err := splitContentTypeHeader(action, msg.Header("Content-Type"))
	if err != nil {
		return Message{}, err
	}
	if mediaType != xmlContentType {
		return Message{}, fmt.Errorf("%w: %s: unsupported content type %q", errUnsupportedMediaType, action, mediaType)
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
	case ErrorCodeUnspecified, ErrorCodeLanguageUnsupported, ErrorCodeUnexpectedDataValue:
		return code
	default:
		return ErrorCodeUnspecified
	}
}

func contentDispositionType(value string) string {
	disposition, _, err := mime.ParseMediaType(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	return disposition
}

func validInfoContentDisposition(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		// Samsung's USSD stack exposes additional contents as MIME type + body only.
		return true
	}
	return strings.EqualFold(contentDispositionType(value), infoPackageDisposition)
}

func acceptsMedia(value string) bool {
	var hasXML, hasSDP, hasMixed bool
	for _, raw := range strings.Split(value, ",") {
		mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		switch strings.ToLower(mediaType) {
		case xmlContentType:
			hasXML = true
		case sdpContentType:
			hasSDP = true
		case mixedMultipartType:
			hasMixed = true
		}
	}
	return hasXML && hasSDP && hasMixed
}

func ioReadAll(part *multipart.Part) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(part); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
