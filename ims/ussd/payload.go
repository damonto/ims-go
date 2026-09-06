package ussd

import (
	"errors"
	"fmt"
	"mime"
	"strconv"
	"strings"

	"github.com/damonto/ims-go/ims/sip"
)

var errBadInfoPackage = errors.New("bad info package")
var errUnsupportedMediaType = errors.New("unsupported media type")

type payloadContext uint8

const (
	payloadContextUSSDInfo payloadContext = iota
	payloadContextUSSDInvite
	payloadContextSDP
	payloadContextUSSDPayload
	payloadContextUSSDBye
)

func (c payloadContext) String() string {
	switch c {
	case payloadContextUSSDInfo:
		return "parsing USSD INFO"
	case payloadContextUSSDInvite:
		return "parsing USSD INVITE"
	case payloadContextSDP:
		return "validating SDP"
	case payloadContextUSSDPayload:
		return "parsing USSD payload"
	case payloadContextUSSDBye:
		return "parsing USSD BYE"
	default:
		return "parsing USSD"
	}
}

func validateInboundInfo(msg sip.Message, requireRequestMarker bool) (Message, error) {
	if !msg.HeaderHasToken("Info-Package", infoPackage) {
		return Message{}, fmt.Errorf("%w: missing Info-Package %q", errBadInfoPackage, infoPackage)
	}
	if !validInfoContentDisposition(msg.Header("Content-Disposition")) {
		return Message{}, errors.New("bad Content-Disposition info-package")
	}
	payload, presence, err := decodeSinglePayloadWithPresence(payloadContextUSSDInfo, msg)
	if err != nil {
		return Message{}, err
	}
	if presence.hasErrorCode && payload.ErrorCode != 0 {
		return payload, nil
	}
	if !presence.hasText {
		return Message{}, errors.New("missing ussd-string element")
	}
	if !presence.hasLanguage {
		return Message{}, errors.New("missing language element")
	}
	if requireRequestMarker {
		if !payload.Request || payload.Notify {
			return Message{}, errors.New("invalid network initiated USSD request marker")
		}
	}
	return payload, nil
}

func splitContentTypeHeader(context payloadContext, rawContentType string) (string, map[string]string, error) {
	rawContentType = strings.TrimSpace(rawContentType)
	if rawContentType == "" {
		return "", nil, fmt.Errorf("%s: content type is empty", context)
	}
	mediaType, params, err := mime.ParseMediaType(rawContentType)
	if err != nil {
		return "", nil, fmt.Errorf("%s: content type: %w", context, err)
	}
	return strings.ToLower(mediaType), params, nil
}

func readMultipartMessageBody(context payloadContext, params map[string]string, data []byte) (multipartBody, error) {
	boundary := params["boundary"]
	if boundary == "" {
		return multipartBody{}, fmt.Errorf("%s: multipart boundary is empty", context)
	}
	body := multipartBody{Boundary: boundary}
	if err := body.UnmarshalBinary(data); err != nil {
		return multipartBody{}, err
	}
	return body, nil
}

func validateMultipartSDPOffer(body multipartBody) ([]byte, error) {
	var sdp []byte
	for _, part := range body.Parts {
		partType, err := part.mediaType()
		if err != nil || !strings.EqualFold(partType, sdpContentType) {
			continue
		}
		if sdp != nil {
			return nil, fmt.Errorf("multiple %s parts", sdpContentType)
		}
		if err := validateSDPBody(part.Body); err != nil {
			return nil, err
		}
		sdp = part.Body
	}
	return sdp, nil
}

func validateMultipartMessageSDP(context payloadContext, body multipartBody) error {
	part, ok := body.part(sdpContentType)
	if !ok {
		return fmt.Errorf("%s: %s part not found", context, sdpContentType)
	}
	return validateSDPBody(part.Body)
}

func validateMessageSDP(msg sip.Message) error {
	mediaType, params, err := splitContentTypeHeader(payloadContextSDP, msg.Header("Content-Type"))
	if err != nil {
		return err
	}
	switch mediaType {
	case sdpContentType:
		return validateSDPBody(msg.Body)
	case mixedMultipartType:
		body, err := readMultipartMessageBody(payloadContextSDP, params, msg.Body)
		if err != nil {
			return err
		}
		if err := body.rejectUnsupportedRequiredParts(payloadContextSDP, sdpContentType, xmlContentType); err != nil {
			return err
		}
		return validateMultipartMessageSDP(payloadContextSDP, body)
	default:
		return fmt.Errorf("%w: unsupported content type %q", errUnsupportedMediaType, mediaType)
	}
}

func messageSDPBody(msg sip.Message) ([]byte, error) {
	return messageBodyPart(msg, sdpContentType)
}

func messageBodyPart(msg sip.Message, wantedType string) ([]byte, error) {
	mediaType, params, err := splitContentTypeHeader(payloadContextSDP, msg.Header("Content-Type"))
	if err != nil {
		return nil, err
	}
	if mediaType == wantedType {
		return msg.Body, nil
	}
	if mediaType != mixedMultipartType {
		return nil, fmt.Errorf("%w: unsupported content type %q", errUnsupportedMediaType, mediaType)
	}
	body, err := readMultipartMessageBody(payloadContextSDP, params, msg.Body)
	if err != nil {
		return nil, err
	}
	part, ok := body.part(wantedType)
	if !ok {
		return nil, fmt.Errorf("%s part not found", wantedType)
	}
	return part.Body, nil
}

func validateSDPBody(body []byte) error {
	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	counts := map[byte]int{}
	lastMandatory := 0
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if len(line) < 2 || line[1] != '=' {
			return fmt.Errorf("malformed SDP line %q", line)
		}
		field := line[0]
		counts[field]++
		order := map[byte]int{'v': 1, 'o': 2, 's': 3, 't': 4, 'm': 5}[field]
		if order != 0 {
			if order < lastMandatory {
				return fmt.Errorf("SDP %c= line is out of order", field)
			}
			lastMandatory = order
		}
		switch field {
		case 'v':
			if counts[field] > 1 || line != "v=0" {
				return errors.New("invalid SDP protocol version")
			}
		case 'o':
			if counts[field] > 1 || len(strings.Fields(strings.TrimPrefix(line, "o="))) != 6 {
				return errors.New("malformed SDP origin")
			}
		case 's':
			if counts[field] > 1 || strings.TrimPrefix(line, "s=") == "" {
				return errors.New("malformed SDP session name")
			}
		case 't':
			if len(strings.Fields(strings.TrimPrefix(line, "t="))) != 2 {
				return errors.New("malformed SDP timing")
			}
		case 'c':
			if len(strings.Fields(strings.TrimPrefix(line, "c="))) < 3 {
				return errors.New("malformed SDP connection information")
			}
		case 'm':
			fields := strings.Fields(strings.TrimPrefix(line, "m="))
			if len(fields) < 4 {
				return errors.New("malformed media description")
			}
			port := strings.SplitN(fields[1], "/", 2)[0]
			if port != "0" {
				return fmt.Errorf("media port %q is not zero", fields[1])
			}
		}
	}
	for _, field := range []byte{'v', 'o', 's', 't', 'c'} {
		if counts[field] == 0 {
			return fmt.Errorf("missing %c= line", field)
		}
	}
	switch counts['m'] {
	case 0:
		return errors.New("missing media description")
	case 1:
		return nil
	default:
		return fmt.Errorf("expected one media description, got %d", counts['m'])
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
	mediaType, params, err := splitContentTypeHeader(payloadContextUSSDPayload, rawContentType)
	if err != nil {
		return Message{}, err
	}
	switch mediaType {
	case xmlContentType:
		return decodeXML(msg.Body)
	case mixedMultipartType:
		body, err := readMultipartMessageBody(payloadContextUSSDPayload, params, msg.Body)
		if err != nil {
			return Message{}, err
		}
		if err := body.rejectUnsupportedRequiredParts(payloadContextUSSDPayload, xmlContentType, sdpContentType); err != nil {
			return Message{}, err
		}
		payload, ok, err := body.payload()
		if err != nil {
			return Message{}, err
		}
		if !ok {
			return Message{}, fmt.Errorf("%s: %s part not found", payloadContextUSSDPayload, xmlContentType)
		}
		return payload, nil
	default:
		return Message{}, fmt.Errorf("%w: parsing USSD payload: unsupported content type %q", errUnsupportedMediaType, mediaType)
	}
}

func decodeSinglePayloadWithPresence(context payloadContext, msg sip.Message) (Message, payloadPresence, error) {
	mediaType, _, err := splitContentTypeHeader(context, msg.Header("Content-Type"))
	if err != nil {
		return Message{}, payloadPresence{}, err
	}
	if mediaType != xmlContentType {
		return Message{}, payloadPresence{}, fmt.Errorf("%w: %s: unsupported content type %q", errUnsupportedMediaType, context, mediaType)
	}
	return decodeXMLWithPresence(msg.Body)
}

func decodeXML(data []byte) (Message, error) {
	payload, _, err := decodeXMLWithPresence(data)
	return payload, err
}

func decodeXMLWithPresence(data []byte) (Message, payloadPresence, error) {
	var payload xmlBody
	if err := payload.UnmarshalText(data); err != nil {
		return Message{}, payloadPresence{}, err
	}
	return payload.Message, payload.presence, nil
}

func normalizeErrorCode(code int) int {
	switch code {
	case ErrorCodeUnspecified, ErrorCodeLanguageUnsupported, ErrorCodeUnexpectedDataValue, ErrorCodeUSSDBusy:
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
		return false
	}
	return strings.EqualFold(contentDispositionType(value), infoPackageDisposition)
}

func acceptsMedia(value string) bool {
	var hasXML, hasSDP, hasMixed bool
	for _, raw := range strings.Split(value, ",") {
		mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		if q, ok := params["q"]; ok {
			quality, err := strconv.ParseFloat(q, 64)
			if err != nil || quality <= 0 || quality > 1 {
				continue
			}
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
