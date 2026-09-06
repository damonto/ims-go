package ussd

import (
	"bytes"
	"encoding"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strconv"
	"strings"

	"golang.org/x/text/language"
)

var (
	_ encoding.TextAppender      = xmlBody{}
	_ encoding.TextMarshaler     = xmlBody{}
	_ encoding.TextUnmarshaler   = (*xmlBody)(nil)
	_ encoding.BinaryAppender    = multipartBody{}
	_ encoding.BinaryMarshaler   = multipartBody{}
	_ encoding.BinaryUnmarshaler = (*multipartBody)(nil)
	_ xml.Unmarshaler            = (*xmlPayload)(nil)
)

type xmlBody struct {
	Message  Message
	presence payloadPresence
}

type multipartBody struct {
	Boundary string
	Parts    []multipartBodyPart
}

func (b xmlBody) MarshalText() ([]byte, error) {
	return b.AppendText(nil)
}

func (b xmlBody) AppendText(dst []byte) ([]byte, error) {
	language := strings.TrimSpace(b.Message.Language)
	if err := validateLanguage(language); err != nil {
		return nil, err
	}
	payload := xmlPayload{}
	if language != "" {
		payload.Language = &language
	}
	if b.Message.ErrorCode == 0 || b.Message.Text != "" {
		text := b.Message.Text
		payload.String = &text
	}
	if b.Message.ErrorCode != 0 {
		errorCode := normalizeErrorCode(b.Message.ErrorCode)
		payload.ErrorCode = &errorCode
	}
	if b.Message.Request || b.Message.Notify {
		payload.AnyExt = &anyExt{}
		if b.Message.Request {
			payload.AnyExt.Request = new(struct{})
		}
		if b.Message.Notify {
			payload.AnyExt.Notify = new(struct{})
		}
	}
	body, err := xml.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encoding USSD XML: %w", err)
	}
	dst = append(dst, xml.Header...)
	return append(dst, body...), nil
}

func (b *xmlBody) UnmarshalText(text []byte) error {
	var payload xmlPayload
	if err := xml.Unmarshal(text, &payload); err != nil {
		return err
	}
	language := stringValue(payload.Language)
	if err := validateLanguage(language); err != nil {
		return err
	}
	msg := Message{
		Text:     stringValue(payload.String),
		Language: strings.TrimSpace(language),
	}
	// Some networks label a successful textual result with error-code 0.
	if payload.ErrorCode != nil && *payload.ErrorCode != 0 {
		msg.ErrorCode = normalizeErrorCode(*payload.ErrorCode)
	}
	if payload.AnyExt != nil {
		msg.Request = payload.AnyExt.Request != nil
		msg.Notify = payload.AnyExt.Notify != nil
	}
	b.Message = msg
	b.presence = payloadPresence{
		hasLanguage:  payload.hasLanguage,
		hasText:      payload.hasString,
		hasErrorCode: payload.hasError,
	}
	return nil
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (p *xmlPayload) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	if start.Name.Local != "ussd-data" || start.Name.Space != "" {
		return fmt.Errorf("parsing USSD XML: unexpected root element %q", start.Name.Local)
	}
	*p = xmlPayload{XMLName: start.Name}
	// Carrier replies can reorder the fields. Match names while retaining
	// the duplicate checks required by TS 24.390 section 5.1.3.2.
	counts := map[string]int{
		"language":    0,
		"ussd-string": 0,
		"error-code":  0,
		"anyExt":      0,
	}
	var field string
	var fieldText strings.Builder
	depth := 0
	inAnyExt := false
	markerCounts := map[string]int{}
	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("parsing USSD XML: %w", err)
		}
		switch elem := token.(type) {
		case xml.StartElement:
			if field != "" {
				return fmt.Errorf("parsing USSD XML: %s element contains a child element", field)
			}
			if depth == 0 && elem.Name.Space == "" {
				switch elem.Name.Local {
				case "language", "ussd-string", "error-code":
					counts[elem.Name.Local]++
					if counts[elem.Name.Local] > 1 {
						return fmt.Errorf("parsing USSD XML: duplicate %s element", elem.Name.Local)
					}
					field = elem.Name.Local
					fieldText.Reset()
					switch elem.Name.Local {
					case "language":
						p.hasLanguage = true
					case "ussd-string":
						p.hasString = true
					case "error-code":
						p.hasError = true
					}
				case "anyExt":
					counts[elem.Name.Local]++
					if counts[elem.Name.Local] > 1 {
						return fmt.Errorf("parsing USSD XML: duplicate %s element", elem.Name.Local)
					}
					inAnyExt = true
					p.AnyExt = &anyExt{}
				}
			} else if inAnyExt && depth == 1 && elem.Name.Space == "" {
				switch elem.Name.Local {
				case "UnstructuredSS-Request":
					markerCounts[elem.Name.Local]++
					if markerCounts[elem.Name.Local] > 1 {
						return errors.New("parsing USSD XML: duplicate UnstructuredSS-Request element")
					}
					p.AnyExt.Request = new(struct{})
				case "UnstructuredSS-Notify":
					markerCounts[elem.Name.Local]++
					if markerCounts[elem.Name.Local] > 1 {
						return errors.New("parsing USSD XML: duplicate UnstructuredSS-Notify element")
					}
					p.AnyExt.Notify = new(struct{})
				}
			}
			depth++
		case xml.CharData:
			if field != "" {
				fieldText.Write([]byte(elem))
			}
		case xml.EndElement:
			if depth == 0 && elem.Name.Local == start.Name.Local {
				return nil
			}
			depth--
			if field != "" && depth == 0 {
				value := fieldText.String()
				switch field {
				case "language":
					p.Language = &value
				case "ussd-string":
					p.String = &value
				case "error-code":
					code, err := strconv.Atoi(strings.TrimSpace(value))
					if err != nil {
						return fmt.Errorf("parsing USSD XML: error-code: %w", err)
					}
					p.ErrorCode = &code
				}
				field = ""
			}
			if inAnyExt && depth == 0 && elem.Name.Space == "" && elem.Name.Local == "anyExt" {
				inAnyExt = false
			}
		}
	}
	return errors.New("parsing USSD XML: missing ussd-data root element")
}

func validateLanguage(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	// Networks use full RFC 5646 tags such as en-US, including in dialogs
	// where the received language is reused for subsequent replies.
	if strings.Contains(value, "_") {
		return fmt.Errorf("parsing USSD XML: language %q uses an invalid separator", value)
	}
	if _, err := language.Parse(value); err != nil {
		return fmt.Errorf("parsing USSD XML: language %q: %w", value, err)
	}
	return nil
}

func (b multipartBody) MarshalBinary() ([]byte, error) {
	return b.AppendBinary(nil)
}

func (b multipartBody) AppendBinary(dst []byte) ([]byte, error) {
	buf := bytes.NewBuffer(dst)
	writer := multipart.NewWriter(buf)
	if err := writer.SetBoundary(b.Boundary); err != nil {
		return nil, fmt.Errorf("building multipart body: %w", err)
	}
	for _, part := range b.Parts {
		pw, err := writer.CreatePart(part.Header)
		if err != nil {
			return nil, fmt.Errorf("building multipart part: %w", err)
		}
		if _, err := pw.Write(part.Body); err != nil {
			return nil, fmt.Errorf("writing multipart part: %w", err)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("closing multipart body: %w", err)
	}
	return buf.Bytes(), nil
}

func (b *multipartBody) UnmarshalBinary(data []byte) error {
	reader := multipart.NewReader(bytes.NewReader(data), b.Boundary)
	var parts []multipartBodyPart
	for {
		part, err := reader.NextPart()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("parsing multipart body: %w", err)
		}
		body, err := io.ReadAll(part)
		if err != nil {
			return fmt.Errorf("reading multipart part: %w", err)
		}
		parts = append(parts, multipartBodyPart{Header: part.Header, Body: body})
	}
	b.Parts = parts
	return nil
}

func (p multipartBodyPart) mediaType() (string, error) {
	mediaType, _, err := mime.ParseMediaType(p.Header.Get("Content-Type"))
	if err != nil {
		return "", err
	}
	return strings.ToLower(mediaType), nil
}

func (b multipartBody) part(mediaType string) (multipartBodyPart, bool) {
	for _, part := range b.Parts {
		partType, err := part.mediaType()
		if err != nil {
			continue
		}
		if strings.EqualFold(partType, mediaType) {
			return part, true
		}
	}
	return multipartBodyPart{}, false
}

func (b multipartBody) rejectUnsupportedRequiredParts(context payloadContext, supportedTypes ...string) error {
	for _, part := range b.Parts {
		partType, err := part.mediaType()
		if err != nil {
			if part.isOptional() {
				continue
			}
			return fmt.Errorf("%w: %s: multipart part content type: %w", errUnsupportedMediaType, context, err)
		}
		if supportedMediaType(partType, supportedTypes) || part.isOptional() {
			continue
		}
		return fmt.Errorf("%w: %s: unsupported multipart part content type %q", errUnsupportedMediaType, context, partType)
	}
	return nil
}

func supportedMediaType(mediaType string, supportedTypes []string) bool {
	for _, supported := range supportedTypes {
		if strings.EqualFold(mediaType, supported) {
			return true
		}
	}
	return false
}

func (p multipartBodyPart) isOptional() bool {
	_, params, err := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
	if err != nil {
		return false
	}
	return strings.EqualFold(params[handlingDispositionParam], optionalHandlingDisposition)
}

func (b multipartBody) payload() (Message, bool, error) {
	payload, ok, _, err := b.payloadWithPresence()
	return payload, ok, err
}

func (b multipartBody) payloadWithPresence() (Message, bool, payloadPresence, error) {
	var payloadPart multipartBodyPart
	found := false
	for _, part := range b.Parts {
		partType, err := part.mediaType()
		if err != nil || !strings.EqualFold(partType, xmlContentType) {
			continue
		}
		if found {
			return Message{}, false, payloadPresence{}, fmt.Errorf("parsing multipart body: multiple %s parts", xmlContentType)
		}
		payloadPart = part
		found = true
	}
	if !found {
		return Message{}, false, payloadPresence{}, nil
	}
	payload, presence, err := decodeXMLWithPresence(payloadPart.Body)
	if err != nil {
		return Message{}, false, payloadPresence{}, err
	}
	return payload, true, presence, nil
}
