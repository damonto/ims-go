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
)

var (
	_ encoding.TextMarshaler     = xmlBody{}
	_ encoding.TextUnmarshaler   = (*xmlBody)(nil)
	_ encoding.BinaryMarshaler   = multipartBody{}
	_ encoding.BinaryUnmarshaler = (*multipartBody)(nil)
	_ xml.Unmarshaler            = (*xmlPayload)(nil)
)

type xmlBody struct {
	Message Message
}

type multipartBody struct {
	Boundary string
	Parts    []multipartBodyPart
}

func (b xmlBody) MarshalText() ([]byte, error) {
	language := strings.TrimSpace(b.Message.Language)
	if err := validateLanguage(language); err != nil {
		return nil, err
	}
	payload := xmlPayload{
		Language: language,
		String:   b.Message.Text,
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
	return append([]byte(xml.Header), body...), nil
}

func (b *xmlBody) UnmarshalText(text []byte) error {
	var payload xmlPayload
	if err := xml.Unmarshal(escapeBareAmpersands(text), &payload); err != nil {
		return err
	}
	if err := validateLanguage(payload.Language); err != nil {
		return err
	}
	msg := Message{
		Text:     payload.String,
		Language: strings.TrimSpace(payload.Language),
	}
	if payload.ErrorCode != nil {
		msg.ErrorCode = normalizeErrorCode(*payload.ErrorCode)
	}
	if payload.AnyExt != nil {
		msg.Request = payload.AnyExt.Request != nil
		msg.Notify = payload.AnyExt.Notify != nil
	}
	b.Message = msg
	return nil
}

func escapeBareAmpersands(text []byte) []byte {
	if !bytes.Contains(text, []byte("&")) {
		return text
	}
	var out []byte
	for i := 0; i < len(text); i++ {
		if text[i] != '&' || isXMLReference(text[i:]) {
			out = append(out, text[i])
			continue
		}
		out = append(out, "&amp;"...)
	}
	return out
}

func isXMLReference(text []byte) bool {
	semi := bytes.IndexByte(text, ';')
	if semi < 0 {
		return false
	}
	name := string(text[1:semi])
	switch name {
	case "quot", "lt", "gt", "apos", "amp":
		return true
	}
	if strings.HasPrefix(name, "#x") || strings.HasPrefix(name, "#X") {
		return len(name) > 2 && allASCIIAlphaNum(name[2:])
	}
	if strings.HasPrefix(name, "#") {
		return len(name) > 1 && allASCIIAlphaNum(name[1:])
	}
	return false
}

func allASCIIAlphaNum(value string) bool {
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return false
		}
	}
	return value != ""
}

func (p *xmlPayload) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	if start.Name.Local != "ussd-data" {
		return fmt.Errorf("parsing USSD XML: unexpected root element %q", start.Name.Local)
	}
	*p = xmlPayload{XMLName: start.Name}
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
			if depth == 0 && elementInDocumentNamespace(elem.Name, start.Name.Space) {
				switch elem.Name.Local {
				case "language", "ussd-string", "error-code":
					counts[elem.Name.Local]++
					if counts[elem.Name.Local] > 1 {
						return fmt.Errorf("parsing USSD XML: duplicate %s element", elem.Name.Local)
					}
					field = elem.Name.Local
					fieldText.Reset()
				case "anyExt":
					counts[elem.Name.Local]++
					if counts[elem.Name.Local] > 1 {
						return fmt.Errorf("parsing USSD XML: duplicate %s element", elem.Name.Local)
					}
					inAnyExt = true
					p.AnyExt = &anyExt{}
				case "UnstructuredSS-Request":
					p.ensureAnyExt().Request = new(struct{})
				case "UnstructuredSS-Notify":
					p.ensureAnyExt().Notify = new(struct{})
				}
			} else if inAnyExt && depth == 1 && elementInDocumentNamespace(elem.Name, start.Name.Space) {
				switch elem.Name.Local {
				case "UnstructuredSS-Request":
					p.AnyExt.Request = new(struct{})
				case "UnstructuredSS-Notify":
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
					p.Language = value
				case "ussd-string":
					p.String = value
				case "error-code":
					code, err := strconv.Atoi(strings.TrimSpace(value))
					if err != nil {
						return fmt.Errorf("parsing USSD XML: error-code: %w", err)
					}
					p.ErrorCode = &code
				}
				field = ""
			}
			if inAnyExt && depth == 0 && elementInDocumentNamespace(elem.Name, start.Name.Space) && elem.Name.Local == "anyExt" {
				inAnyExt = false
			}
		}
	}
	return errors.New("parsing USSD XML: missing ussd-data root element")
}

func elementInDocumentNamespace(name xml.Name, documentNamespace string) bool {
	return name.Space == "" || name.Space == documentNamespace
}

func (p *xmlPayload) ensureAnyExt() *anyExt {
	if p.AnyExt == nil {
		p.AnyExt = &anyExt{}
	}
	return p.AnyExt
}

func validateLanguage(language string) error {
	language = strings.TrimSpace(language)
	if language == "" {
		return nil
	}
	if strings.EqualFold(language, undefinedLang) {
		return nil
	}
	if strings.Contains(language, "-") {
		return fmt.Errorf("parsing USSD XML: language %q contains more than one subtag", language)
	}
	if len(language) < 2 || len(language) > 8 {
		return fmt.Errorf("parsing USSD XML: language %q is not a single RFC 5646 subtag", language)
	}
	for _, r := range language {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return fmt.Errorf("parsing USSD XML: language %q is not a single RFC 5646 subtag", language)
		}
	}
	return nil
}

func (b multipartBody) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
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
		body, err := ioReadAll(part)
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
	var payloadPart multipartBodyPart
	found := false
	for _, part := range b.Parts {
		partType, err := part.mediaType()
		if err != nil || !strings.EqualFold(partType, xmlContentType) {
			continue
		}
		if found {
			return Message{}, false, fmt.Errorf("parsing multipart body: multiple %s parts", xmlContentType)
		}
		payloadPart = part
		found = true
	}
	if !found {
		return Message{}, false, nil
	}
	var payload xmlBody
	if err := payload.UnmarshalText(payloadPart.Body); err != nil {
		return Message{}, false, err
	}
	return payload.Message, true, nil
}
