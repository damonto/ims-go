package ims

import (
	"bytes"
	"encoding"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strings"
)

var (
	_ encoding.TextMarshaler     = ussdXMLBody{}
	_ encoding.TextUnmarshaler   = (*ussdXMLBody)(nil)
	_ encoding.BinaryMarshaler   = multipartBody{}
	_ encoding.BinaryUnmarshaler = (*multipartBody)(nil)
)

type ussdXMLBody struct {
	Message USSDMessage
}

type multipartBody struct {
	Boundary string
	Parts    []multipartBodyPart
}

func (b ussdXMLBody) MarshalText() ([]byte, error) {
	payload := ussdXML{
		Language:  strings.TrimSpace(b.Message.Language),
		String:    b.Message.Text,
		ErrorCode: normalizeUSSDErrorCode(b.Message.ErrorCode),
	}
	if b.Message.ErrorCode == 0 {
		payload.ErrorCode = 0
	}
	if b.Message.Request || b.Message.Notify {
		payload.AnyExt = &ussdAnyExt{}
		if b.Message.Request {
			payload.AnyExt.Request = &struct{}{}
		}
		if b.Message.Notify {
			payload.AnyExt.Notify = &struct{}{}
		}
	}
	body, err := xml.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encoding USSD XML: %w", err)
	}
	return append([]byte(xml.Header), body...), nil
}

func (b *ussdXMLBody) UnmarshalText(text []byte) error {
	var payload ussdXML
	if err := xml.Unmarshal(text, &payload); err != nil {
		return fmt.Errorf("parsing USSD XML: %w", err)
	}
	msg := USSDMessage{
		Text:      strings.TrimSpace(payload.String),
		Language:  strings.TrimSpace(payload.Language),
		ErrorCode: normalizeUSSDErrorCode(payload.ErrorCode),
	}
	if payload.ErrorCode == 0 {
		msg.ErrorCode = 0
	}
	if payload.AnyExt != nil {
		msg.Request = payload.AnyExt.Request != nil
		msg.Notify = payload.AnyExt.Notify != nil
	}
	b.Message = msg
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

func (b multipartBody) ussdPayload() (USSDMessage, bool, error) {
	part, ok := b.part(ussdContentType)
	if !ok {
		return USSDMessage{}, false, nil
	}
	var payload ussdXMLBody
	if err := payload.UnmarshalText(part.Body); err != nil {
		return USSDMessage{}, false, err
	}
	return payload.Message, true, nil
}
