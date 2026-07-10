package sms

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"

	"github.com/damonto/ims-go/ims/sip"
)

const (
	messageContentType          = "application/vnd.3gpp.sms"
	xmlContentType              = "application/vnd.3gpp.sms+xml"
	mixedMultipartType          = "multipart/mixed"
	acceptHeader                = messageContentType + ", " + xmlContentType + ", " + mixedMultipartType
	xmlDisposition              = "render;handling=optional"
	xmlDispositionType          = "render"
	xmlDispositionHandlingParam = "handling"
	xmlDispositionHandlingValue = "optional"
	binaryTransferValue         = "binary"
	ipFeatureTag                = "+g.3gpp.smsip"
	ipMSISDNLessFeatureTag      = "+g.3gpp.smsip-msisdn-less"
	dummyMSISDN                 = "+000000000000000"
)

type messagePayload struct {
	RPDU []byte
	Info xmlInfo
}

func decodeMessagePayload(msg sip.Message) (messagePayload, error) {
	mediaType, params, err := mime.ParseMediaType(msg.Header("Content-Type"))
	if err != nil {
		return messagePayload{}, fmt.Errorf("parsing sms content type: %w", err)
	}
	switch {
	case strings.EqualFold(mediaType, messageContentType):
		if err := validateBinaryTransferEncoding(msg.Header("Content-Transfer-Encoding")); err != nil {
			return messagePayload{}, err
		}
		return messagePayload{RPDU: bytes.Clone(msg.Body)}, nil
	case strings.EqualFold(mediaType, mixedMultipartType):
		return decodeMultipartMessagePayload(msg, params)
	default:
		return messagePayload{}, fmt.Errorf("unsupported sms content type: %s", mediaType)
	}
}

func decodeMultipartMessagePayload(msg sip.Message, params map[string]string) (messagePayload, error) {
	boundary := strings.TrimSpace(params["boundary"])
	if boundary == "" {
		return messagePayload{}, errors.New("multipart sms boundary is empty")
	}
	var payload messagePayload
	var xmlSeen bool
	reader := multipart.NewReader(bytes.NewReader(msg.Body), boundary)
	for {
		part, err := reader.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return messagePayload{}, fmt.Errorf("reading multipart sms body: %w", err)
		}
		mediaType, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			if isOptionalBodyPart(part.Header.Get("Content-Disposition")) {
				_ = part.Close()
				continue
			}
			_ = part.Close()
			return messagePayload{}, fmt.Errorf("parsing multipart sms part content type: %w", err)
		}
		switch {
		case strings.EqualFold(mediaType, messageContentType):
			if err := validateBinaryTransferEncoding(part.Header.Get("Content-Transfer-Encoding")); err != nil {
				_ = part.Close()
				return messagePayload{}, err
			}
		case strings.EqualFold(mediaType, xmlContentType):
			if err := validateXMLDisposition(part.Header.Get("Content-Disposition")); err != nil {
				_ = part.Close()
				return messagePayload{}, err
			}
		default:
			if isOptionalBodyPart(part.Header.Get("Content-Disposition")) {
				_ = part.Close()
				continue
			}
			_ = part.Close()
			return messagePayload{}, fmt.Errorf("unsupported multipart sms part content type: %s", mediaType)
		}
		data, err := io.ReadAll(part)
		if err != nil {
			_ = part.Close()
			return messagePayload{}, fmt.Errorf("reading multipart sms part: %w", err)
		}
		if err := part.Close(); err != nil {
			return messagePayload{}, fmt.Errorf("closing multipart sms part: %w", err)
		}
		switch {
		case strings.EqualFold(mediaType, messageContentType):
			if payload.RPDU != nil {
				return messagePayload{}, errors.New("multipart sms body contains duplicate RP-DATA part")
			}
			payload.RPDU = bytes.Clone(data)
		case strings.EqualFold(mediaType, xmlContentType):
			if xmlSeen {
				return messagePayload{}, errors.New("multipart sms body contains duplicate XML info part")
			}
			xmlSeen = true
			info, err := decodeXMLInfo(data)
			if err != nil {
				return messagePayload{}, err
			}
			payload.Info = info
		}
	}
	if payload.RPDU == nil {
		return messagePayload{}, errors.New("multipart sms body missing RP-DATA part")
	}
	return payload, nil
}

func isOptionalBodyPart(value string) bool {
	_, params, err := mime.ParseMediaType(value)
	if err != nil {
		return false
	}
	return strings.EqualFold(params["handling"], xmlDispositionHandlingValue)
}

func validateBinaryTransferEncoding(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, binaryTransferValue) {
		return nil
	}
	return fmt.Errorf("unsupported sms content transfer encoding: %s", value)
}

func validateXMLDisposition(value string) error {
	disposition, params, err := mime.ParseMediaType(value)
	if err != nil {
		return fmt.Errorf("parsing sms xml content disposition: %w", err)
	}
	if !strings.EqualFold(disposition, xmlDispositionType) {
		return fmt.Errorf("unsupported sms xml content disposition: %s", disposition)
	}
	if !strings.EqualFold(params[xmlDispositionHandlingParam], xmlDispositionHandlingValue) {
		return fmt.Errorf("unsupported sms xml handling: %s", params[xmlDispositionHandlingParam])
	}
	return nil
}

func buildMultipartPayload(info xmlInfo, rpdu []byte) ([]byte, string, error) {
	var payload bytes.Buffer
	writer := multipart.NewWriter(&payload)
	xmlPart, err := writer.CreatePart(textproto.MIMEHeader{
		"Content-Type":        {xmlContentType},
		"Content-Disposition": {xmlDisposition},
	})
	if err != nil {
		return nil, "", fmt.Errorf("creating sms xml part: %w", err)
	}
	xmlBody, err := info.MarshalText()
	if err != nil {
		return nil, "", fmt.Errorf("marshaling sms xml body: %w", err)
	}
	if _, err := xmlPart.Write(xmlBody); err != nil {
		return nil, "", fmt.Errorf("writing sms xml part: %w", err)
	}
	part, err := writer.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {messageContentType},
		"Content-Transfer-Encoding": {binaryTransferValue},
	})
	if err != nil {
		return nil, "", fmt.Errorf("creating sms RP-DATA part: %w", err)
	}
	if _, err := part.Write(rpdu); err != nil {
		return nil, "", fmt.Errorf("writing sms RP-DATA part: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, "", fmt.Errorf("closing sms multipart body: %w", err)
	}
	return payload.Bytes(), fmt.Sprintf("%s; boundary=%q", mixedMultipartType, writer.Boundary()), nil
}
