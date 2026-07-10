package session

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const sipHeaderDelimiter = "\r\n\r\n"

// StageSIPMessages splits a SIP TCP byte stream into complete SIP messages.
func StageSIPMessages(stream []byte) ([][]byte, []byte, error) {
	rest := trimLeadingSIPCRLF(stream)
	messages := make([][]byte, 0)
	for len(rest) != 0 {
		message, next, complete, err := NextSIPMessage(rest)
		if err != nil {
			return messages, rest, err
		}
		if !complete {
			return messages, rest, nil
		}
		messages = append(messages, message)
		rest = trimLeadingSIPCRLF(next)
	}
	return messages, rest, nil
}

// NextSIPMessage returns the next complete SIP message from a TCP byte stream.
func NextSIPMessage(stream []byte) ([]byte, []byte, bool, error) {
	stream = trimLeadingSIPCRLF(stream)
	if len(stream) == 0 {
		return nil, stream, false, nil
	}
	headerEnd := bytes.Index(stream, []byte(sipHeaderDelimiter))
	if headerEnd < 0 {
		if len(stream) > maxSIPHeaderBytes {
			return nil, nil, false, errors.New("parsing SIP message: SIP header too large")
		}
		return nil, stream, false, nil
	}
	headerBytes := headerEnd + len(sipHeaderDelimiter)
	if headerBytes > maxSIPHeaderBytes {
		return nil, nil, false, errors.New("parsing SIP message: SIP header too large")
	}
	contentLength, err := sipContentLength(stream[:headerEnd])
	if err != nil {
		return nil, nil, false, fmt.Errorf("parsing SIP message: %w", err)
	}
	if contentLength > maxSIPMessageBytes-headerBytes {
		return nil, nil, false, errors.New("parsing SIP message: SIP message too large")
	}
	messageBytes := headerBytes + contentLength
	if len(stream) < messageBytes {
		return nil, stream, false, nil
	}
	return append([]byte(nil), stream[:messageBytes]...), stream[messageBytes:], true, nil
}

func sipContentLength(header []byte) (int, error) {
	lines := bytes.Split(header, []byte("\r\n"))
	for _, line := range lines[1:] {
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		field := strings.TrimSpace(string(name))
		if !strings.EqualFold(field, "Content-Length") && !strings.EqualFold(field, "l") {
			continue
		}
		raw := strings.TrimSpace(string(value))
		length, err := strconv.Atoi(raw)
		if err != nil {
			return 0, fmt.Errorf("invalid Content-Length %q", raw)
		}
		if length < 0 {
			return 0, errors.New("invalid negative Content-Length")
		}
		return length, nil
	}
	return 0, errors.New("missing Content-Length")
}

func trimLeadingSIPCRLF(stream []byte) []byte {
	for len(stream) != 0 {
		switch {
		case bytes.HasPrefix(stream, []byte("\r\n")):
			stream = stream[2:]
		case stream[0] == '\r' || stream[0] == '\n':
			stream = stream[1:]
		default:
			return stream
		}
	}
	return stream
}
