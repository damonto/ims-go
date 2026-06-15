package transport

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func nextSIPMessage(stream []byte) ([]byte, []byte, bool, error) {
	stream = trimLeadingSIPCRLF(stream)
	headersEnd := bytes.Index(stream, []byte("\r\n\r\n"))
	if headersEnd < 0 {
		if len(stream) > tcpMaxSIPHeaderBytes {
			return nil, stream, false, errors.New("reading tcp packet: SIP header too large")
		}
		return nil, stream, false, nil
	}
	if headersEnd > tcpMaxSIPHeaderBytes {
		return nil, stream, false, errors.New("reading tcp packet: SIP header too large")
	}
	headersBlob := string(stream[:headersEnd])
	contentLength := 0
	foundContentLength := false
	for line := range strings.SplitSeq(headersBlob, "\r\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if !strings.EqualFold(name, "Content-Length") && !strings.EqualFold(name, "l") {
			continue
		}
		foundContentLength = true
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return nil, stream, false, fmt.Errorf("reading tcp packet: parsing Content-Length: %w", err)
		}
		if parsed < 0 {
			return nil, stream, false, errors.New("reading tcp packet: invalid negative Content-Length")
		}
		contentLength = parsed
		break
	}
	if !foundContentLength {
		return nil, stream, false, errors.New("reading tcp packet: missing Content-Length")
	}
	headersSize := headersEnd + 4
	if contentLength > tcpMaxSIPMessageBytes-headersSize {
		return nil, stream, false, errors.New("reading tcp packet: SIP message too large")
	}
	total := headersSize + contentLength
	if len(stream) < total {
		return nil, stream, false, nil
	}
	return append([]byte(nil), stream[:total]...), append([]byte(nil), stream[total:]...), true, nil
}

func stageSIPMessages(stream []byte) ([][]byte, []byte, error) {
	var messages [][]byte
	for {
		msg, rest, ok, err := nextSIPMessage(stream)
		if err != nil {
			return messages, stream, err
		}
		if !ok {
			return messages, rest, nil
		}
		messages = append(messages, msg)
		stream = rest
	}
}

func trimLeadingSIPCRLF(stream []byte) []byte {
	for len(stream) >= 2 && stream[0] == '\r' && stream[1] == '\n' {
		stream = stream[2:]
	}
	return stream
}
