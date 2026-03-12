package ims

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type Header struct {
	Name  string
	Value string
}

type Message struct {
	StartLine string
	Headers   []Header
	Body      []byte
}

func NewRequest(method, uri string) Message {
	return Message{StartLine: fmt.Sprintf("%s %s SIP/2.0", method, uri)}
}

func NewResponse(code int, reason string) Message {
	return Message{StartLine: fmt.Sprintf("SIP/2.0 %d %s", code, reason)}
}

func splitMessageSections(data []byte) ([]byte, []byte, error) {
	parts := bytes.SplitN(data, []byte("\r\n\r\n"), 2)
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("parsing SIP message: missing header separator")
	}
	return parts[0], parts[1], nil
}

func appendParsedHeader(headers []Header, line string) ([]Header, error) {
	if line == "" {
		return headers, nil
	}
	if line[0] == ' ' || line[0] == '	' {
		if len(headers) == 0 {
			return nil, fmt.Errorf("parsing SIP header %q: missing previous header", line)
		}
		headers[len(headers)-1].Value += " " + strings.TrimSpace(line)
		return headers, nil
	}
	idx := strings.IndexByte(line, ':')
	if idx <= 0 || strings.ContainsAny(line[:idx], " 	") {
		return nil, fmt.Errorf("parsing SIP header %q: invalid header", line)
	}
	name := strings.TrimSpace(line[:idx])
	value := strings.TrimSpace(line[idx+1:])
	return append(headers, Header{Name: name, Value: value}), nil
}

func readMessageHeaderBlock(data []byte) (string, []Header, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 1024), max(64*1024, len(data)+1))
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", nil, fmt.Errorf("parsing SIP message: %w", err)
		}
		return "", nil, fmt.Errorf("parsing SIP message: missing start line")
	}
	startLine := scanner.Text()
	headers := make([]Header, 0, 8)
	for scanner.Scan() {
		var err error
		headers, err = appendParsedHeader(headers, scanner.Text())
		if err != nil {
			return "", nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return "", nil, fmt.Errorf("parsing SIP headers: %w", err)
	}
	return startLine, headers, nil
}

func ParseMessage(data []byte) (Message, error) {
	headerBlock, body, err := splitMessageSections(data)
	if err != nil {
		return Message{}, err
	}
	startLine, headers, err := readMessageHeaderBlock(headerBlock)
	if err != nil {
		return Message{}, err
	}
	return Message{
		StartLine: startLine,
		Headers:   headers,
		Body:      append([]byte(nil), body...),
	}, nil
}

func (m *Message) AddHeader(name, value string) {
	m.Headers = append(m.Headers, Header{Name: name, Value: value})
}

func (m Message) Header(name string) string {
	for _, header := range m.Headers {
		if strings.EqualFold(header.Name, name) {
			return header.Value
		}
	}
	return ""
}

func (m Message) HeadersByName(name string) []string {
	var values []string
	for _, header := range m.Headers {
		if strings.EqualFold(header.Name, name) {
			values = append(values, header.Value)
		}
	}
	return values
}

func (m Message) Method() string {
	parts := strings.SplitN(m.StartLine, " ", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func (m Message) IsRequest() bool {
	return !strings.HasPrefix(m.StartLine, "SIP/2.0")
}

func (m Message) StatusCode() int {
	if m.IsRequest() {
		return 0
	}
	parts := strings.SplitN(m.StartLine, " ", 3)
	if len(parts) < 2 {
		return 0
	}
	code, _ := strconv.Atoi(parts[1])
	return code
}

func (m Message) MarshalText() ([]byte, error) {
	return m.Bytes(), nil
}

func (m *Message) UnmarshalText(text []byte) error {
	parsed, err := ParseMessage(text)
	if err != nil {
		return err
	}
	*m = parsed
	return nil
}

type writeCounter struct {
	w io.Writer
	n int64
}

func (w *writeCounter) writeString(value string) error {
	written, err := io.WriteString(w.w, value)
	w.n += int64(written)
	return err
}

func (w *writeCounter) writeBytes(value []byte) error {
	written, err := w.w.Write(value)
	w.n += int64(written)
	return err
}

func (w *writeCounter) writeHeader(header Header) error {
	if err := w.writeString(header.Name); err != nil {
		return err
	}
	if err := w.writeString(": "); err != nil {
		return err
	}
	if err := w.writeString(header.Value); err != nil {
		return err
	}
	return w.writeString("\r\n")
}

func (m Message) serializedHeaders() []Header {
	headers := append([]Header(nil), m.Headers...)
	for _, header := range headers {
		if strings.EqualFold(header.Name, "Content-Length") {
			return headers
		}
	}
	return append(headers, Header{Name: "Content-Length", Value: strconv.Itoa(len(m.Body))})
}

func (m Message) WriteTo(w io.Writer) (n int64, err error) {
	counter := writeCounter{w: w}
	if err := counter.writeString(m.StartLine); err != nil {
		return counter.n, err
	}
	if err := counter.writeString("\r\n"); err != nil {
		return counter.n, err
	}
	for _, header := range m.serializedHeaders() {
		if err := counter.writeHeader(header); err != nil {
			return counter.n, err
		}
	}
	if err := counter.writeString("\r\n"); err != nil {
		return counter.n, err
	}
	if err := counter.writeBytes(m.Body); err != nil {
		return counter.n, err
	}
	return counter.n, nil
}

func (m Message) Bytes() []byte {
	var buf bytes.Buffer
	_, _ = m.WriteTo(&buf)
	return buf.Bytes()
}
