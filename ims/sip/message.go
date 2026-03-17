package sip

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"strconv"
	"strings"
)

type Header struct {
	Name  string
	Value string
}

type Headers []Header

type Message struct {
	StartLine string
	Headers   Headers
	Body      []byte
}

func NewRequest(method, uri string) Message {
	return Message{StartLine: fmt.Sprintf("%s %s SIP/2.0", method, uri)}
}

func NewResponse(code int, reason string) Message {
	return Message{StartLine: fmt.Sprintf("SIP/2.0 %d %s", code, reason)}
}

func ParseMessage(data []byte) (Message, error) {
	var msg Message
	if err := msg.parseBytes(data); err != nil {
		return Message{}, err
	}
	return msg, nil
}

func (hs Headers) Get(name string) string {
	for _, header := range hs {
		if strings.EqualFold(header.Name, name) {
			return header.Value
		}
	}
	return ""
}

func (hs Headers) Values(name string) []string {
	values := make([]string, 0, 1)
	for _, header := range hs {
		if strings.EqualFold(header.Name, name) {
			values = append(values, header.Value)
		}
	}
	return values
}

func (hs Headers) Has(name string) bool {
	for _, header := range hs {
		if strings.EqualFold(header.Name, name) {
			return true
		}
	}
	return false
}

func (hs Headers) Clone() Headers {
	if len(hs) == 0 {
		return nil
	}
	cloned := make(Headers, len(hs))
	copy(cloned, hs)
	return cloned
}

func (hs *Headers) Add(name, value string) {
	*hs = append(*hs, Header{Name: name, Value: value})
}

func (hs *Headers) Set(name, value string) {
	hs.Del(name)
	hs.Add(name, value)
}

func (hs *Headers) Del(name string) {
	if len(*hs) == 0 {
		return
	}
	dst := (*hs)[:0]
	for _, header := range *hs {
		if strings.EqualFold(header.Name, name) {
			continue
		}
		dst = append(dst, header)
	}
	*hs = dst
}

func (hs Headers) MarshalText() ([]byte, error) {
	var buf bytes.Buffer
	_, err := hs.WriteTo(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (hs *Headers) UnmarshalText(text []byte) error {
	parsed, err := parseHeaderBlock(text)
	if err != nil {
		return err
	}
	*hs = parsed
	return nil
}

func (hs Headers) WriteTo(w io.Writer) (int64, error) {
	counter := writeCounter{w: w}
	for _, header := range hs {
		if err := counter.writeHeader(header); err != nil {
			return counter.n, err
		}
	}
	return counter.n, nil
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

func (m Message) Header(name string) string {
	return m.Headers.Get(name)
}

func (m Message) HeadersByName(name string) []string {
	return m.Headers.Values(name)
}

func (m Message) Bytes() []byte {
	var buf bytes.Buffer
	_, _ = m.WriteTo(&buf)
	return buf.Bytes()
}

func (m Message) MarshalText() ([]byte, error) {
	return m.Bytes(), nil
}

func (m *Message) UnmarshalText(text []byte) error {
	return m.parseBytes(text)
}

func (m Message) WriteTo(w io.Writer) (int64, error) {
	counter := writeCounter{w: w}
	if err := counter.writeString(m.StartLine); err != nil {
		return counter.n, err
	}
	if err := counter.writeString("\r\n"); err != nil {
		return counter.n, err
	}
	headers := m.serializedHeaders()
	if _, err := headers.WriteTo(&counter); err != nil {
		return counter.n, err
	}
	if err := counter.writeString("\r\n"); err != nil {
		return counter.n, err
	}
	if err := counter.writeBytes(m.Body); err != nil {
		return counter.n, err
	}
	return counter.n, nil
}

func (m *Message) ReadFrom(r io.Reader) (int64, error) {
	br := bufio.NewReader(r)
	startLine, headers, n, err := readHeaderSection(br)
	if err != nil {
		return n, err
	}
	body, bodyN, err := readBody(br, headers)
	n += bodyN
	if err != nil {
		return n, err
	}
	m.StartLine = startLine
	m.Headers = headers
	m.Body = body
	return n, nil
}

func PendingKey(msg Message) string {
	if branch := TopViaBranch(msg.Header("Via")); branch != "" {
		if method := CSeqMethod(msg.Header("CSeq")); method != "" {
			return branch + "|" + method
		}
	}
	return msg.Header("Call-ID") + "|" + msg.Header("CSeq")
}

func ResponseHeaders(req Message, code int) Headers {
	to := req.Header("To")
	if code != 100 && to != "" {
		to = WithTag(to, "", ResponseTag(req))
	}
	vias := req.HeadersByName("Via")
	headers := make(Headers, 0, len(vias)+4)
	for _, via := range vias {
		headers = append(headers, Header{Name: "Via", Value: via})
	}
	headers = append(headers,
		Header{Name: "From", Value: req.Header("From")},
		Header{Name: "To", Value: to},
		Header{Name: "Call-ID", Value: req.Header("Call-ID")},
		Header{Name: "CSeq", Value: req.Header("CSeq")},
	)
	return headers
}

func ResponseTag(req Message) string {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(req.Method()))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(req.Header("Via")))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(req.Header("Call-ID")))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(req.Header("CSeq")))
	return fmt.Sprintf("%016x", hash.Sum64())
}

func RequestURI(msg Message) string {
	parts := strings.SplitN(msg.StartLine, " ", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

func SetRequestURI(msg *Message, uri string) {
	parts := strings.SplitN(msg.StartLine, " ", 3)
	if len(parts) != 3 {
		return
	}
	parts[1] = uri
	msg.StartLine = strings.Join(parts, " ")
}

func AddressURI(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if left := strings.IndexByte(value, '<'); left >= 0 {
		right := strings.IndexByte(value[left+1:], '>')
		if right >= 0 {
			return strings.TrimSpace(value[left+1 : left+1+right])
		}
	}
	if idx := strings.IndexByte(value, ';'); idx >= 0 {
		return strings.TrimSpace(value[:idx])
	}
	return value
}

func HeaderTag(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, part := range strings.Split(value, ";") {
		name, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(name, "tag") {
			return strings.Trim(strings.TrimSpace(val), `"`)
		}
	}
	return ""
}

func WithTag(headerValue, fallbackURI, tag string) string {
	base := strings.TrimSpace(headerValue)
	if base == "" {
		base = fmt.Sprintf("<%s>", fallbackURI)
	}
	if strings.Contains(strings.ToLower(base), ";tag=") {
		return base
	}
	return base + ";tag=" + tag
}

func UpsertHeader(headers Headers, name, value string) Headers {
	for i, header := range headers {
		if strings.EqualFold(header.Name, name) {
			headers[i].Value = value
			return headers
		}
	}
	return append(headers, Header{Name: name, Value: value})
}

func CSeqNumber(value string) int64 {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) == 0 {
		return 0
	}
	n, _ := strconv.ParseInt(fields[0], 10, 64)
	return n
}

func CSeqMethod(value string) string {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) < 2 {
		return ""
	}
	return fields[1]
}

func TopViaBranch(value string) string {
	return viaParam(topViaValue(value), "branch")
}

func TopViaReceived(value string) string {
	return viaParam(topViaValue(value), "received")
}

func TopViaRPort(value string) string {
	return viaParam(topViaValue(value), "rport")
}

func TopViaHasRPort(value string) bool {
	_, ok := topViaParam(topViaValue(value), "rport")
	return ok
}

func TopViaSentBy(value string) string {
	fields := strings.Fields(topViaValue(value))
	if len(fields) < 2 {
		return ""
	}
	sentBy, _, _ := strings.Cut(fields[1], ";")
	return strings.TrimSpace(sentBy)
}

func TokenListContains(value, want string) bool {
	for _, token := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(token), want) {
			return true
		}
	}
	return false
}

func topViaValue(value string) string {
	value, _, _ = strings.Cut(value, ",")
	return strings.TrimSpace(value)
}

func viaParam(value, want string) string {
	param, _ := topViaParam(value, want)
	return param
}

func topViaParam(value, want string) (string, bool) {
	idx := strings.IndexByte(value, ';')
	if idx < 0 {
		return "", false
	}
	for _, field := range strings.Split(value[idx+1:], ";") {
		name, rawValue, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !strings.EqualFold(name, want) {
			continue
		}
		if !ok {
			return "", true
		}
		return strings.Trim(strings.TrimSpace(rawValue), `"`), true
	}
	return "", false
}

func (m *Message) parseBytes(data []byte) error {
	headerBlock, body, err := splitMessageSections(data)
	if err != nil {
		return err
	}
	startLine, headers, err := parseMessageHeaderBlock(headerBlock)
	if err != nil {
		return err
	}
	m.StartLine = startLine
	m.Headers = headers
	m.Body = append([]byte(nil), body...)
	return nil
}

func splitMessageSections(data []byte) ([]byte, []byte, error) {
	parts := bytes.SplitN(data, []byte("\r\n\r\n"), 2)
	if len(parts) != 2 {
		return nil, nil, errors.New("parsing SIP message: missing header separator")
	}
	return parts[0], parts[1], nil
}

func parseHeaderBlock(data []byte) (Headers, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 1024), max(64*1024, len(data)+1))
	headers := make(Headers, 0, 8)
	for scanner.Scan() {
		var err error
		headers, err = appendParsedHeader(headers, scanner.Text())
		if err != nil {
			return nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parsing SIP headers: %w", err)
	}
	return headers, nil
}

func parseMessageHeaderBlock(data []byte) (string, Headers, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 1024), max(64*1024, len(data)+1))
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", nil, fmt.Errorf("parsing SIP message: %w", err)
		}
		return "", nil, errors.New("parsing SIP message: missing start line")
	}
	startLine := scanner.Text()
	headers := make(Headers, 0, 8)
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

func appendParsedHeader(headers Headers, line string) (Headers, error) {
	if line == "" {
		return headers, nil
	}
	if line[0] == ' ' || line[0] == '\t' {
		if len(headers) == 0 {
			return nil, fmt.Errorf("parsing SIP header %q: missing previous header", line)
		}
		headers[len(headers)-1].Value += " " + strings.TrimSpace(line)
		return headers, nil
	}
	idx := strings.IndexByte(line, ':')
	if idx <= 0 || strings.ContainsAny(line[:idx], " \t") {
		return nil, fmt.Errorf("parsing SIP header %q: invalid header", line)
	}
	name := strings.TrimSpace(line[:idx])
	value := strings.TrimSpace(line[idx+1:])
	return append(headers, Header{Name: name, Value: value}), nil
}

func readHeaderSection(br *bufio.Reader) (string, Headers, int64, error) {
	startLine, n, err := readLine(br)
	if err != nil {
		if err == io.EOF {
			return "", nil, n, errors.New("parsing SIP message: missing start line")
		}
		return "", nil, n, fmt.Errorf("parsing SIP message: %w", err)
	}
	headers := make(Headers, 0, 8)
	total := n
	for {
		line, lineN, err := readLine(br)
		total += lineN
		if err != nil {
			return "", nil, total, fmt.Errorf("parsing SIP headers: %w", err)
		}
		if line == "" {
			return startLine, headers, total, nil
		}
		headers, err = appendParsedHeader(headers, line)
		if err != nil {
			return "", nil, total, err
		}
	}
}

func readLine(br *bufio.Reader) (string, int64, error) {
	line, err := br.ReadString('\n')
	consumed := int64(len(line))
	if err != nil {
		return "", consumed, err
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, consumed, nil
}

func readBody(br *bufio.Reader, headers Headers) ([]byte, int64, error) {
	lengthValue := strings.TrimSpace(headers.Get("Content-Length"))
	if lengthValue == "" {
		body, err := io.ReadAll(br)
		return body, int64(len(body)), err
	}
	length, err := strconv.Atoi(lengthValue)
	if err != nil {
		return nil, 0, fmt.Errorf("parsing Content-Length %q: %w", lengthValue, err)
	}
	if length < 0 {
		return nil, 0, fmt.Errorf("parsing Content-Length %q: negative value", lengthValue)
	}
	body := make([]byte, length)
	n, err := io.ReadFull(br, body)
	if err != nil {
		return nil, int64(n), err
	}
	return body, int64(n), nil
}

func (m Message) serializedHeaders() Headers {
	headers := m.Headers.Clone()
	for _, header := range headers {
		if strings.EqualFold(header.Name, "Content-Length") {
			return headers
		}
	}
	return append(headers, Header{Name: "Content-Length", Value: strconv.Itoa(len(m.Body))})
}

type writeCounter struct {
	w io.Writer
	n int64
}

func (w *writeCounter) Write(data []byte) (int, error) {
	written, err := w.w.Write(data)
	w.n += int64(written)
	return written, err
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
