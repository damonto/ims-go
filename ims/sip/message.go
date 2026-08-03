package sip

import (
	"bufio"
	"bytes"
	"encoding"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
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

var (
	_ encoding.TextMarshaler   = Headers{}
	_ encoding.TextUnmarshaler = (*Headers)(nil)
	_ encoding.TextAppender    = Headers{}
	_ io.WriterTo              = Headers{}

	_ encoding.BinaryAppender    = Message{}
	_ encoding.BinaryMarshaler   = Message{}
	_ encoding.BinaryUnmarshaler = (*Message)(nil)
	_ io.WriterTo                = Message{}
)

func NewRequest(method, uri string) Message {
	return Message{StartLine: fmt.Sprintf("%s %s SIP/2.0", method, uri)}
}

func NewResponse(code int, reason string) Message {
	return Message{StartLine: fmt.Sprintf("SIP/2.0 %d %s", code, reason)}
}

func ParseMessage(data []byte) (Message, error) {
	var msg Message
	if err := msg.UnmarshalBinary(data); err != nil {
		return Message{}, err
	}
	return msg, nil
}

// ParseMessagePartial preserves a syntactically valid start-line and header
// section when body framing fails. It is intended for protocol error responses;
// callers must not dispatch a message returned with a non-nil error.
func ParseMessagePartial(data []byte) (Message, error) {
	var msg Message
	err := msg.parseBytes(data)
	return msg, err
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
	return hs.AppendText(nil)
}

func (hs Headers) AppendText(dst []byte) ([]byte, error) {
	if err := hs.validate(); err != nil {
		return nil, err
	}
	for _, header := range hs {
		dst = append(dst, header.Name...)
		dst = append(dst, ':', ' ')
		dst = append(dst, header.Value...)
		dst = append(dst, '\r', '\n')
	}
	return dst, nil
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
	if err := hs.validate(); err != nil {
		return 0, err
	}
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
	version, _, _ := strings.Cut(m.StartLine, " ")
	return !strings.EqualFold(version, "SIP/2.0")
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

func (m Message) ReasonPhrase() string {
	if m.IsRequest() {
		return ""
	}
	parts := strings.SplitN(m.StartLine, " ", 3)
	if len(parts) < 3 {
		return ""
	}
	return strings.TrimSpace(parts[2])
}

func (m Message) Header(name string) string {
	return m.Headers.Get(name)
}

func (m Message) HeadersByName(name string) []string {
	return m.Headers.Values(name)
}

// HeaderHasToken reports whether any occurrence of a comma-separated header
// contains want. SIP permits list-valued fields to be split across lines.
func (m Message) HeaderHasToken(name, want string) bool {
	for _, value := range m.Headers.Values(name) {
		if TokenListContains(value, want) {
			return true
		}
	}
	return false
}

// HeaderList returns all comma-separated values for a list-valued field in
// wire order, including values spread across repeated header lines.
func (m Message) HeaderList(name string) []string {
	values := make([]string, 0, len(m.Headers.Values(name)))
	for _, value := range m.Headers.Values(name) {
		values = append(values, SplitHeaderList(value)...)
	}
	return values
}

// Validate checks the core fields required before a SIP message enters
// transaction processing. Parsing and validation stay separate so callers can
// still inspect a syntactically readable malformed message.
func (m Message) Validate() error {
	if err := validateStartLine(m.StartLine); err != nil {
		return err
	}
	required := []string{"Via", "From", "To", "Call-ID", "CSeq"}
	if m.IsRequest() {
		required = append(required, "Max-Forwards")
	}
	for _, name := range required {
		values := m.Headers.Values(name)
		if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
			return fmt.Errorf("validating SIP message: missing %s header", name)
		}
		if name != "Via" && len(values) != 1 {
			return fmt.Errorf("validating SIP message: multiple %s headers", name)
		}
	}
	if m.IsRequest() {
		if _, err := strconv.ParseUint(strings.TrimSpace(m.Header("Max-Forwards")), 10, 32); err != nil {
			return fmt.Errorf("validating SIP Max-Forwards %q: %w", m.Header("Max-Forwards"), err)
		}
		if !strings.EqualFold(CSeqMethod(m.Header("CSeq")), m.Method()) {
			return fmt.Errorf("validating SIP message: CSeq method %q does not match %q", CSeqMethod(m.Header("CSeq")), m.Method())
		}
	}
	cseqFields := strings.Fields(m.Header("CSeq"))
	if len(cseqFields) != 2 {
		return fmt.Errorf("validating SIP CSeq %q: expected number and method", m.Header("CSeq"))
	}
	if !isSIPToken(cseqFields[1]) {
		return fmt.Errorf("validating SIP CSeq method %q: invalid method", cseqFields[1])
	}
	if _, err := strconv.ParseUint(cseqFields[0], 10, 31); err != nil {
		return fmt.Errorf("validating SIP CSeq %q: %w", m.Header("CSeq"), err)
	}
	return nil
}

func (m Message) MarshalBinary() ([]byte, error) {
	return m.AppendBinary(nil)
}

func (m Message) AppendBinary(dst []byte) ([]byte, error) {
	if err := validateStartLine(m.StartLine); err != nil {
		return nil, err
	}
	headers := m.serializedHeaders()
	if err := headers.validate(); err != nil {
		return nil, err
	}
	dst = append(dst, m.StartLine...)
	dst = append(dst, '\r', '\n')
	dst, err := headers.AppendText(dst)
	if err != nil {
		return nil, err
	}
	dst = append(dst, '\r', '\n')
	dst = append(dst, m.Body...)
	return dst, nil
}

func (m *Message) UnmarshalBinary(data []byte) error {
	return m.parseBytes(data)
}

func (m Message) WriteTo(w io.Writer) (int64, error) {
	if err := validateStartLine(m.StartLine); err != nil {
		return 0, err
	}
	headers := m.serializedHeaders()
	if err := headers.validate(); err != nil {
		return 0, err
	}
	counter := writeCounter{w: w}
	if err := counter.writeString(m.StartLine); err != nil {
		return counter.n, err
	}
	if err := counter.writeString("\r\n"); err != nil {
		return counter.n, err
	}
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

// ReadMessage reads exactly one Content-Length-framed SIP message from r.
func (m *Message) ReadMessage(r io.Reader) (int64, error) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		// A temporary buffered reader must not read into the next SIP message.
		// Limiting each underlying read keeps unread bytes with the caller.
		br = bufio.NewReader(&singleByteReader{r: r})
	}
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
	if left, right, ok := nameAddrBounds(value); ok {
		return strings.TrimSpace(value[left+1 : right])
	}
	if idx := strings.IndexByte(value, ';'); idx >= 0 {
		return strings.TrimSpace(value[:idx])
	}
	return value
}

// AddressURIAndParams returns the address URI and header parameters from a SIP
// name-addr or addr-spec value.
func AddressURIAndParams(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	if left, right, ok := nameAddrBounds(value); ok {
		return strings.TrimSpace(value[left+1 : right]), value[right+1:]
	}
	if semi := strings.IndexByte(value, ';'); semi >= 0 {
		return strings.TrimSpace(value[:semi]), value[semi:]
	}
	return value, ""
}

// SplitHeaderList splits comma-separated SIP header values without splitting
// inside quoted strings or name-addr brackets.
func SplitHeaderList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parts := make([]string, 0, 1)
	start := 0
	inQuote := false
	escaped := false
	angleDepth := 0
	commentDepth := 0
	for i := range len(value) {
		if escaped {
			escaped = false
			continue
		}
		switch value[i] {
		case '\\':
			if inQuote || commentDepth > 0 {
				escaped = true
			}
		case '"':
			if commentDepth == 0 {
				inQuote = !inQuote
			}
		case '(':
			if !inQuote {
				commentDepth++
			}
		case ')':
			if !inQuote && commentDepth > 0 {
				commentDepth--
			}
		case '<':
			if !inQuote && commentDepth == 0 {
				angleDepth++
			}
		case '>':
			if !inQuote && commentDepth == 0 && angleDepth > 0 {
				angleDepth--
			}
		case ',':
			if !inQuote && commentDepth == 0 && angleDepth == 0 {
				part := strings.TrimSpace(value[start:i])
				if part != "" {
					parts = append(parts, part)
				}
				start = i + 1
			}
		}
	}
	if tail := strings.TrimSpace(value[start:]); tail != "" {
		parts = append(parts, tail)
	}
	return parts
}

// HeaderParam returns a semicolon parameter value using SIP's case-insensitive
// parameter names.
func HeaderParam(params, name string) string {
	value, _ := headerParam(params, name)
	return value
}

func headerParam(params, name string) (string, bool) {
	for _, part := range splitSemicolonParams(params) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), name) {
			continue
		}
		return unquoteSIPString(strings.TrimSpace(value)), true
	}
	return "", false
}

func HeaderTag(value string) string {
	_, params := AddressURIAndParams(value)
	return HeaderParam(params, "tag")
}

func WithTag(headerValue, fallbackURI, tag string) string {
	base := strings.TrimSpace(headerValue)
	if base == "" {
		base = fmt.Sprintf("<%s>", fallbackURI)
	}
	if _, ok := headerParam(addressHeaderParams(base), "tag"); ok {
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

func TopViaKeep(value string) string {
	return viaParam(topViaValue(value), "keep")
}

func TopViaHasKeep(value string) bool {
	_, ok := topViaParam(topViaValue(value), "keep")
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

// SetResponseViaPeer records the packet source in the response's top Via.
// RFC 3261 uses received, and RFC 3581 uses rport, to route responses through
// address and port translation without trusting the request's sent-by value.
func SetResponseViaPeer(resp *Message, peer net.Addr) {
	host, port, udp := sipPeerAddress(peer)
	if host == "" {
		return
	}
	for i := range resp.Headers {
		if !strings.EqualFold(resp.Headers[i].Name, "Via") {
			continue
		}
		top, rest, found := strings.Cut(resp.Headers[i].Value, ",")
		if sentByHost(TopViaSentBy(top)) != host {
			top = upsertViaParam(top, "received", host)
		}
		if udp && TopViaHasRPort(top) {
			top = upsertViaParam(top, "rport", strconv.Itoa(port))
		}
		if found {
			resp.Headers[i].Value = top + "," + rest
		} else {
			resp.Headers[i].Value = top
		}
		return
	}
}

func sipPeerAddress(peer net.Addr) (host string, port int, udp bool) {
	switch addr := peer.(type) {
	case *net.UDPAddr:
		return addr.IP.String(), addr.Port, true
	case *net.TCPAddr:
		return addr.IP.String(), addr.Port, false
	default:
		return "", 0, false
	}
}

func sentByHost(sentBy string) string {
	host, _, err := net.SplitHostPort(sentBy)
	if err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(sentBy, "[]")
}

func upsertViaParam(via, name, value string) string {
	fields := splitSemicolonParams(via)
	for i := 1; i < len(fields); i++ {
		key, _, _ := strings.Cut(strings.TrimSpace(fields[i]), "=")
		if strings.EqualFold(key, name) {
			fields[i] = name + "=" + value
			return strings.Join(fields, ";")
		}
	}
	return via + ";" + name + "=" + value
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
	_, after, ok := strings.Cut(value, ";")
	if !ok {
		return "", false
	}
	for _, field := range splitSemicolonParams(after) {
		name, rawValue, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !strings.EqualFold(name, want) {
			continue
		}
		if !ok {
			return "", true
		}
		return unquoteSIPString(strings.TrimSpace(rawValue)), true
	}
	return "", false
}

func (m *Message) parseBytes(data []byte) error {
	data = trimLeadingCRLF(data)
	headerBlock, body, err := splitMessageSections(data)
	if err != nil {
		return err
	}
	startLine, headers, err := parseMessageHeaderBlock(headerBlock)
	if err != nil {
		return err
	}
	if err := validateStartLine(startLine); err != nil {
		return err
	}
	m.StartLine = startLine
	m.Headers = headers
	body, err = bodyFromContentLength(body, headers)
	if err != nil {
		return err
	}
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
	if err := validateCRLFBlock(data); err != nil {
		return nil, err
	}
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
	if err := validateCRLFBlock(data); err != nil {
		return "", nil, err
	}
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
	if idx <= 0 || !isSIPToken(line[:idx]) {
		return nil, fmt.Errorf("parsing SIP header %q: invalid header", line)
	}
	name := strings.TrimSpace(line[:idx])
	value := strings.TrimSpace(line[idx+1:])
	return append(headers, Header{Name: expandedHeaderName(name), Value: value}), nil
}

func expandedHeaderName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "a":
		return "Accept-Contact"
	case "b":
		return "Referred-By"
	case "c":
		return "Content-Type"
	case "d":
		return "Request-Disposition"
	case "e":
		return "Content-Encoding"
	case "f":
		return "From"
	case "i":
		return "Call-ID"
	case "j":
		return "Reject-Contact"
	case "k":
		return "Supported"
	case "l":
		return "Content-Length"
	case "m":
		return "Contact"
	case "o":
		return "Event"
	case "r":
		return "Refer-To"
	case "s":
		return "Subject"
	case "t":
		return "To"
	case "u":
		return "Allow-Events"
	case "v":
		return "Via"
	case "x":
		return "Session-Expires"
	default:
		return name
	}
}

func readHeaderSection(br *bufio.Reader) (string, Headers, int64, error) {
	var total int64
	var startLine string
	for startLine == "" {
		line, n, err := readLine(br)
		total += n
		if err != nil {
			if err == io.EOF {
				return "", nil, total, errors.New("parsing SIP message: missing start line")
			}
			return "", nil, total, fmt.Errorf("parsing SIP message: %w", err)
		}
		startLine = line
	}
	if err := validateStartLine(startLine); err != nil {
		return "", nil, total, err
	}
	headers := make(Headers, 0, 8)
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
	if !strings.HasSuffix(line, "\r\n") {
		return "", consumed, errors.New("parsing SIP message: line is not terminated by CRLF")
	}
	return strings.TrimSuffix(line, "\r\n"), consumed, nil
}

func readBody(br *bufio.Reader, headers Headers) ([]byte, int64, error) {
	length, ok, err := contentLength(headers)
	if err != nil {
		return nil, 0, err
	}
	if !ok {
		return nil, 0, errors.New("parsing SIP stream: missing Content-Length")
	}
	body := make([]byte, length)
	n, err := io.ReadFull(br, body)
	if err != nil {
		return nil, int64(n), err
	}
	return body, int64(n), nil
}

func bodyFromContentLength(body []byte, headers Headers) ([]byte, error) {
	length, ok, err := contentLength(headers)
	if err != nil {
		return nil, err
	}
	if !ok {
		return body, nil
	}
	if length > len(body) {
		return nil, fmt.Errorf("parsing SIP body: Content-Length %d exceeds available body %d", length, len(body))
	}
	return body[:length], nil
}

func contentLength(headers Headers) (int, bool, error) {
	values := headers.Values("Content-Length")
	if len(values) == 0 {
		return 0, false, nil
	}
	if len(values) > 1 {
		return 0, true, errors.New("parsing SIP headers: multiple Content-Length fields")
	}
	lengthValue := strings.TrimSpace(values[0])
	if lengthValue == "" {
		return 0, true, errors.New("parsing Content-Length: empty value")
	}
	length, err := strconv.Atoi(lengthValue)
	if err != nil {
		return 0, true, fmt.Errorf("parsing Content-Length %q: %w", lengthValue, err)
	}
	if length < 0 {
		return 0, true, fmt.Errorf("parsing Content-Length %q: negative value", lengthValue)
	}
	return length, true, nil
}

func (m Message) serializedHeaders() Headers {
	headers := make(Headers, 0, len(m.Headers)+1)
	found := false
	for _, header := range m.Headers {
		if strings.EqualFold(expandedHeaderName(header.Name), "Content-Length") {
			if found {
				continue
			}
			header.Value = strconv.Itoa(len(m.Body))
			found = true
		}
		headers = append(headers, header)
	}
	if found {
		return headers
	}
	return append(headers, Header{Name: "Content-Length", Value: strconv.Itoa(len(m.Body))})
}

func validateStartLine(line string) error {
	if strings.ContainsAny(line, "\r\n") {
		return errors.New("parsing SIP message: invalid start line")
	}
	if strings.HasPrefix(strings.ToUpper(line), "SIP/2.0 ") {
		parts := strings.SplitN(line, " ", 3)
		if len(parts) != 3 {
			return fmt.Errorf("parsing SIP status line %q: invalid status line", line)
		}
		if len(parts[1]) != 3 {
			return fmt.Errorf("parsing SIP status code %q: expected three digits", parts[1])
		}
		if _, err := strconv.Atoi(parts[1]); err != nil {
			return fmt.Errorf("parsing SIP status code %q: %w", parts[1], err)
		}
		return nil
	}
	parts := strings.Split(line, " ")
	if len(parts) != 3 || !isSIPToken(parts[0]) || parts[1] == "" || strings.ContainsAny(parts[1], "\x00\r\n\t") || !strings.EqualFold(parts[2], "SIP/2.0") {
		return fmt.Errorf("parsing SIP request line %q: invalid request line", line)
	}
	return nil
}

func validateCRLFBlock(data []byte) error {
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '\r':
			if i+1 >= len(data) || data[i+1] != '\n' {
				return errors.New("parsing SIP headers: CR is not followed by LF")
			}
			i++
		case '\n':
			return errors.New("parsing SIP headers: LF is not preceded by CR")
		}
	}
	return nil
}

func (hs Headers) validate() error {
	for _, header := range hs {
		if !isSIPToken(header.Name) {
			return fmt.Errorf("marshaling SIP header %q: invalid name", header.Name)
		}
		if strings.ContainsAny(header.Value, "\r\n") {
			return fmt.Errorf("marshaling SIP header %q: value contains CR or LF", header.Name)
		}
	}
	return nil
}

func isSIPToken(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		b := value[i]
		if b <= 0x20 || b >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={} ", rune(b)) {
			return false
		}
	}
	return true
}

func addressHeaderParams(value string) string {
	_, params := AddressURIAndParams(value)
	return params
}

func nameAddrBounds(value string) (left, right int, ok bool) {
	inQuote := false
	escaped := false
	commentDepth := 0
	left = -1
	for i := range len(value) {
		if escaped {
			escaped = false
			continue
		}
		switch value[i] {
		case '\\':
			if inQuote || commentDepth > 0 {
				escaped = true
			}
		case '"':
			if commentDepth == 0 {
				inQuote = !inQuote
			}
		case '(':
			if !inQuote {
				commentDepth++
			}
		case ')':
			if !inQuote && commentDepth > 0 {
				commentDepth--
			}
		case '<':
			if !inQuote && commentDepth == 0 && left < 0 {
				left = i
			}
		case '>':
			if !inQuote && commentDepth == 0 && left >= 0 {
				return left, i, true
			}
		}
	}
	return 0, 0, false
}

func splitSemicolonParams(value string) []string {
	parts := make([]string, 0, 2)
	start := 0
	inQuote := false
	escaped := false
	for i := range len(value) {
		if escaped {
			escaped = false
			continue
		}
		switch value[i] {
		case '\\':
			if inQuote {
				escaped = true
			}
		case '"':
			inQuote = !inQuote
		case ';':
			if !inQuote {
				parts = append(parts, value[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, value[start:])
}

type singleByteReader struct {
	r io.Reader
}

func (r *singleByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.r.Read(p)
}

func trimLeadingCRLF(data []byte) []byte {
	for bytes.HasPrefix(data, []byte("\r\n")) {
		data = data[2:]
	}
	return data
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
