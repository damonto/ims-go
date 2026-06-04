package at

import (
	"bufio"
	"bytes"
	"context"
	"encoding"
	"errors"
	"io"
	"strings"
	"testing"
)

var (
	_ encoding.TextMarshaler   = CSIMCommand(nil)
	_ encoding.TextMarshaler   = CSIMResponse(nil)
	_ encoding.TextUnmarshaler = (*CSIMResponse)(nil)
)

type scriptPort struct {
	readData string
	written  []byte
	closed   bool
}

func (p *scriptPort) Read(buf []byte) (int, error) {
	if len(p.readData) == 0 {
		return 0, io.EOF
	}
	n := copy(buf, p.readData)
	p.readData = p.readData[n:]
	return n, nil
}

func (p *scriptPort) Write(data []byte) (int, error) {
	p.written = append(p.written, data...)
	return len(data), nil
}

func (p *scriptPort) Close() error {
	p.closed = true
	return nil
}

type partialWritePort struct {
	readData string
	written  bytes.Buffer
	max      int
}

func (p *partialWritePort) Read(buf []byte) (int, error) {
	if len(p.readData) == 0 {
		return 0, io.EOF
	}
	n := copy(buf, p.readData)
	p.readData = p.readData[n:]
	return n, nil
}

func (p *partialWritePort) Write(data []byte) (int, error) {
	if len(data) > p.max {
		data = data[:p.max]
	}
	return p.written.Write(data)
}

func (p *partialWritePort) Close() error {
	return nil
}

func TestCSIMResponseUnmarshalText(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr bool
	}{
		{name: "prefixed", input: "+CMTI: \"SM\",1\n+CSIM: 4,\"9000\"", want: []byte{0x90, 0x00}},
		{name: "multiline body", input: "noise\n+CSIM: 12,\"DEADBEEF9000\"", want: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x90, 0x00}},
		{name: "bare hex", input: "+CMTI: \"SM\",1\n9000", want: []byte{0x90, 0x00}},
		{name: "bare quoted hex", input: `"9000"`, want: []byte{0x90, 0x00}},
		{name: "bare length and quoted hex", input: `4,"9000"`, want: []byte{0x90, 0x00}},
		{name: "bare length and hex", input: `4,9000`, want: []byte{0x90, 0x00}},
		{name: "prefixed unquoted hex", input: `+CSIM: 4,9000`, want: []byte{0x90, 0x00}},
		{name: "bad length", input: `+CSIM: 6,"9000"`, wantErr: true},
		{name: "bad hex", input: `+CSIM: 4,"90GG"`, wantErr: true},
		{name: "missing comma", input: `+CSIM: 4 "9000"`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var response CSIMResponse
			err := response.UnmarshalText([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalText() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			got, err := response.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("MarshalBinary() = % X, want % X", got, tt.want)
			}
		})
	}
}

func TestCSIMResponseMarshalText(t *testing.T) {
	response := CSIMResponse{0x90, 0x00}
	got, err := response.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	if string(got) != `4,"9000"` {
		t.Fatalf("MarshalText() = %q, want %q", string(got), `4,"9000"`)
	}
}

func TestCSIMResponseMarshalBinaryRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "status only", data: []byte{0x90, 0x00}},
		{name: "payload", data: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x90, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var response CSIMResponse
			if err := response.UnmarshalBinary(tt.data); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			got, err := response.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if string(got) != string(tt.data) {
				t.Fatalf("MarshalBinary() = % X, want % X", got, tt.data)
			}
		})
	}
}

func TestCSIMResponseUnmarshalTextReportsBareDecodeError(t *testing.T) {
	var response CSIMResponse
	err := response.UnmarshalText([]byte("not-hex"))
	if err == nil {
		t.Fatal("UnmarshalText() error = nil, want error")
	}
	if !strings.Contains(err.Error(), `"not-hex"`) {
		t.Fatalf("UnmarshalText() error = %q, want line context", err.Error())
	}
	if !strings.Contains(err.Error(), "invalid CSIM response data") {
		t.Fatalf("UnmarshalText() error = %q, want data error", err.Error())
	}
}

func TestCSIMResponseUnmarshalTextRejectsBareShortResponse(t *testing.T) {
	var response CSIMResponse
	err := response.UnmarshalText([]byte("90"))
	if err == nil {
		t.Fatal("UnmarshalText() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "missing response status word") {
		t.Fatalf("UnmarshalText() error = %q, want status word error", err.Error())
	}
}

func TestCSIMResponseUnmarshalTextRejectsUnknownBareStatusWord(t *testing.T) {
	var response CSIMResponse
	err := response.UnmarshalText([]byte("DEADBEEF"))
	if err == nil {
		t.Fatal("UnmarshalText() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "unrecognized APDU status word") {
		t.Fatalf("UnmarshalText() error = %q, want status word error", err.Error())
	}
}

func TestCSIMCommandMarshalText(t *testing.T) {
	command, err := newCSIMCommand([]byte{0x00, 0xC0, 0x00, 0x00, 0x10})
	if err != nil {
		t.Fatalf("newCSIMCommand() error = %v", err)
	}

	got, err := command.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	if string(got) != `AT+CSIM=10,"00C0000010"` {
		t.Fatalf("MarshalText() = %q, want %q", string(got), `AT+CSIM=10,"00C0000010"`)
	}
}

func TestDefaultInitCommands(t *testing.T) {
	got := defaultInitCommands()
	want := []string{"AT", "ATE0", "AT+CMEE=2"}
	if len(got) != len(want) {
		t.Fatalf("defaultInitCommands() len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("defaultInitCommands()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestBaudRateOrDefault(t *testing.T) {
	tests := []struct {
		name string
		baud int
		want int
	}{
		{name: "default", want: defaultBaudRate},
		{name: "custom", baud: 230400, want: 230400},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := baudRateOrDefault(tt.baud); got != tt.want {
				t.Fatalf("baudRateOrDefault() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestReaderInit(t *testing.T) {
	tests := []struct {
		name      string
		ctx       context.Context
		response  string
		wantWrite string
		wantErr   error
	}{
		{
			name:      "runs default commands",
			ctx:       context.Background(),
			response:  "AT\r\nOK\r\nATE0\r\nOK\r\nAT+CMEE=2\r\nOK\r\n",
			wantWrite: "AT\r\nATE0\r\nAT+CMEE=2\r\n",
		},
		{
			name:    "uses caller context",
			ctx:     canceledContext(),
			wantErr: context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := &scriptPort{readData: tt.response}
			reader := newReader(port)

			err := reader.init(tt.ctx)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("init() error = %v, want %v", err, tt.wantErr)
			}
			if string(port.written) != tt.wantWrite {
				t.Fatalf("init() wrote %q, want %q", string(port.written), tt.wantWrite)
			}
		})
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestRunKeepsBufferedDataAcrossCalls(t *testing.T) {
	port := &scriptPort{readData: "\r\nAT+CSIM=?\r\n\r\nOK\r\nAT+CSIM=4,\"00\"\r\n+CSIM: 4,\"9000\"\r\nOK\r\n"}
	reader := &Reader{
		port:   port,
		reader: bufio.NewReader(port),
	}

	got, err := reader.run(context.Background(), "AT+CSIM=?")
	if err != nil {
		t.Fatalf("first run() error = %v", err)
	}
	if got != "" {
		t.Fatalf("first run() = %q, want empty response", got)
	}

	got, err = reader.run(context.Background(), `AT+CSIM=4,"00"`)
	if err != nil {
		t.Fatalf("second run() error = %v", err)
	}
	if got != `+CSIM: 4,"9000"` {
		t.Fatalf("second run() = %q, want %q", got, `+CSIM: 4,"9000"`)
	}

	if string(port.written) != "AT+CSIM=?\r\nAT+CSIM=4,\"00\"\r\n" {
		t.Fatalf("written commands = %q", string(port.written))
	}
}

func TestRunWritesCompleteCommand(t *testing.T) {
	port := &partialWritePort{readData: "AT+TEST\r\nOK\r\n", max: 3}
	reader := &Reader{
		port:   port,
		reader: bufio.NewReader(port),
	}

	if _, err := reader.run(context.Background(), "AT+TEST"); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if got := port.written.String(); got != "AT+TEST\r\n" {
		t.Fatalf("write = %q, want %q", got, "AT+TEST\r\n")
	}
}

func TestRunMatchesCompleteResultCodes(t *testing.T) {
	port := &scriptPort{readData: "AT+TEST\r\n+INFO: LOOKUP\r\nOK\r\n"}
	reader := &Reader{
		port:   port,
		reader: bufio.NewReader(port),
	}

	got, err := reader.run(context.Background(), "AT+TEST")
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if got != "+INFO: LOOKUP" {
		t.Fatalf("run() = %q, want %q", got, "+INFO: LOOKUP")
	}
}

func TestRunReturnsStructuredATErrors(t *testing.T) {
	port := &scriptPort{readData: "AT+TEST\r\n+CME ERROR: 42\r\n"}
	reader := &Reader{
		port:   port,
		reader: bufio.NewReader(port),
	}

	_, err := reader.run(context.Background(), "AT+TEST")
	if err == nil {
		t.Fatal("run() error = nil, want error")
	}
	if err.Error() != "+CME ERROR: 42" {
		t.Fatalf("run() error = %q, want %q", err.Error(), "+CME ERROR: 42")
	}
}

func TestTransmitReturnsNonOKStatusWord(t *testing.T) {
	port := &scriptPort{readData: "AT+CSIM=2,\"00\"\r\n+CSIM: 4,\"6A82\"\r\nOK\r\n"}
	reader := &Reader{
		port:   port,
		reader: bufio.NewReader(port),
	}

	got, err := reader.Transmit(context.Background(), []byte{0x00})
	if err != nil {
		t.Fatalf("Transmit() error = %v", err)
	}
	if !bytes.Equal(got, []byte{0x6A, 0x82}) {
		t.Fatalf("Transmit() = % X, want 6A 82", got)
	}
}

func TestTransmitRejectsShortStatusWord(t *testing.T) {
	port := &scriptPort{readData: "AT+CSIM=2,\"00\"\r\n+CSIM: 2,\"90\"\r\nOK\r\n"}
	reader := &Reader{
		port:   port,
		reader: bufio.NewReader(port),
	}

	_, err := reader.Transmit(context.Background(), []byte{0x00})
	if err == nil {
		t.Fatal("Transmit() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "invalid response status word") {
		t.Fatalf("Transmit() error = %q, want status word error", err.Error())
	}
}

func TestRun(t *testing.T) {
	tests := []struct {
		name      string
		response  string
		command   string
		want      string
		wantWrite string
		wantErr   bool
	}{
		{
			name:      "skip echo and blank lines",
			response:  "\r\nAT\r\n\r\n+CSIM: 4,\"9000\"\r\nOK\r\n",
			command:   "AT",
			want:      `+CSIM: 4,"9000"`,
			wantWrite: "AT\r\n",
		},
		{
			name:      "cme error",
			response:  "\r\nAT+CMEE=2\r\n+CME ERROR: operation not supported\r\n",
			command:   "AT+CMEE=2",
			wantWrite: "AT+CMEE=2\r\n",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := &scriptPort{readData: tt.response}
			reader := &Reader{
				port:   port,
				reader: bufio.NewReader(port),
			}

			got, err := reader.run(context.Background(), tt.command)
			if (err != nil) != tt.wantErr {
				t.Fatalf("run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if string(port.written) != tt.wantWrite {
				t.Fatalf("run() wrote %q, want %q", string(port.written), tt.wantWrite)
			}
			if tt.wantErr {
				return
			}
			if got != tt.want {
				t.Fatalf("run() = %q, want %q", got, tt.want)
			}
		})
	}
}
