package driver

import (
	"bufio"
	"context"
	"io"
	"testing"

	"github.com/damonto/ims-client/apdu"
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

func TestATCSIMResponseUnmarshalText(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    apdu.Response
		wantErr bool
	}{
		{name: "single line", input: `+CSIM: 4,"9000"`, want: apdu.Response{0x90, 0x00}},
		{name: "multiline body", input: "noise\n+CSIM: 12,\"DEADBEEF9000\"", want: apdu.Response{0xDE, 0xAD, 0xBE, 0xEF, 0x90, 0x00}},
		{name: "bad length", input: `+CSIM: 6,"9000"`, wantErr: true},
		{name: "bad hex", input: `+CSIM: 4,"90GG"`, wantErr: true},
		{name: "missing comma", input: `+CSIM: 4 "9000"`, wantErr: true},
		{name: "missing quotes", input: `+CSIM: 4,9000`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var response ATCSIMResponse
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
			if string(got) != string(tt.want) {
				t.Fatalf("MarshalBinary() = % X, want % X", got, []byte(tt.want))
			}
		})
	}
}

func TestATCSIMCommandMarshalText(t *testing.T) {
	req := apdu.GetResponse(0x10)
	command, err := NewATCSIMCommand(req)
	if err != nil {
		t.Fatalf("NewATCSIMCommand() error = %v", err)
	}

	got, err := command.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	if string(got) != `AT+CSIM=10,"00C0000010"` {
		t.Fatalf("MarshalText() = %q, want %q", string(got), `AT+CSIM=10,"00C0000010"`)
	}
}

func TestATInitCommandsOrDefault(t *testing.T) {
	tests := []struct {
		name string
		init []string
		want []string
	}{
		{name: "defaults", want: []string{"AT", "ATE0", "AT+CMEE=2", "AT+CSIM=?"}},
		{name: "custom", init: []string{"ATZ"}, want: []string{"ATZ"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := atInitCommandsOrDefault(tt.init)
			if len(got) != len(tt.want) {
				t.Fatalf("atInitCommandsOrDefault() len = %d, want %d", len(got), len(tt.want))
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("atInitCommandsOrDefault()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestATBaudRateOrDefault(t *testing.T) {
	tests := []struct {
		name string
		baud int
		want int
	}{
		{name: "default", want: atDefaultBaudRate},
		{name: "custom", baud: 230400, want: 230400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := atBaudRateOrDefault(tt.baud); got != tt.want {
				t.Fatalf("atBaudRateOrDefault() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestATRun(t *testing.T) {
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
			response:  "\r\nAT+CSIM=?\r\n+CME ERROR: operation not supported\r\n",
			command:   "AT+CSIM=?",
			wantWrite: "AT+CSIM=?\r\n",
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := &scriptPort{readData: tt.response}
			drv := &AT{
				port:   port,
				reader: bufio.NewReader(port),
			}

			got, err := drv.run(context.Background(), tt.command)
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
