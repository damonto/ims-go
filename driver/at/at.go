package at

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/damonto/ims-client/usim"
	usimreader "github.com/damonto/ims-client/usim/reader"
)

const defaultBaudRate = 115200

type Reader struct {
	port   io.ReadWriteCloser
	reader *bufio.Reader

	mu     sync.Mutex
	closed bool
}

type csimCommand struct {
	Payload string
}

type csimResponse struct {
	Payload string
	raw     []byte
}

func New(device string, baudRate int) (usimreader.Reader, error) {
	device = strings.TrimSpace(device)
	if device == "" {
		return nil, errors.New("opening AT reader: device is empty")
	}

	port, err := openSerialPort(device, baudRateOrDefault(baudRate))
	if err != nil {
		return nil, fmt.Errorf("opening serial port %s: %w", device, err)
	}

	reader := &Reader{
		port:   port,
		reader: bufio.NewReader(port),
	}
	for _, command := range defaultInitCommands() {
		if _, err := reader.run(context.Background(), command); err != nil {
			_ = port.Close()
			return nil, fmt.Errorf("running init command %q: %w", command, err)
		}
	}
	return usim.New(reader), nil
}

func Open(device string, baudRate int) (usimreader.Reader, error) {
	return New(device, baudRate)
}

func newCSIMCommand(req []byte) (csimCommand, error) {
	if req == nil {
		return csimCommand{}, errors.New("building AT+CSIM command: request is nil")
	}
	return csimCommand{Payload: strings.ToUpper(hex.EncodeToString(req))}, nil
}

func baudRateOrDefault(baudRate int) int {
	if baudRate == 0 {
		return defaultBaudRate
	}
	return baudRate
}

func defaultInitCommands() []string {
	return []string{"AT", "ATE0", "AT+CMEE=2"}
}

func (c csimCommand) MarshalText() ([]byte, error) {
	if _, err := hex.DecodeString(c.Payload); err != nil {
		return nil, fmt.Errorf("marshaling AT+CSIM command payload: %w", err)
	}
	return []byte(fmt.Sprintf("AT+CSIM=%d,%q", len(c.Payload), c.Payload)), nil
}

func (c *csimResponse) UnmarshalText(text []byte) error {
	line := strings.TrimSpace(string(text))
	if idx := strings.LastIndexAny(line, "\r\n"); idx >= 0 {
		line = strings.TrimSpace(line[idx+1:])
	}
	if line == "" {
		return errors.New("unmarshaling +CSIM response: empty payload")
	}

	lastIdx := strings.LastIndex(line, ",")
	if lastIdx == -1 {
		return errors.New("unmarshaling +CSIM response: missing payload separator")
	}

	payloadText := strings.TrimSpace(line[lastIdx+1:])
	if len(payloadText) < 2 || payloadText[0] != '"' || payloadText[len(payloadText)-1] != '"' {
		return errors.New("unmarshaling +CSIM response: payload is not quoted")
	}
	payload := payloadText[1 : len(payloadText)-1]

	if colon := strings.LastIndex(line[:lastIdx], ":"); colon >= 0 {
		declaredText := strings.TrimSpace(line[colon+1 : lastIdx])
		declaredLen, err := strconv.Atoi(declaredText)
		if err != nil {
			return fmt.Errorf("unmarshaling +CSIM length: %w", err)
		}
		if declaredLen != len(payload) {
			return fmt.Errorf("unmarshaling +CSIM response: declared length %d does not match payload length %d", declaredLen, len(payload))
		}
	}

	raw, err := hex.DecodeString(payload)
	if err != nil {
		return fmt.Errorf("decoding +CSIM payload: %w", err)
	}

	c.Payload = payload
	c.raw = raw
	return nil
}

func (c csimResponse) MarshalBinary() ([]byte, error) {
	if c.raw != nil {
		return append([]byte(nil), c.raw...), nil
	}

	raw, err := hex.DecodeString(c.Payload)
	if err != nil {
		return nil, fmt.Errorf("decoding +CSIM payload: %w", err)
	}
	return raw, nil
}

func (d *Reader) Transmit(ctx context.Context, req []byte) ([]byte, error) {
	command, err := newCSIMCommand(req)
	if err != nil {
		return nil, fmt.Errorf("transmitting APDU: %w", err)
	}

	textCommand, err := command.MarshalText()
	if err != nil {
		return nil, fmt.Errorf("transmitting APDU %X: %w", req, err)
	}

	text, err := d.run(ctx, string(textCommand))
	if err != nil {
		return nil, fmt.Errorf("transmitting APDU %X: %w", req, err)
	}

	var response csimResponse
	if err := response.UnmarshalText([]byte(text)); err != nil {
		return nil, fmt.Errorf("transmitting APDU %X: %w", req, err)
	}

	raw, err := response.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("transmitting APDU %X: %w", req, err)
	}
	return raw, nil
}

func (d *Reader) run(ctx context.Context, command string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return "", errors.New("using serial reader: reader is closed")
	}
	if _, err := d.port.Write([]byte(command + "\r\n")); err != nil {
		return "", fmt.Errorf("writing AT command %q: %w", command, err)
	}

	var builder strings.Builder
	for {
		line, err := d.reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("reading AT response for %q: %w", command, err)
		}

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		line = strings.TrimSpace(line)
		if line == "" || line == command {
			continue
		}

		upper := strings.ToUpper(line)
		switch {
		case upper == "OK":
			return strings.TrimSpace(builder.String()), nil
		case upper == "ERROR", strings.HasPrefix(upper, "+CME ERROR:"), strings.HasPrefix(upper, "+CMS ERROR:"):
			return "", errors.New(line)
		default:
			if builder.Len() > 0 {
				builder.WriteByte('\n')
			}
			builder.WriteString(line)
		}
	}
}

func (d *Reader) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	return d.port.Close()
}

var _ usimreader.Transmitter = (*Reader)(nil)
