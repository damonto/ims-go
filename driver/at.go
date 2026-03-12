package driver

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/damonto/ims-client/apdu"
)

const atDefaultBaudRate = 115200

type AT struct {
	port   io.ReadWriteCloser
	reader *bufio.Reader

	mu     sync.Mutex
	closed bool
}

type ATCSIMCommand struct {
	Payload string
}

type ATCSIMResponse struct {
	Payload string
	raw     apdu.Response
}

func NewAT(device string, baudRate int, initCommands []string) (*AT, error) {
	device = strings.TrimSpace(device)
	if device == "" {
		return nil, errors.New("opening AT driver: device is empty")
	}

	port, err := openATSerialPort(device, atBaudRateOrDefault(baudRate))
	if err != nil {
		return nil, fmt.Errorf("opening serial port %s: %w", device, err)
	}

	driver := &AT{
		port:   port,
		reader: bufio.NewReader(port),
	}
	for _, command := range atInitCommandsOrDefault(initCommands) {
		if _, err := driver.run(context.Background(), command); err != nil {
			_ = port.Close()
			return nil, fmt.Errorf("running init command %q: %w", command, err)
		}
	}
	return driver, nil
}

func NewATCSIMCommand(req *apdu.Request) (ATCSIMCommand, error) {
	if req == nil {
		return ATCSIMCommand{}, errors.New("building AT+CSIM command: request is nil")
	}
	return ATCSIMCommand{Payload: req.String()}, nil
}

func atBaudRateOrDefault(baudRate int) int {
	if baudRate == 0 {
		return atDefaultBaudRate
	}
	return baudRate
}

func atInitCommandsOrDefault(initCommands []string) []string {
	if len(initCommands) == 0 {
		return []string{"AT", "ATE0", "AT+CMEE=2", "AT+CSIM=?"}
	}
	return slices.Clone(initCommands)
}

func (c ATCSIMCommand) MarshalText() ([]byte, error) {
	if _, err := hex.DecodeString(c.Payload); err != nil {
		return nil, fmt.Errorf("marshaling AT+CSIM command payload: %w", err)
	}
	return []byte(fmt.Sprintf("AT+CSIM=%d,%q", len(c.Payload), c.Payload)), nil
}

func (c *ATCSIMResponse) UnmarshalText(text []byte) error {
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
	c.raw = apdu.Response(raw)
	return nil
}

func (c ATCSIMResponse) MarshalBinary() ([]byte, error) {
	if c.raw != nil {
		return []byte(slices.Clone(c.raw)), nil
	}
	raw, err := hex.DecodeString(c.Payload)
	if err != nil {
		return nil, fmt.Errorf("decoding +CSIM payload: %w", err)
	}
	return raw, nil
}

func (d *AT) Transmit(ctx context.Context, req *apdu.Request) (apdu.Response, error) {
	command, err := NewATCSIMCommand(req)
	if err != nil {
		return nil, fmt.Errorf("transmitting APDU: %w", err)
	}

	textCommand, err := command.MarshalText()
	if err != nil {
		return nil, fmt.Errorf("transmitting APDU %s: %w", req.String(), err)
	}

	text, err := d.run(ctx, string(textCommand))
	if err != nil {
		return nil, fmt.Errorf("transmitting APDU %s: %w", req.String(), err)
	}

	var response ATCSIMResponse
	if err := response.UnmarshalText([]byte(text)); err != nil {
		return nil, fmt.Errorf("transmitting APDU %s: %w", req.String(), err)
	}

	raw, err := response.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("transmitting APDU %s: %w", req.String(), err)
	}
	return apdu.Response(raw), nil
}

func (d *AT) run(ctx context.Context, command string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return "", errors.New("using serial driver: driver is closed")
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

func (d *AT) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	return d.port.Close()
}

var _ apdu.Driver = (*AT)(nil)
