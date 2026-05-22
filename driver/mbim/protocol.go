package mbim

import (
	"context"
	"encoding"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

type Request struct {
	MessageType   MessageType
	MessageLength uint32
	TransactionID uint32
	Timeout       time.Duration
	Command       encoding.BinaryMarshaler
	Response      encoding.BinaryUnmarshaler
}

func (r *Request) Transmit(ctx context.Context, conn net.Conn) error {
	if _, err := r.WriteTo(ctx, conn); err != nil {
		return err
	}
	if _, err := r.ReadFrom(ctx, conn); err != nil {
		return err
	}
	return nil
}

func (r *Request) WriteTo(ctx context.Context, conn net.Conn) (int, error) {
	data, err := r.MarshalBinary()
	if err != nil {
		return 0, err
	}
	frames, err := fragmentedMessage{
		data:         data,
		maxFrameSize: maxControlTransfer,
	}.Frames()
	if err != nil {
		return 0, err
	}

	if deadline, ok := requestDeadline(ctx, r.timeout()); ok {
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return 0, fmt.Errorf("setting MBIM write deadline: %w", err)
		}
	}

	var written int
	for _, frame := range frames {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		n, err := writeFull(conn, frame)
		written += n
		if err != nil {
			return written, fmt.Errorf("writing MBIM request: %w", err)
		}
	}
	return written, nil
}

func (r *Request) ReadFrom(ctx context.Context, conn net.Conn) (int, error) {
	deadline, hasDeadline := requestDeadline(ctx, r.timeout())
	var collector *fragmentCollector

	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if hasDeadline && !time.Now().Before(deadline) {
			return 0, fmt.Errorf("reading MBIM response: transaction ID %d not found", r.TransactionID)
		}

		readDeadline := time.Now().Add(time.Second)
		if hasDeadline && deadline.Before(readDeadline) {
			readDeadline = deadline
		}
		if err := conn.SetReadDeadline(readDeadline); err != nil {
			return 0, fmt.Errorf("setting MBIM read deadline: %w", err)
		}

		buf, err := readFrame(conn)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return 0, fmt.Errorf("reading MBIM response: %w", err)
		}

		messageType := MessageType(binary.LittleEndian.Uint32(buf[:4]))
		transactionID := binary.LittleEndian.Uint32(buf[8:12])
		if transactionID != r.TransactionID {
			continue
		}
		expectedMessageType, ok := responseMessageType(r.MessageType)
		if !ok {
			return 0, fmt.Errorf("reading MBIM response: unsupported request message type %#x", r.MessageType)
		}
		if messageType != expectedMessageType && messageType != MessageTypeFunctionError {
			continue
		}

		if isFragmentMessage(messageType) {
			if collector != nil {
				if err := collector.add(buf); err != nil {
					return 0, err
				}
				if !collector.complete() {
					continue
				}
				completeFrame, err := collector.MarshalBinary()
				if err != nil {
					return 0, err
				}
				buf = completeFrame
			} else if len(buf) >= 20 && binary.LittleEndian.Uint32(buf[12:16]) > 1 {
				var err error
				collector, err = newFragmentCollector(buf)
				if err != nil {
					return 0, err
				}
				if !collector.complete() {
					continue
				}
				buf, err = collector.MarshalBinary()
				if err != nil {
					return 0, err
				}
			}
		}

		response := CommandResponse{Response: r.Response}
		if err := response.UnmarshalBinary(buf); err != nil {
			return 0, err
		}
		return len(buf), nil
	}
}

func (r *Request) MarshalBinary() ([]byte, error) {
	command, err := r.Command.MarshalBinary()
	if err != nil {
		return nil, err
	}
	r.MessageLength = uint32(12 + len(command))
	buf := make([]byte, 0, r.MessageLength)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(r.MessageType))
	buf = binary.LittleEndian.AppendUint32(buf, r.MessageLength)
	buf = binary.LittleEndian.AppendUint32(buf, r.TransactionID)
	buf = append(buf, command...)
	return buf, nil
}

func (r *Request) timeout() time.Duration {
	if r.Timeout == 0 {
		return 30 * time.Second
	}
	return r.Timeout
}

func responseMessageType(requestType MessageType) (MessageType, bool) {
	switch requestType {
	case MessageTypeOpen:
		return MessageTypeOpenDone, true
	case MessageTypeClose:
		return MessageTypeCloseDone, true
	case MessageTypeCommand:
		return MessageTypeCommandDone, true
	default:
		return 0, false
	}
}

func requestDeadline(ctx context.Context, timeout time.Duration) (time.Time, bool) {
	if deadline, ok := ctx.Deadline(); ok {
		timeoutDeadline := time.Now().Add(timeout)
		if deadline.Before(timeoutDeadline) {
			return deadline, true
		}
		return timeoutDeadline, true
	}
	return time.Now().Add(timeout), true
}

func readFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, 12)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint32(header[4:8])
	if length < 12 {
		return nil, fmt.Errorf("invalid MBIM message length %d", length)
	}
	if length > maxControlTransfer {
		return nil, fmt.Errorf("MBIM frame length %d exceeds max control transfer %d", length, maxControlTransfer)
	}
	buf := make([]byte, length)
	copy(buf, header)
	if _, err := io.ReadFull(r, buf[12:]); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeFull(w io.Writer, data []byte) (int, error) {
	var written int
	for len(data) > 0 {
		n, err := w.Write(data)
		written += n
		if err != nil {
			return written, err
		}
		if n <= 0 {
			return written, io.ErrShortWrite
		}
		data = data[n:]
	}
	return written, nil
}

type Command struct {
	FragmentTotal   uint32
	FragmentCurrent uint32
	ServiceID       [16]byte
	CommandID       uint32
	CommandType     uint32
	Data            []byte
}

func (c *Command) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, 36+len(c.Data))
	buf = binary.LittleEndian.AppendUint32(buf, c.FragmentTotal)
	buf = binary.LittleEndian.AppendUint32(buf, c.FragmentCurrent)
	buf = append(buf, c.ServiceID[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, c.CommandID)
	buf = binary.LittleEndian.AppendUint32(buf, c.CommandType)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(c.Data)))
	buf = append(buf, c.Data...)
	return buf, nil
}

type CommandResponse struct {
	MessageType     MessageType
	MessageLength   uint32
	TransactionID   uint32
	FragmentTotal   uint32
	FragmentCurrent uint32
	ServiceID       [16]byte
	CommandID       uint32
	Status          Status
	ResponseLength  uint32
	ResponseBuffer  []byte
	Response        encoding.BinaryUnmarshaler
}

func (r *CommandResponse) UnmarshalBinary(data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("parsing MBIM response: length %d is too short", len(data))
	}
	r.MessageType = MessageType(binary.LittleEndian.Uint32(data[:4]))
	r.MessageLength = binary.LittleEndian.Uint32(data[4:8])
	r.TransactionID = binary.LittleEndian.Uint32(data[8:12])
	if r.MessageLength != uint32(len(data)) {
		return fmt.Errorf("parsing MBIM response: header length %d does not match actual length %d", r.MessageLength, len(data))
	}

	switch r.MessageType {
	case MessageTypeOpenDone, MessageTypeCloseDone:
		return r.unmarshalStatusDone(data)
	case MessageTypeCommandDone:
		return r.unmarshalCommandDone(data)
	case MessageTypeFunctionError:
		return r.unmarshalFunctionError(data)
	default:
		return fmt.Errorf("parsing MBIM response: unexpected message type %#x", r.MessageType)
	}
}

func (r *CommandResponse) unmarshalStatusDone(data []byte) error {
	if len(data) != 16 {
		return fmt.Errorf("parsing MBIM status response: length %d, want 16", len(data))
	}
	r.Status = Status(binary.LittleEndian.Uint32(data[12:16]))
	if r.Status != StatusNone {
		return r.Status
	}
	if r.Response == nil {
		return nil
	}
	return r.Response.UnmarshalBinary(nil)
}

func (r *CommandResponse) unmarshalCommandDone(data []byte) error {
	if len(data) < 48 {
		return fmt.Errorf("parsing MBIM command response: length %d is too short", len(data))
	}
	r.FragmentTotal = binary.LittleEndian.Uint32(data[12:16])
	r.FragmentCurrent = binary.LittleEndian.Uint32(data[16:20])
	copy(r.ServiceID[:], data[20:36])
	r.CommandID = binary.LittleEndian.Uint32(data[36:40])
	r.Status = Status(binary.LittleEndian.Uint32(data[40:44]))
	if r.Status != StatusNone {
		return r.Status
	}
	if r.FragmentTotal != 1 || r.FragmentCurrent != 0 {
		return fmt.Errorf("parsing MBIM command response: unsupported fragment %d of %d", r.FragmentCurrent, r.FragmentTotal)
	}
	r.ResponseLength = binary.LittleEndian.Uint32(data[44:48])
	if r.ResponseLength > uint32(len(data)-48) {
		return fmt.Errorf("parsing MBIM command response: response length %d exceeds remaining %d", r.ResponseLength, len(data)-48)
	}
	r.ResponseBuffer = data[48 : 48+r.ResponseLength]
	if r.Response == nil {
		return nil
	}
	return r.Response.UnmarshalBinary(r.ResponseBuffer)
}

func (r *CommandResponse) unmarshalFunctionError(data []byte) error {
	if len(data) != 16 {
		return fmt.Errorf("parsing MBIM function error: length %d, want 16", len(data))
	}
	return ProtocolError(binary.LittleEndian.Uint32(data[12:16]))
}
