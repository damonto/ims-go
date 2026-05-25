package qmi

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/damonto/ims-client/driver/qmi/protocol"
)

type QMUXHeader struct {
	IfType       uint8
	Length       uint16
	ControlFlags uint8
	ServiceType  protocol.ServiceType
	ClientID     uint8
}

type Header[T uint8 | uint16] struct {
	MessageType   protocol.MessageType
	TransactionID T
	MessageID     protocol.MessageID
	MessageLength uint16
}

type Transport struct {
	conn net.Conn
	mu   sync.Mutex
}

func New(conn net.Conn) protocol.Transport {
	return &Transport{conn: conn}
}

func (t *Transport) Close() error {
	return t.conn.Close()
}

func (t *Transport) Do(ctx context.Context, req protocol.Request) (protocol.Response, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	packet, err := marshalRequest(req)
	if err != nil {
		return protocol.Response{}, err
	}

	deadline, hasDeadline := protocol.RequestDeadline(ctx, req.Timeout)
	if hasDeadline {
		if err := t.conn.SetWriteDeadline(deadline); err != nil {
			return protocol.Response{}, fmt.Errorf("setting QMI write deadline: %w", err)
		}
		defer func() { _ = t.conn.SetWriteDeadline(time.Time{}) }()
	}
	if err := writeFull(t.conn, packet); err != nil {
		return protocol.Response{}, fmt.Errorf("writing QMI request: %w", err)
	}

	for {
		if hasDeadline {
			if err := t.conn.SetReadDeadline(deadline); err != nil {
				return protocol.Response{}, fmt.Errorf("setting QMI read deadline: %w", err)
			}
			defer func() { _ = t.conn.SetReadDeadline(time.Time{}) }()
		}

		frame, err := ReadFrame(t.conn)
		if err != nil {
			if ctx.Err() != nil {
				return protocol.Response{}, ctx.Err()
			}
			return protocol.Response{}, fmt.Errorf("reading QMI response: %w", err)
		}

		resp, err := ParseResponse(frame)
		if err != nil {
			return protocol.Response{}, err
		}
		if resp.Service != req.Service || resp.TransactionID != req.TransactionID || resp.MessageID != req.MessageID {
			continue
		}
		if req.Service != protocol.ServiceControl && resp.ClientID != req.ClientID {
			continue
		}
		return resp, nil
	}
}

func MarshalRequest(req protocol.Request) []byte {
	packet, _ := marshalRequest(req)
	return packet
}

func marshalRequest(req protocol.Request) ([]byte, error) {
	payload := req.TLVs.MarshalBinary()
	maxPayloadLength := protocol.MaxQMUXServiceTLVLength
	if req.Service == protocol.ServiceControl {
		maxPayloadLength = protocol.MaxQMUXControlTLVLength
	}
	if len(payload) > maxPayloadLength {
		return nil, fmt.Errorf("QMI message TLVs length %d exceeds limit %d", len(payload), maxPayloadLength)
	}

	sdu := new(bytes.Buffer)
	if req.Service == protocol.ServiceControl {
		if err := binary.Write(sdu, binary.LittleEndian, Header[uint8]{
			MessageType:   protocol.MessageTypeRequest,
			TransactionID: uint8(req.TransactionID),
			MessageID:     req.MessageID,
			MessageLength: uint16(len(payload)),
		}); err != nil {
			return nil, fmt.Errorf("write control QMI header: %w", err)
		}
	} else {
		if err := binary.Write(sdu, binary.LittleEndian, Header[uint16]{
			MessageType:   protocol.MessageTypeRequest,
			TransactionID: req.TransactionID,
			MessageID:     req.MessageID,
			MessageLength: uint16(len(payload)),
		}); err != nil {
			return nil, fmt.Errorf("write service QMI header: %w", err)
		}
	}
	if _, err := sdu.Write(payload); err != nil {
		return nil, fmt.Errorf("write QMI payload: %w", err)
	}

	out := new(bytes.Buffer)
	if err := binary.Write(out, binary.LittleEndian, QMUXHeader{
		IfType:       protocol.QMUXIfType,
		Length:       uint16(sdu.Len() + 5),
		ControlFlags: protocol.QMUXControlFlagRequest,
		ServiceType:  req.Service,
		ClientID:     req.ClientID,
	}); err != nil {
		return nil, fmt.Errorf("write QMUX header: %w", err)
	}
	if _, err := out.Write(sdu.Bytes()); err != nil {
		return nil, fmt.Errorf("write QMUX payload: %w", err)
	}
	return out.Bytes(), nil
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
