package qrtr

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/damonto/vowifi-go/driver/qmi/protocol"
)

type Conn interface {
	io.ReadWriter
	SetReadDeadline(time.Time) error
	Close() error
}

type Header struct {
	MessageType   protocol.MessageType
	TransactionID uint16
	MessageID     protocol.MessageID
	MessageLength uint16
}

type Transport struct {
	conn Conn
	mu   sync.Mutex
}

func New(conn Conn) protocol.Transport {
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
	if err := writeFull(t.conn, packet); err != nil {
		return protocol.Response{}, fmt.Errorf("writing QRTR request: %w", err)
	}

	for {
		if hasDeadline {
			if err := t.conn.SetReadDeadline(deadline); err != nil {
				return protocol.Response{}, fmt.Errorf("setting QRTR read deadline: %w", err)
			}
			defer func() { _ = t.conn.SetReadDeadline(time.Time{}) }()
		}

		buf := make([]byte, protocol.MaxQRTRQMIMessageLength)
		n, err := t.conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return protocol.Response{}, ctx.Err()
			}
			return protocol.Response{}, fmt.Errorf("reading QRTR response: %w", err)
		}

		resp, err := ParseResponse(buf[:n])
		if err != nil {
			return protocol.Response{}, err
		}
		if resp.TransactionID != req.TransactionID || resp.MessageID != req.MessageID {
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
	if len(payload) > protocol.MaxQRTRServiceTLVLength {
		return nil, fmt.Errorf("QRTR QMI message TLVs length %d exceeds limit %d", len(payload), protocol.MaxQRTRServiceTLVLength)
	}

	out := new(bytes.Buffer)
	if err := binary.Write(out, binary.LittleEndian, Header{
		MessageType:   protocol.MessageTypeRequest,
		TransactionID: req.TransactionID,
		MessageID:     req.MessageID,
		MessageLength: uint16(len(payload)),
	}); err != nil {
		return nil, fmt.Errorf("write QRTR QMI header: %w", err)
	}
	if _, err := out.Write(payload); err != nil {
		return nil, fmt.Errorf("write QRTR QMI payload: %w", err)
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
