package qrtr

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/damonto/ims-client/driver/qmi/core"
)

type Transport struct {
	conn net.Conn
	mu   sync.Mutex
}

func New(conn net.Conn) core.Transport {
	return &Transport{conn: conn}
}

func (t *Transport) Close() error {
	return t.conn.Close()
}

func (t *Transport) Do(ctx context.Context, req core.Request) (core.Response, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	packet := MarshalRequest(req)
	deadline, hasDeadline := core.RequestDeadline(ctx, req.Timeout)
	if hasDeadline {
		if err := t.conn.SetWriteDeadline(deadline); err != nil {
			return core.Response{}, fmt.Errorf("setting QRTR write deadline: %w", err)
		}
		defer func() { _ = t.conn.SetWriteDeadline(time.Time{}) }()
	}
	if _, err := t.conn.Write(packet); err != nil {
		return core.Response{}, fmt.Errorf("writing QRTR request: %w", err)
	}

	for {
		if hasDeadline {
			if err := t.conn.SetReadDeadline(deadline); err != nil {
				return core.Response{}, fmt.Errorf("setting QRTR read deadline: %w", err)
			}
			defer func() { _ = t.conn.SetReadDeadline(time.Time{}) }()
		}

		buf := make([]byte, 1024)
		n, err := t.conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return core.Response{}, ctx.Err()
			}
			return core.Response{}, fmt.Errorf("reading QRTR response: %w", err)
		}

		resp, err := ParseResponse(buf[:n])
		if err != nil {
			return core.Response{}, err
		}
		if resp.TransactionID != req.TransactionID || resp.MessageID != req.MessageID {
			continue
		}
		return resp, nil
	}
}

func MarshalRequest(req core.Request) []byte {
	payload := req.TLVs.MarshalBinary()

	out := []byte{byte(core.MessageTypeRequest)}
	out = binary.LittleEndian.AppendUint16(out, req.TransactionID)
	out = binary.LittleEndian.AppendUint16(out, uint16(req.MessageID))
	out = binary.LittleEndian.AppendUint16(out, uint16(len(payload)))
	out = append(out, payload...)
	return out
}
