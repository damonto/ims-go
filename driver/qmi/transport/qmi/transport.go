package qmi

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
			return core.Response{}, fmt.Errorf("setting QMI write deadline: %w", err)
		}
		defer func() { _ = t.conn.SetWriteDeadline(time.Time{}) }()
	}
	if _, err := t.conn.Write(packet); err != nil {
		return core.Response{}, fmt.Errorf("writing QMI request: %w", err)
	}

	for {
		if hasDeadline {
			if err := t.conn.SetReadDeadline(deadline); err != nil {
				return core.Response{}, fmt.Errorf("setting QMI read deadline: %w", err)
			}
			defer func() { _ = t.conn.SetReadDeadline(time.Time{}) }()
		}

		frame, err := ReadFrame(t.conn)
		if err != nil {
			if ctx.Err() != nil {
				return core.Response{}, ctx.Err()
			}
			return core.Response{}, fmt.Errorf("reading QMI response: %w", err)
		}

		resp, err := ParseResponse(frame)
		if err != nil {
			return core.Response{}, err
		}
		if resp.Service != req.Service || resp.TransactionID != req.TransactionID || resp.MessageID != req.MessageID {
			continue
		}
		if req.Service != core.ServiceControl && resp.ClientID != req.ClientID {
			continue
		}
		return resp, nil
	}
}

func MarshalRequest(req core.Request) []byte {
	payload := req.TLVs.MarshalBinary()

	sdu := []byte{byte(core.MessageTypeRequest)}
	if req.Service == core.ServiceControl {
		sdu = append(sdu, byte(req.TransactionID))
	} else {
		sdu = binary.LittleEndian.AppendUint16(sdu, req.TransactionID)
	}
	sdu = binary.LittleEndian.AppendUint16(sdu, uint16(req.MessageID))
	sdu = binary.LittleEndian.AppendUint16(sdu, uint16(len(payload)))
	sdu = append(sdu, payload...)

	out := []byte{core.QMUXIfType}
	out = binary.LittleEndian.AppendUint16(out, uint16(len(sdu)+5))
	out = append(out, core.QMUXControlFlagRequest, byte(req.Service), req.ClientID)
	out = append(out, sdu...)
	return out
}
