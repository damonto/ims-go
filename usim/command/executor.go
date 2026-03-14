package command

import (
	"context"
	"fmt"

	"github.com/damonto/ims-client/usim/apdu"
	usimreader "github.com/damonto/ims-client/usim/reader"
)

type Command[T any] interface {
	APDU() []byte
	DecodeResponse(resp apdu.Response) (T, error)
}

func Execute[T any](ctx context.Context, r usimreader.Reader, cmd Command[T]) (T, error) {
	var zero T
	if r == nil {
		return zero, fmt.Errorf("executing APDU command: reader is nil")
	}

	resp, err := transmit(ctx, r, cmd.APDU())
	if err != nil {
		return zero, err
	}

	result, err := cmd.DecodeResponse(resp)
	if err != nil {
		return zero, err
	}
	return result, nil
}

func transmit(ctx context.Context, r usimreader.Reader, req []byte) (apdu.Response, error) {
	raw, err := r.Transmit(ctx, req)
	if err != nil {
		return nil, err
	}

	resp := apdu.Response(raw)
	if len(resp) < 2 {
		return nil, apdu.ErrMalformedResponse
	}

	data := append([]byte(nil), resp.Data()...)
	for resp.HasMore() {
		length := resp.SW2()
		follow, err := r.Transmit(ctx, apdu.Request{
			CLA: 0x00,
			INS: 0xC0,
			P1:  0x00,
			P2:  0x00,
			Le:  &length,
		}.APDU())
		if err != nil {
			return nil, fmt.Errorf("reading response body: %w", err)
		}
		resp = apdu.Response(follow)
		if len(resp) < 2 {
			return nil, apdu.ErrMalformedResponse
		}
		data = append(data, resp.Data()...)
	}

	if !resp.OK() {
		return nil, apdu.StatusError{SW: resp.SW()}
	}

	return append(data, byte(resp.SW()>>8), byte(resp.SW())), nil
}
