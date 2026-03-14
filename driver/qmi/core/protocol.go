package core

import (
	"context"
	"time"
)

type Request struct {
	Service       Service
	ClientID      uint8
	TransactionID uint16
	MessageID     MessageID
	Timeout       time.Duration
	TLVs          TLVs
}

type Response struct {
	Service       Service
	ClientID      uint8
	TransactionID uint16
	MessageID     MessageID
	TLVs          TLVs
}

type Transport interface {
	Do(ctx context.Context, req Request) (Response, error)
	Close() error
}

func RequestDeadline(ctx context.Context, timeout time.Duration) (time.Time, bool) {
	if deadline, ok := ctx.Deadline(); ok {
		if timeout <= 0 {
			return deadline, true
		}

		timeoutDeadline := time.Now().Add(timeout)
		if deadline.Before(timeoutDeadline) {
			return deadline, true
		}
		return timeoutDeadline, true
	}
	if timeout <= 0 {
		return time.Time{}, false
	}
	return time.Now().Add(timeout), true
}
