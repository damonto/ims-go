package apdu

import "context"

type Driver interface {
	Transmit(ctx context.Context, req *Request) (Response, error)
	Close() error
}
