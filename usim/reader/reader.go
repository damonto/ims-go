package reader

import "context"

type Reader interface {
	Transmit(ctx context.Context, req []byte) ([]byte, error)
	Close() error
}
