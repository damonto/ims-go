package ccid

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/ElMostafaIdrassi/goscard"

	"github.com/damonto/ims-client/usim"
	usimreader "github.com/damonto/ims-client/usim/reader"
)

var ErrReaderNotFound = errors.New("reader not found")

type Reader struct {
	mu     sync.Mutex
	ctx    *goscard.Context
	card   *goscard.Card
	ioSend *goscard.SCardIORequest
	closed bool
}

var pcsc struct {
	mu   sync.Mutex
	refs int
}

func ListReaders() ([]string, error) {
	ctx, err := newContext()
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = ctx.Release()
		releasePCSC()
	}()

	readers, _, err := ctx.ListReaders(nil)
	if err != nil {
		return nil, fmt.Errorf("listing readers: %w", err)
	}
	return slices.Clone(readers), nil
}

func Open(readerName string) (usimreader.Reader, error) {
	readerName = strings.TrimSpace(readerName)
	if readerName == "" {
		return nil, errors.New("opening reader: reader name is empty")
	}

	ctx, err := newContext()
	if err != nil {
		return nil, err
	}

	readers, _, err := ctx.ListReaders(nil)
	if err != nil {
		_, _ = ctx.Release()
		releasePCSC()
		return nil, fmt.Errorf("listing readers: %w", err)
	}
	if !slices.Contains(readers, readerName) {
		_, _ = ctx.Release()
		releasePCSC()
		return nil, fmt.Errorf("selecting %q: %w", readerName, ErrReaderNotFound)
	}

	card, _, err := ctx.Connect(readerName, goscard.SCardShareShared, goscard.SCardProtocolAny)
	if err != nil {
		_, _ = ctx.Release()
		releasePCSC()
		return nil, fmt.Errorf("connecting to %s: %w", readerName, err)
	}
	ioSend, err := ioRequestForProtocol(card.ActiveProtocol())
	if err != nil {
		_, _ = card.Disconnect(goscard.SCardLeaveCard)
		_, _ = ctx.Release()
		releasePCSC()
		return nil, err
	}

	return usim.New(&Reader{
		ctx:    &ctx,
		card:   &card,
		ioSend: ioSend,
	}), nil
}

func newContext() (goscard.Context, error) {
	if err := acquirePCSC(); err != nil {
		return goscard.Context{}, err
	}

	ctx, _, err := goscard.NewContext(goscard.SCardScopeSystem, nil, nil)
	if err != nil {
		releasePCSC()
		return goscard.Context{}, fmt.Errorf("creating pcsc context: %w", err)
	}
	return ctx, nil
}

func (r *Reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}

	var errs []error
	if err := r.disconnectCard(); err != nil {
		errs = append(errs, err)
	}
	if _, err := r.ctx.Release(); err != nil {
		errs = append(errs, fmt.Errorf("releasing pcsc context: %w", err))
	}
	r.ctx = nil
	r.closed = true
	releasePCSC()
	return errors.Join(errs...)
}

func (r *Reader) disconnectCard() error {
	if r.card == nil {
		return nil
	}

	_, err := r.card.Disconnect(goscard.SCardLeaveCard)
	r.card = nil
	r.ioSend = nil
	if err != nil {
		return fmt.Errorf("disconnecting card: %w", err)
	}
	return nil
}

func (r *Reader) Transmit(ctx context.Context, req []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, errors.New("transmitting APDU: reader is closed")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	recv, _, err := r.card.Transmit(r.ioSend, req, nil)
	if err != nil {
		return nil, fmt.Errorf("transmitting APDU %X: %w", req, err)
	}
	return recv, nil
}

func acquirePCSC() error {
	pcsc.mu.Lock()
	defer pcsc.mu.Unlock()

	if pcsc.refs == 0 {
		if err := goscard.Initialize(goscard.NewDefaultLogger(goscard.LogLevelNone)); err != nil {
			return fmt.Errorf("initializing pcsc: %w", err)
		}
	}
	pcsc.refs++
	return nil
}

func releasePCSC() {
	pcsc.mu.Lock()
	defer pcsc.mu.Unlock()

	if pcsc.refs == 0 {
		return
	}
	pcsc.refs--
	if pcsc.refs == 0 {
		goscard.Finalize()
	}
}

func ioRequestForProtocol(protocol goscard.SCardProtocol) (*goscard.SCardIORequest, error) {
	switch protocol {
	case goscard.SCardProtocolT0:
		return &goscard.SCardIoRequestT0, nil
	case goscard.SCardProtocolT1:
		return &goscard.SCardIoRequestT1, nil
	default:
		return nil, fmt.Errorf("unsupported active PC/SC protocol: %s", protocol.String())
	}
}

var _ usimreader.Transmitter = (*Reader)(nil)
