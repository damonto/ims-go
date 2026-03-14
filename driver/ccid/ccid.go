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
	ctx  *goscard.Context
	card *goscard.Card
}

var (
	pcscInitOnce sync.Once
	pcscInitErr  error
)

func ListReaders() ([]string, error) {
	ctx, err := newContext()
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = ctx.Release()
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
		return nil, fmt.Errorf("listing readers: %w", err)
	}
	if !slices.Contains(readers, readerName) {
		_, _ = ctx.Release()
		return nil, fmt.Errorf("selecting %q: %w", readerName, ErrReaderNotFound)
	}

	card, _, err := ctx.Connect(readerName, goscard.SCardShareShared, goscard.SCardProtocolT0|goscard.SCardProtocolT1)
	if err != nil {
		_, _ = ctx.Release()
		return nil, fmt.Errorf("connecting to %s: %w", readerName, err)
	}

	return usim.New(&Reader{
		ctx:  &ctx,
		card: &card,
	}), nil
}

func newContext() (goscard.Context, error) {
	pcscInitOnce.Do(func() {
		pcscInitErr = goscard.Initialize(goscard.NewDefaultLogger(goscard.LogLevelNone))
	})
	if pcscInitErr != nil {
		return goscard.Context{}, fmt.Errorf("initializing pcsc: %w", pcscInitErr)
	}

	ctx, _, err := goscard.NewContext(goscard.SCardScopeSystem, nil, nil)
	if err != nil {
		return goscard.Context{}, fmt.Errorf("creating pcsc context: %w", err)
	}
	return ctx, nil
}

func (r *Reader) Close() error {
	var errs []error
	if err := r.disconnectCard(); err != nil {
		errs = append(errs, err)
	}
	if r.ctx != nil {
		if _, err := r.ctx.Release(); err != nil {
			errs = append(errs, fmt.Errorf("releasing pcsc context: %w", err))
		}
		r.ctx = nil
	}
	return errors.Join(errs...)
}

func (r *Reader) disconnectCard() error {
	if r.card == nil {
		return nil
	}

	_, err := r.card.Disconnect(goscard.SCardLeaveCard)
	r.card = nil
	if err != nil {
		return fmt.Errorf("disconnecting card: %w", err)
	}
	return nil
}

func (r *Reader) Transmit(ctx context.Context, req []byte) ([]byte, error) {
	if r.card == nil {
		return nil, errors.New("transmitting APDU: reader is closed")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	pci := goscard.SCardIoRequestT1
	if r.card.ActiveProtocol() == goscard.SCardProtocolT0 {
		pci = goscard.SCardIoRequestT0
	}

	recv, _, err := r.card.Transmit(&pci, req, nil)
	if err != nil {
		return nil, fmt.Errorf("transmitting APDU %X: %w", req, err)
	}
	return recv, nil
}

var _ usimreader.Transmitter = (*Reader)(nil)
