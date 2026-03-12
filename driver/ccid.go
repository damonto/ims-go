package driver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/ElMostafaIdrassi/goscard"

	"github.com/damonto/ims-client/apdu"
)

var ErrReaderNotSelected = errors.New("reader not selected")

type CCID struct {
	ctx        *goscard.Context
	card       *goscard.Card
	readerName string
}

var (
	pcscInitOnce sync.Once
	pcscInitErr  error
)

func NewCCID() (*CCID, error) {
	pcscInitOnce.Do(func() {
		pcscInitErr = goscard.Initialize(goscard.NewDefaultLogger(goscard.LogLevelNone))
	})
	if pcscInitErr != nil {
		return nil, fmt.Errorf("initializing pcsc: %w", pcscInitErr)
	}

	ctx, _, err := goscard.NewContext(goscard.SCardScopeSystem, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("creating pcsc context: %w", err)
	}

	return &CCID{ctx: &ctx}, nil
}

func (r *CCID) ListReaders() ([]string, error) {
	if r.ctx == nil {
		return nil, errors.New("listing readers: driver is closed")
	}

	readers, _, err := r.ctx.ListReaders(nil)
	if err != nil {
		return nil, fmt.Errorf("listing readers: %w", err)
	}
	return slices.Clone(readers), nil
}

func (r *CCID) SetReader(name string) error {
	if r.ctx == nil {
		return errors.New("selecting reader: driver is closed")
	}

	name = strings.TrimSpace(name)
	if err := validateReaderName(name); err != nil {
		return err
	}

	readers, err := r.ListReaders()
	if err != nil {
		return err
	}
	if err := ensureReaderExists(readers, name); err != nil {
		return err
	}
	if r.readerName == name && r.card != nil {
		return nil
	}

	card, _, err := r.ctx.Connect(name, goscard.SCardShareShared, goscard.SCardProtocolT0|goscard.SCardProtocolT1)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", name, err)
	}
	if err := r.disconnectCard(); err != nil {
		_, _ = card.Disconnect(goscard.SCardLeaveCard)
		return err
	}

	r.card = &card
	r.readerName = name
	return nil
}

func validateReaderName(name string) error {
	if name == "" {
		return errors.New("selecting reader: reader name is empty")
	}
	return nil
}

func ensureReaderExists(readers []string, wanted string) error {
	if !slices.Contains(readers, wanted) {
		return fmt.Errorf("selecting %q: %w", wanted, apdu.ErrReaderNotFound)
	}
	return nil
}

func (r *CCID) disconnectCard() error {
	if r.card == nil {
		return nil
	}

	_, err := r.card.Disconnect(goscard.SCardLeaveCard)
	r.card = nil
	r.readerName = ""
	if err != nil {
		return fmt.Errorf("disconnecting card: %w", err)
	}
	return nil
}

func (r *CCID) Close() error {
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

func (r *CCID) Transmit(ctx context.Context, req *apdu.Request) (apdu.Response, error) {
	if r.card == nil {
		return nil, fmt.Errorf("transmitting APDU: %w", ErrReaderNotSelected)
	}
	if ctx == nil {
		ctx = context.Background()
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
	recv, _, err := r.card.Transmit(&pci, req.APDU(), nil)
	if err != nil {
		return nil, fmt.Errorf("transmitting APDU %s: %w", req.String(), err)
	}
	return apdu.Response(recv), nil
}

var _ apdu.Driver = (*CCID)(nil)
