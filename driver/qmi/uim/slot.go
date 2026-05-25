package uim

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/damonto/ims-client/driver/qmi/protocol"
)

func (r *Reader) ensureSlotActivated(ctx context.Context) error {
	activeSlot, err := r.currentActivatedSlot(ctx)
	if err != nil {
		if errors.Is(err, protocol.QMIErrorNotSupported) {
			return nil
		}
		return fmt.Errorf("activating slot %d: %w", r.Slot, err)
	}
	if activeSlot == r.Slot {
		return nil
	}
	if err := r.switchSlot(ctx, r.Slot); err != nil {
		return fmt.Errorf("activating slot %d: %w", r.Slot, err)
	}
	if err := r.waitForSlotReady(ctx); err != nil {
		return fmt.Errorf("activating slot %d: %w", r.Slot, err)
	}
	return nil
}

func (r *Reader) currentActivatedSlot(ctx context.Context) (uint8, error) {
	resp, err := r.request(ctx, protocol.QMIServiceUIM, r.ClientID, protocol.QMIUIMGetSlotStatus, nil, slotStatusTimeout)
	if err != nil {
		return 0, err
	}
	if err := resultOK(resp); err != nil {
		return 0, err
	}

	status, err := decodeSlotStatus(resp)
	if err != nil {
		return 0, err
	}
	return status.ActiveSlot, nil
}

func (r *Reader) switchSlot(ctx context.Context, slot uint8) error {
	resp, err := r.request(ctx, protocol.QMIServiceUIM, r.ClientID, protocol.QMIUIMSwitchSlot, protocol.TLVs{
		tlvUint8(0x01, 1),
		tlvUint32(0x02, uint32(slot)),
	}, DefaultRequestTimeout)
	if err != nil {
		return err
	}
	return resultOK(resp)
}

func (r *Reader) waitForSlotReady(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, slotReadyTimeout)
	defer cancel()

	for {
		status, err := r.getCardStatus(ctx)
		if err == nil && status.Ready() {
			return nil
		}
		if ctx.Err() != nil {
			if err != nil {
				return fmt.Errorf("waiting for card readiness: %w", err)
			}
			return errors.New("waiting for card readiness: timeout")
		}

		timer := time.NewTimer(slotPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			if err != nil {
				return fmt.Errorf("waiting for card readiness: %w", err)
			}
			return errors.New("waiting for card readiness: timeout")
		case <-timer.C:
		}
	}
}

func (r *Reader) getCardStatus(ctx context.Context) (CardStatus, error) {
	resp, err := r.request(ctx, protocol.QMIServiceUIM, r.ClientID, protocol.QMIUIMGetCardStatus, nil, DefaultRequestTimeout)
	if err != nil {
		return CardStatus{}, err
	}
	if err := resultOK(resp); err != nil {
		return CardStatus{}, err
	}
	return decodeCardStatus(resp)
}
