package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/damonto/vowifi-go/swu/ike"
)

func (state informationalState) sealDeleteRequest(messageID uint32) ([][]byte, error) {
	return state.sealInitiatorRequest(messageID, []ike.Payload{&ike.DeletePayload{ProtocolID: protocolIDIKE}})
}

func (s *Session) sendDeleteRequest(ctx context.Context) error {
	state := s.currentInformationalState()
	if !state.canSendDelete() {
		return nil
	}
	release, err := s.acquireIKERequest(ctx, ikeActionCloseSWUSession)
	if err != nil {
		return err
	}
	defer release()
	messageID, err := s.allocateMessageID()
	if err != nil {
		return fmt.Errorf("closing swu session: %w", err)
	}
	key := state.responseMessageKey(messageID, exchangeTypeInformational)
	waiter := s.registerInformationalWaiter(key)
	defer s.unregisterInformationalWaiter(key, waiter)
	wires, err := state.sealDeleteRequest(messageID)
	if err != nil {
		return fmt.Errorf("closing swu session: sealing delete request: %w", err)
	}
	payloads, err := s.exchangeInformationalRequest(ctx, state, messageID, wires, waiter, ikeActionCloseSWUSession, false)
	if err != nil {
		return err
	}
	if err := validateIKEDeleteResponsePayloads(payloads); err != nil {
		return fmt.Errorf("closing swu session: %w", err)
	}
	return nil
}

func validateIKEDeleteResponsePayloads(payloads []ike.Payload) error {
	if len(payloads) != 0 {
		return fmt.Errorf("ike delete response payload count %d", len(payloads))
	}
	return nil
}

func buildDeleteResponsePayloads(state informationalState, payloads []ike.Payload) ([]ike.Payload, informationalAction, bool, error) {
	deletePayloads := findDeletePayloads(payloads)
	if len(deletePayloads) == 0 {
		return nil, informationalAction{}, false, nil
	}
	reactivationRequested := hasNotifyPayload(payloads, notifyTypeReactivationRequestedCause)
	for _, deletePayload := range deletePayloads {
		if deletePayload.ProtocolID == protocolIDIKE {
			return nil, informationalAction{
				deleteIKE:             true,
				reactivationRequested: reactivationRequested,
			}, true, nil
		}
	}
	if state.inboundSPI == 0 || state.outboundSPI == 0 {
		return nil, informationalAction{}, true, nil
	}
	for _, deletePayload := range deletePayloads {
		if deletePayload.ProtocolID != protocolIDESP {
			continue
		}
		for _, spi := range deletePayload.SPIs {
			if len(spi) != 4 {
				return nil, informationalAction{}, true, fmt.Errorf("parsing informational delete: invalid esp spi length %d", len(spi))
			}
			if binary.BigEndian.Uint32(spi) != state.outboundSPI {
				continue
			}
			responseSPI := state.inboundSPI
			action := informationalAction{
				deleteChild:           true,
				reactivationRequested: reactivationRequested,
			}
			if state.pendingChild {
				responseSPI = state.oldInboundSPI
				action = informationalAction{
					promotePendingChild:   true,
					deleteRetiredChildSPI: responseSPI,
				}
			}
			return []ike.Payload{
				&ike.DeletePayload{
					ProtocolID: protocolIDESP,
					SPIs:       [][]byte{uint32Bytes(responseSPI)},
				},
			}, action, true, nil
		}
	}
	for _, child := range state.retiredChildSAs {
		for _, deletePayload := range deletePayloads {
			if deletePayload.ProtocolID != protocolIDESP {
				continue
			}
			for _, spi := range deletePayload.SPIs {
				if len(spi) != 4 {
					return nil, informationalAction{}, true, fmt.Errorf("parsing informational delete: invalid esp spi length %d", len(spi))
				}
				if binary.BigEndian.Uint32(spi) != child.outboundSPI {
					continue
				}
				return []ike.Payload{
					&ike.DeletePayload{
						ProtocolID: protocolIDESP,
						SPIs:       [][]byte{uint32Bytes(child.inboundSPI)},
					},
				}, informationalAction{deleteRetiredChildSPI: child.inboundSPI}, true, nil
			}
		}
	}
	return nil, informationalAction{}, true, nil
}

func hasNotifyPayload(payloads []ike.Payload, notifyType uint16) bool {
	for _, payload := range payloads {
		notify, ok := payload.(*ike.NotifyPayload)
		if ok && notify.NotifyType == notifyType {
			return true
		}
	}
	return false
}

func findDeletePayloads(payloads []ike.Payload) []*ike.DeletePayload {
	deletes := make([]*ike.DeletePayload, 0)
	for _, payload := range payloads {
		deletePayload, ok := payload.(*ike.DeletePayload)
		if ok && deletePayload != nil {
			deletes = append(deletes, deletePayload)
		}
	}
	return deletes
}
