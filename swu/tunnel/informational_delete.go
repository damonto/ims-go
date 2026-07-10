package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/damonto/ims-go/swu/esp"
	"github.com/damonto/ims-go/swu/ike"
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
	if hasInvalidDeleteProtocol(deletePayloads) {
		return invalidSyntaxNotify(), informationalAction{}, true, nil
	}
	for _, deletePayload := range deletePayloads {
		if deletePayload.ProtocolID == protocolIDIKE {
			return nil, informationalAction{
				deleteIKE:             true,
				reactivationRequested: reactivationRequested,
				pdnDeactivated:        !reactivationRequested,
			}, true, nil
		}
	}
	responseSPIs, action, err := recognizedESPDeleteResponse(state, deletePayloads, reactivationRequested)
	if err != nil {
		return nil, informationalAction{}, true, err
	}
	if len(responseSPIs) == 0 {
		return nil, informationalAction{}, true, nil
	}
	return []ike.Payload{
		&ike.DeletePayload{
			ProtocolID: protocolIDESP,
			SPIs:       spiBytes(responseSPIs),
		},
	}, action, true, nil
}

func hasInvalidDeleteProtocol(deletePayloads []*ike.DeletePayload) bool {
	for _, deletePayload := range deletePayloads {
		switch deletePayload.ProtocolID {
		case protocolIDIKE, protocolIDAH, protocolIDESP:
			continue
		default:
			return true
		}
	}
	return false
}

func recognizedESPDeleteResponse(state informationalState, deletePayloads []*ike.DeletePayload, reactivationRequested bool) ([]uint32, informationalAction, error) {
	responseSPIs := make([]uint32, 0)
	action := informationalAction{}
	for _, deletePayload := range deletePayloads {
		if deletePayload.ProtocolID != protocolIDESP {
			continue
		}
		for _, spi := range deletePayload.SPIs {
			if len(spi) != 4 {
				return nil, informationalAction{}, fmt.Errorf("parsing informational delete: invalid esp spi length %d", len(spi))
			}
			requestSPI := binary.BigEndian.Uint32(spi)
			responseSPI, activeChild := state.activeESPDeleteResponseSPI(requestSPI)
			if !activeChild {
				if responseSPI, ok := state.retiredESPDeleteResponseSPI(requestSPI); ok {
					responseSPIs = appendUniqueSPI(responseSPIs, responseSPI)
					action.deleteRetiredChildSPIs = appendUniqueSPI(action.deleteRetiredChildSPIs, responseSPI)
				}
				continue
			}
			if state.pendingChild {
				action.promotePendingChild = true
				action.deleteRetiredChildSPIs = appendUniqueSPI(action.deleteRetiredChildSPIs, responseSPI)
			} else {
				action.deleteChild = true
				action.reactivationRequested = reactivationRequested
				action.pdnDeactivated = !reactivationRequested
			}
			responseSPIs = appendUniqueSPI(responseSPIs, responseSPI)
		}
	}
	return responseSPIs, action, nil
}

func (state informationalState) activeESPDeleteResponseSPI(requestSPI uint32) (uint32, bool) {
	if !esp.ValidSPI(requestSPI) || !esp.ValidSPI(state.outboundSPI) || requestSPI != state.outboundSPI {
		return 0, false
	}
	if state.pendingChild {
		if !esp.ValidSPI(state.oldInboundSPI) {
			return 0, false
		}
		return state.oldInboundSPI, true
	}
	if !esp.ValidSPI(state.inboundSPI) {
		return 0, false
	}
	return state.inboundSPI, true
}

func (state informationalState) retiredESPDeleteResponseSPI(spi uint32) (uint32, bool) {
	for _, child := range state.retiredChildSAs {
		if esp.ValidSPI(child.inboundSPI) && esp.ValidSPI(child.outboundSPI) && spi == child.outboundSPI {
			return child.inboundSPI, true
		}
	}
	return 0, false
}

func appendUniqueSPI(spis []uint32, spi uint32) []uint32 {
	if spi == 0 || slices.Contains(spis, spi) {
		return spis
	}
	return append(spis, spi)
}

func spiBytes(spis []uint32) [][]byte {
	data := make([][]byte, 0, len(spis))
	for _, spi := range spis {
		data = append(data, uint32Bytes(spi))
	}
	return data
}

func invalidSyntaxNotify() []ike.Payload {
	return []ike.Payload{&ike.NotifyPayload{NotifyType: notifyTypeInvalidSyntax}}
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
