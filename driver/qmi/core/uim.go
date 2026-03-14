package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

type FileAttributes struct {
	FileSize    uint16
	FileID      uint16
	FileType    byte
	RecordSize  uint16
	RecordCount uint16
	Raw         []byte
}

type SlotStatus struct {
	ActiveSlot uint8
}

type CardStatus struct {
	Cards []Card
}

type Card struct {
	State        byte
	Applications []Application
}

type Application struct {
	Type  byte
	State byte
}

func DecodeSlotStatus(resp Response) (SlotStatus, error) {
	value, ok := resp.TLVs.Find(0x10)
	if !ok {
		return SlotStatus{}, errors.New("reading slot status: status TLV missing")
	}
	if len(value) == 0 {
		return SlotStatus{}, errors.New("reading slot status: status TLV is empty")
	}

	count := int(value[0])
	offset := 1
	status := SlotStatus{}
	for i := 0; i < count; i++ {
		if len(value[offset:]) < 10 {
			return SlotStatus{}, errors.New("reading slot status: slot entry is truncated")
		}

		slotState := binary.LittleEndian.Uint32(value[offset+4 : offset+8])
		offset += 8
		offset++

		iccidLength := int(value[offset])
		offset++
		if len(value[offset:]) < iccidLength {
			return SlotStatus{}, errors.New("reading slot status: ICCID is truncated")
		}
		offset += iccidLength

		if slotState == 1 {
			status.ActiveSlot = uint8(i + 1)
		}
	}
	return status, nil
}

func DecodeCardStatus(resp Response) (CardStatus, error) {
	value, ok := resp.TLVs.Find(0x10)
	if !ok {
		return CardStatus{}, errors.New("reading card status: status TLV missing")
	}
	if len(value) < 9 {
		return CardStatus{}, errors.New("reading card status: status TLV is truncated")
	}

	offset := 8
	cardCount := int(value[offset])
	offset++

	status := CardStatus{
		Cards: make([]Card, 0, cardCount),
	}
	for i := 0; i < cardCount; i++ {
		if len(value[offset:]) < 6 {
			return CardStatus{}, errors.New("reading card status: card entry is truncated")
		}

		entry := Card{State: value[offset]}
		offset += 5

		appCount := int(value[offset])
		offset++
		entry.Applications = make([]Application, 0, appCount)
		for j := 0; j < appCount; j++ {
			if len(value[offset:]) < 30 {
				return CardStatus{}, errors.New("reading card status: application entry is truncated")
			}
			entry.Applications = append(entry.Applications, Application{
				Type:  value[offset],
				State: value[offset+1],
			})
			offset += 30
		}
		status.Cards = append(status.Cards, entry)
	}
	return status, nil
}

func (s CardStatus) Ready() bool {
	for _, card := range s.Cards {
		if card.State != 1 {
			continue
		}
		for _, app := range card.Applications {
			if app.Type == 2 && app.State == 7 {
				return true
			}
		}
	}
	return false
}

func DecodeFileAttributes(data []byte) (FileAttributes, error) {
	if len(data) < 9 {
		return FileAttributes{}, errors.New("reading file attributes: attributes payload is truncated")
	}

	attrs := FileAttributes{
		FileSize:    binary.LittleEndian.Uint16(data[:2]),
		FileID:      binary.LittleEndian.Uint16(data[2:4]),
		FileType:    data[4],
		RecordSize:  binary.LittleEndian.Uint16(data[5:7]),
		RecordCount: binary.LittleEndian.Uint16(data[7:9]),
	}
	if len(data) < 26 {
		return attrs, nil
	}

	rawLength := int(binary.LittleEndian.Uint16(data[24:26]))
	if len(data) < 26+rawLength {
		return FileAttributes{}, errors.New("reading file attributes: raw data is truncated")
	}
	attrs.Raw = slices.Clone(data[26 : 26+rawLength])
	return attrs, nil
}

func CardSessionForSlot(slot uint8) (Session, error) {
	switch slot {
	case 1:
		return SessionCardSlot1, nil
	case 2:
		return SessionCardSlot2, nil
	case 3:
		return SessionCardSlot3, nil
	case 4:
		return SessionCardSlot4, nil
	case 5:
		return SessionCardSlot5, nil
	default:
		return 0, fmt.Errorf("mapping card session: slot %d is out of range", slot)
	}
}

func NonProvisioningSessionForSlot(slot uint8) (Session, error) {
	switch slot {
	case 1:
		return SessionNonProvisioningSlot1, nil
	case 2:
		return SessionNonProvisioningSlot2, nil
	case 3:
		return SessionNonProvisioningSlot3, nil
	case 4:
		return SessionNonProvisioningSlot4, nil
	case 5:
		return SessionNonProvisioningSlot5, nil
	default:
		return 0, fmt.Errorf("mapping nonprovisioning session: slot %d is out of range", slot)
	}
}
