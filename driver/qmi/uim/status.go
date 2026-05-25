package uim

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/damonto/ims-client/driver/qmi/protocol"
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

func decodeSlotStatus(resp protocol.Response) (SlotStatus, error) {
	value, ok := tlvValue(resp.TLVs, 0x10)
	if !ok {
		return SlotStatus{}, errors.New("reading slot status: status TLV missing")
	}

	buf := bytes.NewReader(value)
	count, err := readUint8(buf, "slot count")
	if err != nil {
		return SlotStatus{}, fmt.Errorf("reading slot status: %w", err)
	}

	status := SlotStatus{}
	for i := range count {
		if _, err := readUint32(buf, "physical card status"); err != nil {
			return SlotStatus{}, fmt.Errorf("reading slot status: %w", err)
		}
		slotState, err := readUint32(buf, "physical slot status")
		if err != nil {
			return SlotStatus{}, fmt.Errorf("reading slot status: %w", err)
		}
		if _, err := readUint8(buf, "logical slot"); err != nil {
			return SlotStatus{}, fmt.Errorf("reading slot status: %w", err)
		}
		if _, err := readUint8Array(buf, "ICCID"); err != nil {
			return SlotStatus{}, fmt.Errorf("reading slot status: %w", err)
		}

		if slotState == 1 {
			status.ActiveSlot = uint8(i + 1)
		}
	}
	return status, nil
}

func decodeCardStatus(resp protocol.Response) (CardStatus, error) {
	value, ok := tlvValue(resp.TLVs, 0x10)
	if !ok {
		return CardStatus{}, errors.New("reading card status: status TLV missing")
	}

	buf := bytes.NewReader(value)
	for _, field := range []string{"GW primary index", "1X primary index", "GW secondary index", "1X secondary index"} {
		if _, err := readUint16(buf, field); err != nil {
			return CardStatus{}, fmt.Errorf("reading card status: %w", err)
		}
	}

	cardCount, err := readUint8(buf, "card count")
	if err != nil {
		return CardStatus{}, fmt.Errorf("reading card status: %w", err)
	}

	status := CardStatus{
		Cards: make([]Card, 0, cardCount),
	}
	for range cardCount {
		cardState, err := readUint8(buf, "card state")
		if err != nil {
			return CardStatus{}, fmt.Errorf("reading card status: %w", err)
		}
		if err := skipBytes(buf, 4, "card PIN/error status"); err != nil {
			return CardStatus{}, fmt.Errorf("reading card status: %w", err)
		}

		appCount, err := readUint8(buf, "application count")
		if err != nil {
			return CardStatus{}, fmt.Errorf("reading card status: %w", err)
		}
		entry := Card{State: cardState}
		entry.Applications = make([]Application, 0, appCount)
		for range appCount {
			appType, err := readUint8(buf, "application type")
			if err != nil {
				return CardStatus{}, fmt.Errorf("reading card status: %w", err)
			}
			appState, err := readUint8(buf, "application state")
			if err != nil {
				return CardStatus{}, fmt.Errorf("reading card status: %w", err)
			}
			entry.Applications = append(entry.Applications, Application{
				Type:  appType,
				State: appState,
			})

			if err := skipBytes(buf, 4, "application personalization status"); err != nil {
				return CardStatus{}, fmt.Errorf("reading card status: %w", err)
			}
			if _, err := readUint8Array(buf, "application identifier"); err != nil {
				return CardStatus{}, fmt.Errorf("reading card status: %w", err)
			}
			if err := skipBytes(buf, 7, "application PIN status"); err != nil {
				return CardStatus{}, fmt.Errorf("reading card status: %w", err)
			}
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

func decodeFileAttributes(data []byte) (FileAttributes, error) {
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

func cardSessionForSlot(slot uint8) (Session, error) {
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

func nonProvisioningSessionForSlot(slot uint8) (Session, error) {
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

func readValue(r io.Reader, out any, field string) error {
	if err := binary.Read(r, binary.LittleEndian, out); err != nil {
		return fmt.Errorf("read %s: %w", field, err)
	}
	return nil
}

func readUint8(r io.Reader, field string) (uint8, error) {
	var value uint8
	if err := readValue(r, &value, field); err != nil {
		return 0, err
	}
	return value, nil
}

func readUint16(r io.Reader, field string) (uint16, error) {
	var value uint16
	if err := readValue(r, &value, field); err != nil {
		return 0, err
	}
	return value, nil
}

func readUint32(r io.Reader, field string) (uint32, error) {
	var value uint32
	if err := readValue(r, &value, field); err != nil {
		return 0, err
	}
	return value, nil
}

func readUint8Array(r *bytes.Reader, field string) ([]byte, error) {
	n, err := readUint8(r, field+" length")
	if err != nil {
		return nil, err
	}
	value := make([]byte, n)
	if _, err := io.ReadFull(r, value); err != nil {
		return nil, fmt.Errorf("read %s: %w", field, err)
	}
	return value, nil
}

func skipBytes(r *bytes.Reader, n int, field string) error {
	if r.Len() < n {
		return fmt.Errorf("read %s: %w", field, io.ErrUnexpectedEOF)
	}
	if _, err := r.Seek(int64(n), io.SeekCurrent); err != nil {
		return fmt.Errorf("skip %s: %w", field, err)
	}
	return nil
}
