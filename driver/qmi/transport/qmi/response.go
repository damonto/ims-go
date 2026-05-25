package qmi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/damonto/ims-client/driver/qmi/protocol"
)

type response struct {
	QMUXHeader
	TransactionID uint16
	MessageID     protocol.MessageID
	MessageType   protocol.MessageType
	MessageLength uint16
	TLVs          protocol.TLVs
}

func ParseResponse(data []byte) (protocol.Response, error) {
	var wire response
	if err := wire.UnmarshalBinary(data); err != nil {
		return protocol.Response{}, err
	}
	return protocol.Response{
		Service:       wire.ServiceType,
		ClientID:      wire.ClientID,
		TransactionID: wire.TransactionID,
		MessageID:     wire.MessageID,
		TLVs:          wire.TLVs,
	}, nil
}

func (r *response) UnmarshalBinary(data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("parsing QMI response: data too short: got %d bytes", len(data))
	}

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &r.QMUXHeader); err != nil {
		return fmt.Errorf("parsing QMI response: read QMUX header: %w", err)
	}
	if r.QMUXHeader.IfType != protocol.QMUXIfType {
		return fmt.Errorf("parsing QMI response: unexpected QMUX marker 0x%02X", r.QMUXHeader.IfType)
	}
	if got, want := len(data), int(r.QMUXHeader.Length)+1; got != want {
		return fmt.Errorf("parsing QMI response: QMUX length mismatch: got %d bytes, header declares %d", got, want)
	}

	if r.QMUXHeader.ServiceType == protocol.ServiceControl {
		var header Header[uint8]
		if err := binary.Read(reader, binary.LittleEndian, &header); err != nil {
			return fmt.Errorf("parsing QMI response: read control QMI header: %w", err)
		}
		r.MessageType = header.MessageType
		r.TransactionID = uint16(header.TransactionID)
		r.MessageID = header.MessageID
		r.MessageLength = header.MessageLength
	} else {
		var header Header[uint16]
		if err := binary.Read(reader, binary.LittleEndian, &header); err != nil {
			return fmt.Errorf("parsing QMI response: read service QMI header: %w", err)
		}
		r.MessageType = header.MessageType
		r.TransactionID = header.TransactionID
		r.MessageID = header.MessageID
		r.MessageLength = header.MessageLength
	}

	if r.MessageType != protocol.MessageTypeResponse {
		return fmt.Errorf("parsing QMI response: unexpected message type 0x%02X", r.MessageType)
	}
	if got, want := reader.Len(), int(r.MessageLength); got != want {
		return fmt.Errorf("parsing QMI response: QMI TLV length mismatch: got %d bytes, header declares %d", got, want)
	}
	if r.MessageLength > 0 {
		tlvs, err := protocol.ParseTLVs(data[len(data)-int(r.MessageLength):])
		if err != nil {
			return err
		}
		r.TLVs = tlvs
	}
	return nil
}

func ReadFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	length := int(binary.LittleEndian.Uint16(header[1:3])) + 1
	if length < len(header) {
		return nil, errors.New("reading QMI frame: invalid length")
	}

	frame := make([]byte, length)
	copy(frame, header)
	if _, err := io.ReadFull(r, frame[len(header):]); err != nil {
		return nil, err
	}
	return frame, nil
}
