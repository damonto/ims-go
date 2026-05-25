package qrtr

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/damonto/ims-client/driver/qmi/protocol"
)

type response struct {
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
		Service:       protocol.ServiceUIM,
		TransactionID: wire.TransactionID,
		MessageID:     wire.MessageID,
		TLVs:          wire.TLVs,
	}, nil
}

func (r *response) UnmarshalBinary(data []byte) error {
	const headerLen = 7
	if len(data) < headerLen {
		return fmt.Errorf("parsing QRTR response: data too short: got %d bytes", len(data))
	}

	reader := bytes.NewReader(data)
	var header Header
	if err := binary.Read(reader, binary.LittleEndian, &header); err != nil {
		return fmt.Errorf("parsing QRTR response: read QMI header: %w", err)
	}
	r.MessageType = header.MessageType
	r.TransactionID = header.TransactionID
	r.MessageID = header.MessageID
	r.MessageLength = header.MessageLength

	if r.MessageType != protocol.MessageTypeResponse {
		return fmt.Errorf("parsing QRTR response: unexpected message type 0x%02X", r.MessageType)
	}
	if got, want := reader.Len(), int(r.MessageLength); got != want {
		return fmt.Errorf("parsing QRTR response: QMI TLV length mismatch: got %d bytes, header declares %d", got, want)
	}
	if r.MessageLength > 0 {
		tlvs, err := protocol.ParseTLVs(data[headerLen : headerLen+int(r.MessageLength)])
		if err != nil {
			return err
		}
		r.TLVs = tlvs
	}
	return nil
}
