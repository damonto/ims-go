package qrtr

import (
	"encoding/binary"
	"errors"

	"github.com/damonto/ims-client/driver/qmi/core"
)

func ParseResponse(data []byte) (core.Response, error) {
	if len(data) < 7 {
		return core.Response{}, errors.New("parsing QRTR response: packet is too short")
	}

	resp := core.Response{}
	offset := 1
	resp.TransactionID = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	resp.MessageID = core.MessageID(binary.LittleEndian.Uint16(data[offset : offset+2]))
	offset += 2

	messageLength := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if len(data) < offset+messageLength {
		return core.Response{}, errors.New("parsing QRTR response: TLVs are truncated")
	}

	tlvs, err := core.ParseTLVs(data[offset : offset+messageLength])
	if err != nil {
		return core.Response{}, err
	}
	resp.TLVs = tlvs
	return resp, nil
}
