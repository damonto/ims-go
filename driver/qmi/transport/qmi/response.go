package qmi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/damonto/ims-client/driver/qmi/core"
)

func ParseResponse(data []byte) (core.Response, error) {
	if len(data) < 11 {
		return core.Response{}, errors.New("parsing QMI response: packet is too short")
	}
	if data[0] != core.QMUXIfType {
		return core.Response{}, fmt.Errorf("parsing QMI response: unexpected interface type 0x%02X", data[0])
	}

	resp := core.Response{
		Service:  core.Service(data[4]),
		ClientID: data[5],
	}

	offset := 6
	offset++
	if resp.Service == core.ServiceControl {
		resp.TransactionID = uint16(data[offset])
		offset++
	} else {
		if len(data) < offset+2 {
			return core.Response{}, errors.New("parsing QMI response: transaction ID is truncated")
		}
		resp.TransactionID = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}

	if len(data) < offset+4 {
		return core.Response{}, errors.New("parsing QMI response: header is truncated")
	}
	resp.MessageID = core.MessageID(binary.LittleEndian.Uint16(data[offset : offset+2]))
	offset += 2

	messageLength := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if len(data) < offset+messageLength {
		return core.Response{}, errors.New("parsing QMI response: TLVs are truncated")
	}

	tlvs, err := core.ParseTLVs(data[offset : offset+messageLength])
	if err != nil {
		return core.Response{}, err
	}
	resp.TLVs = tlvs
	return resp, nil
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
