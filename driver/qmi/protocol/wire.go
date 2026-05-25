package protocol

import (
	"encoding/binary"
	"errors"
	"slices"
)

func ParseTLVs(data []byte) (TLVs, error) {
	items := make(TLVs, 0, len(data)/4)
	for len(data) > 0 {
		if len(data) < 3 {
			return nil, errors.New("truncated TLV header")
		}

		length := int(binary.LittleEndian.Uint16(data[1:3]))
		if len(data) < 3+length {
			return nil, errors.New("truncated TLV value")
		}

		items = append(items, TLV{
			Type:  data[0],
			Len:   uint16(length),
			Value: slices.Clone(data[3 : 3+length]),
		})
		data = data[3+length:]
	}
	return items, nil
}

func (ts TLVs) MarshalBinary() []byte {
	size := 0
	for _, tlv := range ts {
		size += 3 + len(tlv.Value)
	}

	out := make([]byte, 0, size)
	for _, tlv := range ts {
		out = append(out, tlv.Type)
		out = binary.LittleEndian.AppendUint16(out, uint16(len(tlv.Value)))
		out = append(out, tlv.Value...)
	}
	return out
}
