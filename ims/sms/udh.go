package sms

import (
	"encoding/binary"
	"errors"
)

const (
	concatIEI8Bit  = 0x00
	concatIEI16Bit = 0x08
	concatUDH8Len  = 0x05
	concatIEDL8Bit = 0x03
)

type concatInfo struct {
	Reference  uint16
	Total      byte
	Sequence   byte
	SixteenBit bool
}

func buildConcatUDH8(reference, total, sequence byte) []byte {
	return []byte{concatUDH8Len, concatIEI8Bit, concatIEDL8Bit, reference, total, sequence}
}

func decodeUserDataHeader(payload []byte) (int, *concatInfo, error) {
	if len(payload) == 0 {
		return 0, nil, errors.New("decoding SMS UDH: missing UDHL")
	}
	headerLen := int(payload[0]) + 1
	if len(payload) < headerLen {
		return 0, nil, errors.New("decoding SMS UDH: truncated header")
	}
	concat, err := decodeConcatInfo(payload[:headerLen])
	if err != nil {
		return 0, nil, err
	}
	return headerLen, concat, nil
}

func decodeConcatInfo(header []byte) (*concatInfo, error) {
	if len(header) == 0 {
		return nil, nil
	}
	limit := int(header[0]) + 1
	if len(header) < limit {
		return nil, errors.New("decoding SMS UDH: truncated information elements")
	}
	for idx := 1; idx < limit; {
		if idx+2 > limit {
			return nil, errors.New("decoding SMS UDH: truncated information element")
		}
		iei := header[idx]
		length := int(header[idx+1])
		idx += 2
		if idx+length > limit {
			return nil, errors.New("decoding SMS UDH: truncated information element data")
		}
		data := header[idx : idx+length]
		idx += length
		switch iei {
		case concatIEI8Bit:
			if length != 3 {
				continue
			}
			if data[1] == 0 || data[2] == 0 || data[2] > data[1] {
				continue
			}
			return &concatInfo{Reference: uint16(data[0]), Total: data[1], Sequence: data[2]}, nil
		case concatIEI16Bit:
			if length != 4 {
				continue
			}
			if data[2] == 0 || data[3] == 0 || data[3] > data[2] {
				continue
			}
			return &concatInfo{Reference: binary.BigEndian.Uint16(data[:2]), Total: data[2], Sequence: data[3], SixteenBit: true}, nil
		}
	}
	return nil, nil
}
