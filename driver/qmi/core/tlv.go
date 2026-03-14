package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

type TLV struct {
	Type  byte
	Value []byte
}

type TLVs []TLV

func (ts TLVs) MarshalBinary() []byte {
	var out []byte
	for _, tlv := range ts {
		out = append(out, tlv.Type)
		out = binary.LittleEndian.AppendUint16(out, uint16(len(tlv.Value)))
		out = append(out, tlv.Value...)
	}
	return out
}

func ParseTLVs(data []byte) (TLVs, error) {
	items := make(TLVs, 0, len(data)/4)
	for len(data) > 0 {
		if len(data) < 3 {
			return nil, errors.New("parsing QMI TLVs: truncated header")
		}

		length := int(binary.LittleEndian.Uint16(data[1:3]))
		if len(data) < 3+length {
			return nil, errors.New("parsing QMI TLVs: truncated value")
		}

		items = append(items, TLV{
			Type:  data[0],
			Value: slices.Clone(data[3 : 3+length]),
		})
		data = data[3+length:]
	}
	return items, nil
}

func (ts TLVs) Find(typ byte) ([]byte, bool) {
	for _, tlv := range ts {
		if tlv.Type == typ {
			return slices.Clone(tlv.Value), true
		}
	}
	return nil, false
}

func (ts TLVs) ResultError() error {
	value, ok := ts.Find(TLVResult)
	if !ok {
		return errors.New("parsing QMI result: result TLV missing")
	}
	if len(value) < 4 {
		return errors.New("parsing QMI result: result TLV is truncated")
	}
	if binary.LittleEndian.Uint16(value[:2]) == 0 {
		return nil
	}
	return Error(binary.LittleEndian.Uint16(value[2:4]))
}

func (ts TLVs) CardError() error {
	value, ok := ts.Find(TLVCardResult)
	if !ok {
		return nil
	}
	if len(value) < 2 {
		return errors.New("parsing QMI card result: TLV is truncated")
	}

	statusWord := uint16(value[0])<<8 | uint16(value[1])
	if statusWord == 0x9000 {
		return nil
	}
	return CardStatusError(statusWord)
}

type CardStatusError uint16

func (e CardStatusError) Error() string {
	return fmt.Sprintf("unexpected status word 0x%04X", uint16(e))
}

func TLVBytes(typ byte, value []byte) TLV {
	return TLV{Type: typ, Value: slices.Clone(value)}
}

func TLVUint8(typ, value byte) TLV {
	return TLV{Type: typ, Value: []byte{value}}
}

func TLVUint16(typ byte, value uint16) TLV {
	return TLV{Type: typ, Value: binary.LittleEndian.AppendUint16(nil, value)}
}

func TLVUint32(typ byte, value uint32) TLV {
	return TLV{Type: typ, Value: binary.LittleEndian.AppendUint32(nil, value)}
}

func MustResultOK(resp Response) error {
	return resp.TLVs.ResultError()
}

func WithCardResult(resp Response) error {
	if err := resp.TLVs.ResultError(); err != nil {
		return err
	}
	return resp.TLVs.CardError()
}

func DecodeLengthPrefixedBytes(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, errors.New("parsing QMI payload: length prefix is truncated")
	}

	length := int(binary.LittleEndian.Uint16(data[:2]))
	if len(data) < 2+length {
		return nil, errors.New("parsing QMI payload: value is truncated")
	}
	return slices.Clone(data[2 : 2+length]), nil
}

func PutSessionValue(session Session, aid []byte) []byte {
	value := make([]byte, 0, 2+len(aid))
	value = append(value, byte(session), byte(len(aid)))
	value = append(value, aid...)
	return value
}

func PutFileValue(path []byte) ([]byte, error) {
	fileID, filePath, err := SplitFilePath(path)
	if err != nil {
		return nil, err
	}

	value := binary.LittleEndian.AppendUint16(nil, fileID)
	value = append(value, byte(len(filePath)))
	value = append(value, filePath...)
	return value, nil
}

func SplitFilePath(path []byte) (uint16, []byte, error) {
	if len(path) < 2 || len(path)%2 != 0 {
		return 0, nil, fmt.Errorf("encoding SIM path %X: path length must be an even number of bytes", path)
	}

	fileID := binary.BigEndian.Uint16(path[len(path)-2:])
	filePath := make([]byte, 0, len(path)-2)
	for i := 0; i < len(path)-2; i += 2 {
		filePath = append(filePath, path[i+1], path[i])
	}
	return fileID, filePath, nil
}

func Buffer(parts ...[]byte) []byte {
	total := 0
	for _, part := range parts {
		total += len(part)
	}

	buf := make([]byte, 0, total)
	for _, part := range parts {
		buf = append(buf, part...)
	}
	return buf
}
