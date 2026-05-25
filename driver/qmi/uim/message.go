package uim

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/damonto/ims-client/driver/qmi/protocol"
)

const (
	qmiTLVResult     = 0x02
	qmiTLVCardResult = 0x10

	authenticate3GContext = 3
	envelopeCommandSMSPP  = 9
)

func retryableSessionError(err error) bool {
	return errors.Is(err, protocol.QMIErrorSessionInactive) ||
		errors.Is(err, protocol.QMIErrorSessionInvalid) ||
		errors.Is(err, protocol.QMIErrorInvalidSessionType)
}

func tlvBytes(typ byte, value []byte) protocol.TLV {
	return protocol.TLV{Type: typ, Len: uint16(len(value)), Value: slices.Clone(value)}
}

func tlvUint8(typ, value byte) protocol.TLV {
	return protocol.TLV{Type: typ, Len: 1, Value: []byte{value}}
}

func tlvUint32(typ byte, value uint32) protocol.TLV {
	data := binary.LittleEndian.AppendUint32(nil, value)
	return protocol.TLV{Type: typ, Len: uint16(len(data)), Value: data}
}

func resultOK(resp protocol.Response) error {
	return resp.TLVs.Error()
}

func cardResultOK(resp protocol.Response) error {
	if err := resp.TLVs.Error(); err != nil {
		return err
	}
	return cardError(resp.TLVs)
}

func decodeLengthPrefixedBytes(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, errors.New("parsing QMI payload: length prefix is truncated")
	}

	length := int(binary.LittleEndian.Uint16(data[:2]))
	if len(data) < 2+length {
		return nil, errors.New("parsing QMI payload: value is truncated")
	}
	return slices.Clone(data[2 : 2+length]), nil
}

func putSessionValue(session Session, aid []byte) []byte {
	value := make([]byte, 0, 2+len(aid))
	value = append(value, byte(session), byte(len(aid)))
	value = append(value, aid...)
	return value
}

func putFileValue(path []byte) ([]byte, error) {
	fileID, filePath, err := splitFilePath(path)
	if err != nil {
		return nil, err
	}

	value := binary.LittleEndian.AppendUint16(nil, fileID)
	value = append(value, byte(len(filePath)))
	value = append(value, filePath...)
	return value, nil
}

func splitFilePath(path []byte) (uint16, []byte, error) {
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

func joinBytes(parts ...[]byte) []byte {
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

func tlvValue(tlvs protocol.TLVs, typ byte) ([]byte, bool) {
	value, ok := tlvs.Find(typ)
	if !ok {
		return nil, false
	}
	return slices.Clone(value.Value), true
}

func cardError(tlvs protocol.TLVs) error {
	value, ok := tlvValue(tlvs, qmiTLVCardResult)
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
	return cardStatusError(statusWord)
}

type cardStatusError uint16

func (e cardStatusError) Error() string {
	return fmt.Sprintf("unexpected status word 0x%04X", uint16(e))
}

type serviceVersion struct {
	Service protocol.ServiceType
	Major   uint16
	Minor   uint16
}

func decodeServiceVersions(resp protocol.Response) ([]serviceVersion, error) {
	value, ok := tlvValue(resp.TLVs, 0x01)
	if !ok {
		return nil, errors.New("reading QMI service versions: service list TLV missing")
	}
	if len(value) == 0 {
		return nil, errors.New("reading QMI service versions: service count is missing")
	}
	count := int(value[0])
	value = value[1:]
	if len(value) < count*5 {
		return nil, errors.New("reading QMI service versions: service list is truncated")
	}

	versions := make([]serviceVersion, 0, count)
	for i := range count {
		offset := i * 5
		versions = append(versions, serviceVersion{
			Service: protocol.ServiceType(value[offset]),
			Major:   binary.LittleEndian.Uint16(value[offset+1 : offset+3]),
			Minor:   binary.LittleEndian.Uint16(value[offset+3 : offset+5]),
		})
	}
	return versions, nil
}
