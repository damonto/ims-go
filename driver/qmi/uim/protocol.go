package uim

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/damonto/ims-client/driver/qmi/protocol"
)

type Request = protocol.Request
type Response = protocol.Response
type Transport = protocol.Transport
type TLV = protocol.TLV
type TLVs = protocol.TLVs
type Error = protocol.QMIError
type Service = protocol.ServiceType
type MessageID = protocol.MessageID

const (
	ServiceControl = protocol.QMIServiceControl
	ServiceUIM     = protocol.QMIServiceUIM

	MessageProxyOpen        = protocol.QMICtlInternalProxyOpen
	MessageAllocateClientID = protocol.QMICtlCmdAllocateClientID
	MessageReleaseClientID  = protocol.QMICtlCmdReleaseClientID

	MessageReadTransparent = protocol.MessageID(0x0020)
	MessageReadRecord      = protocol.MessageID(0x0021)
	MessageGetFileAttrs    = protocol.MessageID(0x0024)
	MessageGetCardStatus   = protocol.QMIUIMGetCardStatus
	MessageAuthenticate    = protocol.MessageID(0x0034)
	MessageSwitchSlot      = protocol.QMIUIMSwitchSlot
	MessageGetSlotStatus   = protocol.QMIUIMGetSlotStatus

	TLVResult     = 0x02
	TLVCardResult = 0x10

	Authenticate3GContext = 3

	ErrorNoMemory           = protocol.QMIErrorNoMemory
	ErrorDeviceInUse        = protocol.QMIErrorDeviceInUse
	ErrorDeviceUnsupported  = protocol.QMIErrorDeviceUnsupported
	ErrorInvalidArgument    = protocol.QMIErrorInvalidArgument
	ErrorSessionInactive    = protocol.QMIErrorSessionInactive
	ErrorSessionInvalid     = protocol.QMIErrorSessionInvalid
	ErrorSIMFileNotFound    = protocol.QMIErrorSimFileNotFound
	ErrorNotSupported       = protocol.QMIErrorNotSupported
	ErrorInvalidSessionType = protocol.QMIErrorInvalidSessionType
	ErrorNoSIM              = protocol.QMIErrorNoSim
)

func RetryableSessionError(err error) bool {
	return errors.Is(err, ErrorSessionInactive) ||
		errors.Is(err, ErrorSessionInvalid) ||
		errors.Is(err, ErrorInvalidSessionType)
}

func TLVBytes(typ byte, value []byte) TLV {
	return TLV{Type: typ, Len: uint16(len(value)), Value: slices.Clone(value)}
}

func TLVUint8(typ, value byte) TLV {
	return TLV{Type: typ, Len: 1, Value: []byte{value}}
}

func TLVUint16(typ byte, value uint16) TLV {
	data := binary.LittleEndian.AppendUint16(nil, value)
	return TLV{Type: typ, Len: uint16(len(data)), Value: data}
}

func TLVUint32(typ byte, value uint32) TLV {
	data := binary.LittleEndian.AppendUint32(nil, value)
	return TLV{Type: typ, Len: uint16(len(data)), Value: data}
}

func MustResultOK(resp Response) error {
	return resp.TLVs.Error()
}

func WithCardResult(resp Response) error {
	if err := resp.TLVs.Error(); err != nil {
		return err
	}
	return cardError(resp.TLVs)
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

func tlvValue(tlvs TLVs, typ byte) ([]byte, bool) {
	value, ok := tlvs.Find(typ)
	if !ok {
		return nil, false
	}
	return slices.Clone(value.Value), true
}

func cardError(tlvs TLVs) error {
	value, ok := tlvValue(tlvs, TLVCardResult)
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
