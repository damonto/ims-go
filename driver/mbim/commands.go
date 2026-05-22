package mbim

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf16"
)

type ProxyConfigRequest struct {
	TransactionID uint32
	DevicePath    string
	Timeout       uint32
	Response      *ProxyConfigResponse
}

func (r *ProxyConfigRequest) Request() *Request {
	devicePath := utf16Bytes(r.DevicePath + "\x00")
	data := make([]byte, 0, 12+len(devicePath))
	data = binary.LittleEndian.AppendUint32(data, 12)
	data = binary.LittleEndian.AppendUint32(data, uint32(len(devicePath)))
	data = binary.LittleEndian.AppendUint32(data, r.Timeout)
	data = append(data, devicePath...)

	r.Response = new(ProxyConfigResponse)
	return &Request{
		MessageType:   MessageTypeCommand,
		TransactionID: r.TransactionID,
		Command: command(
			ServiceMbimProxyControl,
			CIDProxyControlConfiguration,
			CommandTypeSet,
			data,
		),
		Response: r.Response,
	}
}

type ProxyConfigResponse struct{}

func (r *ProxyConfigResponse) UnmarshalBinary([]byte) error { return nil }

type OpenDeviceRequest struct {
	TransactionID uint32
	Response      *OpenDeviceResponse
}

func (r *OpenDeviceRequest) Request() *Request {
	r.Response = new(OpenDeviceResponse)
	return &Request{
		MessageType:   MessageTypeOpen,
		TransactionID: r.TransactionID,
		Command:       r,
		Response:      r.Response,
	}
}

func (r *OpenDeviceRequest) MarshalBinary() ([]byte, error) {
	return binary.LittleEndian.AppendUint32(nil, maxControlTransfer), nil
}

type OpenDeviceResponse struct{}

func (r *OpenDeviceResponse) UnmarshalBinary([]byte) error { return nil }

type CloseRequest struct {
	TransactionID uint32
	Response      *CloseResponse
}

func (r *CloseRequest) Request() *Request {
	r.Response = new(CloseResponse)
	return &Request{
		MessageType:   MessageTypeClose,
		TransactionID: r.TransactionID,
		Timeout:       2 * time.Second,
		Command:       r,
		Response:      r.Response,
	}
}

func (r *CloseRequest) MarshalBinary() ([]byte, error) { return nil, nil }

type CloseResponse struct{}

func (r *CloseResponse) UnmarshalBinary([]byte) error { return nil }

type DeviceSlotMappingsRequest struct {
	TransactionID uint32
	SlotMappings  []SlotMapping
	Response      *DeviceSlotMappingsResponse
}

type SlotMapping struct {
	Slot uint32
}

func (r *DeviceSlotMappingsRequest) Request() *Request {
	mapCount := uint32(len(r.SlotMappings))
	data := binary.LittleEndian.AppendUint32(nil, mapCount)
	if mapCount > 0 {
		dataOffset := 4 + mapCount*8
		for i := range mapCount {
			data = binary.LittleEndian.AppendUint32(data, dataOffset+i*4)
			data = binary.LittleEndian.AppendUint32(data, 4)
		}
		for _, mapping := range r.SlotMappings {
			data = binary.LittleEndian.AppendUint32(data, mapping.Slot)
		}
	}

	commandType := uint32(CommandTypeQuery)
	if mapCount > 0 {
		commandType = CommandTypeSet
	}
	r.Response = new(DeviceSlotMappingsResponse)
	return &Request{
		MessageType:   MessageTypeCommand,
		TransactionID: r.TransactionID,
		Command: command(
			ServiceMsBasicConnectExtensions,
			CIDDeviceSlotMappings,
			commandType,
			data,
		),
		Response: r.Response,
	}
}

type DeviceSlotMappingsResponse struct {
	SlotMappings []SlotMapping
}

func (r *DeviceSlotMappingsResponse) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("parsing MBIM slot mappings: payload is truncated")
	}
	mapCount := binary.LittleEndian.Uint32(data[:4])
	if mapCount == 0 {
		r.SlotMappings = nil
		return nil
	}
	if mapCount > uint32((len(data)-4)/8) {
		return errors.New("parsing MBIM slot mappings: offset table is truncated")
	}

	r.SlotMappings = make([]SlotMapping, mapCount)
	for i := range mapCount {
		entryOffset := 4 + i*8
		slotDataOffset := binary.LittleEndian.Uint32(data[entryOffset : entryOffset+4])
		slotDataSize := binary.LittleEndian.Uint32(data[entryOffset+4 : entryOffset+8])
		if slotDataSize != 4 {
			return fmt.Errorf("parsing MBIM slot mappings: slot data size %d, want 4", slotDataSize)
		}
		if slotDataOffset > uint32(len(data)) || slotDataSize > uint32(len(data))-slotDataOffset {
			return errors.New("parsing MBIM slot mappings: slot data is truncated")
		}
		r.SlotMappings[i].Slot = binary.LittleEndian.Uint32(data[slotDataOffset : slotDataOffset+4])
	}
	return nil
}

type SubscriberReadyStatusRequest struct {
	TransactionID uint32
	Response      *SubscriberReadyStatusResponse
}

func (r *SubscriberReadyStatusRequest) Request() *Request {
	r.Response = new(SubscriberReadyStatusResponse)
	return &Request{
		MessageType:   MessageTypeCommand,
		TransactionID: r.TransactionID,
		Timeout:       time.Second,
		Command: command(
			ServiceBasicConnect,
			CIDSubscriberReadyStatus,
			CommandTypeQuery,
			nil,
		),
		Response: r.Response,
	}
}

type SubscriberReadyStatusResponse struct {
	ReadyState uint32
}

func (r *SubscriberReadyStatusResponse) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("parsing MBIM subscriber ready status: payload is truncated")
	}
	r.ReadyState = binary.LittleEndian.Uint32(data[:4])
	return nil
}

type ApplicationListRequest struct {
	TransactionID uint32
	Response      *ApplicationListResponse
}

func (r *ApplicationListRequest) Request() *Request {
	r.Response = new(ApplicationListResponse)
	return &Request{
		MessageType:   MessageTypeCommand,
		TransactionID: r.TransactionID,
		Command: command(
			ServiceMsUiccLowLevelAccess,
			CIDUiccApplicationList,
			CommandTypeQuery,
			nil,
		),
		Response: r.Response,
	}
}

type UICCApplication struct {
	Type  uint32
	AID   []byte
	Label string
}

type ApplicationListResponse struct {
	Version                uint32
	ActiveApplicationIndex uint32
	Applications           []UICCApplication
}

func (r *ApplicationListResponse) UnmarshalBinary(data []byte) error {
	if len(data) < 16 {
		return errors.New("parsing MBIM application list: payload is truncated")
	}
	r.Version = binary.LittleEndian.Uint32(data[:4])
	applicationCount := binary.LittleEndian.Uint32(data[4:8])
	r.ActiveApplicationIndex = binary.LittleEndian.Uint32(data[8:12])
	if applicationCount > uint32((len(data)-16)/8) {
		return errors.New("parsing MBIM application list: application table is truncated")
	}

	r.Applications = make([]UICCApplication, 0, applicationCount)
	for i := range applicationCount {
		entryOffset := 16 + i*8
		offset := binary.LittleEndian.Uint32(data[entryOffset : entryOffset+4])
		size := binary.LittleEndian.Uint32(data[entryOffset+4 : entryOffset+8])
		if offset > uint32(len(data)) || size > uint32(len(data))-offset {
			return errors.New("parsing MBIM application list: application entry is truncated")
		}
		app, err := parseUICCApplication(data, data[offset:offset+size])
		if err != nil {
			return fmt.Errorf("parsing MBIM application list entry %d: %w", i, err)
		}
		r.Applications = append(r.Applications, app)
	}
	return nil
}

func parseUICCApplication(base, data []byte) (UICCApplication, error) {
	if len(data) < 32 {
		return UICCApplication{}, errors.New("application entry is truncated")
	}

	aid, err := byteArrayRef(data, data, 4)
	if err != nil {
		return UICCApplication{}, fmt.Errorf("application ID: %w", err)
	}
	label, err := stringRef(data, data, 12)
	if err != nil {
		return UICCApplication{}, fmt.Errorf("application name: %w", err)
	}
	if _, err := byteArrayRef(data, data, 24); err != nil {
		return UICCApplication{}, fmt.Errorf("PIN key references: %w", err)
	}

	return UICCApplication{
		Type:  binary.LittleEndian.Uint32(data[:4]),
		AID:   aid,
		Label: label,
	}, nil
}

type FileStatusRequest struct {
	TransactionID uint32
	ApplicationID []byte
	FilePath      []byte
	Response      *FileStatusResponse
}

func (r *FileStatusRequest) Request() *Request {
	data := refHeader(20, r.ApplicationID, r.FilePath)
	data = appendRefs(data, 20, r.ApplicationID, r.FilePath)

	r.Response = new(FileStatusResponse)
	return &Request{
		MessageType:   MessageTypeCommand,
		TransactionID: r.TransactionID,
		Command: command(
			ServiceMsUiccLowLevelAccess,
			CIDUiccFileStatus,
			CommandTypeQuery,
			data,
		),
		Response: r.Response,
	}
}

type FileStatusResponse struct {
	Version       uint32
	StatusWord1   uint32
	StatusWord2   uint32
	FileType      uint32
	FileStructure uint32
	FileItemCount uint32
	FileItemSize  uint32
}

func (r *FileStatusResponse) UnmarshalBinary(data []byte) error {
	if len(data) < 48 {
		return errors.New("parsing MBIM file status: payload is truncated")
	}
	r.Version = binary.LittleEndian.Uint32(data[:4])
	r.StatusWord1 = binary.LittleEndian.Uint32(data[4:8])
	r.StatusWord2 = binary.LittleEndian.Uint32(data[8:12])
	r.FileType = binary.LittleEndian.Uint32(data[16:20])
	r.FileStructure = binary.LittleEndian.Uint32(data[20:24])
	r.FileItemCount = binary.LittleEndian.Uint32(data[24:28])
	r.FileItemSize = binary.LittleEndian.Uint32(data[28:32])
	return nil
}

type ReadBinaryRequest struct {
	TransactionID uint32
	ApplicationID []byte
	FilePath      []byte
	Offset        uint32
	Size          uint32
	Response      *ReadBinaryResponse
}

func (r *ReadBinaryRequest) Request() *Request {
	data := refHeader(44, r.ApplicationID, r.FilePath)
	data = binary.LittleEndian.AppendUint32(data, r.Offset)
	data = binary.LittleEndian.AppendUint32(data, r.Size)
	data = binary.LittleEndian.AppendUint32(data, 0)
	data = binary.LittleEndian.AppendUint32(data, 0)
	data = binary.LittleEndian.AppendUint32(data, 0)
	data = binary.LittleEndian.AppendUint32(data, 0)
	data = appendRefs(data, 44, r.ApplicationID, r.FilePath)

	r.Response = new(ReadBinaryResponse)
	return &Request{
		MessageType:   MessageTypeCommand,
		TransactionID: r.TransactionID,
		Command: command(
			ServiceMsUiccLowLevelAccess,
			CIDUiccReadBinary,
			CommandTypeQuery,
			data,
		),
		Response: r.Response,
	}
}

type ReadBinaryResponse struct {
	Version     uint32
	StatusWord1 uint32
	StatusWord2 uint32
	Data        []byte
}

func (r *ReadBinaryResponse) UnmarshalBinary(data []byte) error {
	if len(data) < 20 {
		return errors.New("parsing MBIM read binary: payload is truncated")
	}
	r.Version = binary.LittleEndian.Uint32(data[:4])
	r.StatusWord1 = binary.LittleEndian.Uint32(data[4:8])
	r.StatusWord2 = binary.LittleEndian.Uint32(data[8:12])
	value, err := byteArrayRef(data, data, 12)
	if err != nil {
		return fmt.Errorf("parsing MBIM read binary data: %w", err)
	}
	r.Data = value
	return nil
}

type ReadRecordRequest struct {
	TransactionID uint32
	ApplicationID []byte
	FilePath      []byte
	Record        uint32
	Response      *ReadRecordResponse
}

func (r *ReadRecordRequest) Request() *Request {
	data := refHeader(40, r.ApplicationID, r.FilePath)
	data = binary.LittleEndian.AppendUint32(data, r.Record)
	data = binary.LittleEndian.AppendUint32(data, 0)
	data = binary.LittleEndian.AppendUint32(data, 0)
	data = binary.LittleEndian.AppendUint32(data, 0)
	data = binary.LittleEndian.AppendUint32(data, 0)
	data = appendRefs(data, 40, r.ApplicationID, r.FilePath)

	r.Response = new(ReadRecordResponse)
	return &Request{
		MessageType:   MessageTypeCommand,
		TransactionID: r.TransactionID,
		Command: command(
			ServiceMsUiccLowLevelAccess,
			CIDUiccReadRecord,
			CommandTypeQuery,
			data,
		),
		Response: r.Response,
	}
}

type ReadRecordResponse struct {
	Version     uint32
	StatusWord1 uint32
	StatusWord2 uint32
	Data        []byte
}

func (r *ReadRecordResponse) UnmarshalBinary(data []byte) error {
	if len(data) < 20 {
		return errors.New("parsing MBIM read record: payload is truncated")
	}
	r.Version = binary.LittleEndian.Uint32(data[:4])
	r.StatusWord1 = binary.LittleEndian.Uint32(data[4:8])
	r.StatusWord2 = binary.LittleEndian.Uint32(data[8:12])
	value, err := byteArrayRef(data, data, 12)
	if err != nil {
		return fmt.Errorf("parsing MBIM read record data: %w", err)
	}
	r.Data = value
	return nil
}

type AuthAKARequest struct {
	TransactionID uint32
	Rand          []byte
	AUTN          []byte
	Response      *AuthAKAResponse
}

func (r *AuthAKARequest) Request() *Request {
	data := make([]byte, 0, len(r.Rand)+len(r.AUTN))
	data = append(data, r.Rand...)
	data = append(data, r.AUTN...)

	r.Response = new(AuthAKAResponse)
	return &Request{
		MessageType:   MessageTypeCommand,
		TransactionID: r.TransactionID,
		Command: command(
			ServiceAuth,
			CIDAuthAKA,
			CommandTypeQuery,
			data,
		),
		Response: r.Response,
	}
}

type AuthAKAResponse struct {
	RES  []byte
	CK   []byte
	IK   []byte
	AUTS []byte
}

func (r *AuthAKAResponse) UnmarshalBinary(data []byte) error {
	if len(data) < 66 {
		return errors.New("parsing MBIM auth AKA: payload is truncated")
	}
	resLength := int(binary.LittleEndian.Uint32(data[16:20]))
	if resLength > 16 {
		return fmt.Errorf("parsing MBIM auth AKA: RES length %d exceeds 16", resLength)
	}
	r.RES = slices.Clone(data[:resLength])
	r.IK = slices.Clone(data[20:36])
	r.CK = slices.Clone(data[36:52])
	r.AUTS = slices.Clone(data[52:66])
	return nil
}

func command(serviceID [16]byte, commandID, commandType uint32, data []byte) *Command {
	return &Command{
		FragmentTotal:   1,
		FragmentCurrent: 0,
		ServiceID:       serviceID,
		CommandID:       commandID,
		CommandType:     commandType,
		Data:            slices.Clone(data),
	}
}

func refHeader(baseOffset int, refs ...[]byte) []byte {
	data := binary.LittleEndian.AppendUint32(nil, 1)
	offset := baseOffset
	for _, ref := range refs {
		data = binary.LittleEndian.AppendUint32(data, uint32(offset))
		data = binary.LittleEndian.AppendUint32(data, uint32(len(ref)))
		offset = align4(offset + len(ref))
	}
	return data
}

func appendRefs(data []byte, baseOffset int, refs ...[]byte) []byte {
	for _, ref := range refs {
		data = append(data, ref...)
		for (baseOffset+len(ref))%4 != 0 {
			data = append(data, 0)
			baseOffset++
		}
		baseOffset += len(ref)
	}
	return data
}

func byteArrayRef(base, data []byte, fieldOffset uint32) ([]byte, error) {
	if fieldOffset > uint32(len(data)) || 8 > uint32(len(data))-fieldOffset {
		return nil, errors.New("reference is truncated")
	}
	offset := binary.LittleEndian.Uint32(data[fieldOffset : fieldOffset+4])
	size := binary.LittleEndian.Uint32(data[fieldOffset+4 : fieldOffset+8])
	if offset > uint32(len(base)) || size > uint32(len(base))-offset {
		return nil, errors.New("value is truncated")
	}
	return slices.Clone(base[offset : offset+size]), nil
}

func stringRef(base, data []byte, fieldOffset uint32) (string, error) {
	raw, err := byteArrayRef(base, data, fieldOffset)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func utf16Bytes(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	buf := make([]byte, 0, len(encoded)*2)
	for _, v := range encoded {
		buf = binary.LittleEndian.AppendUint16(buf, v)
	}
	return buf
}

func align4(n int) int {
	return (n + 3) &^ 3
}
