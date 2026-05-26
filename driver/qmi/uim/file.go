package uim

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/damonto/ims-client/driver/qmi/protocol"
	usimreader "github.com/damonto/ims-client/usim/reader"
	"github.com/damonto/ims-client/usim/simfile"
)

func (r *Reader) readTransparentResponse(
	ctx context.Context,
	session sessionRequest,
	path []byte,
	offset uint16,
	length uint16,
) (protocol.Response, error) {
	fileValue, err := putFileValue(path)
	if err != nil {
		return protocol.Response{}, err
	}

	info := joinBytes(
		binary.LittleEndian.AppendUint16(nil, offset),
		binary.LittleEndian.AppendUint16(nil, length),
	)
	resp, err := r.request(ctx, protocol.QMIServiceUIM, r.ClientID, protocol.QMIUIMReadTransparent, protocol.TLVs{
		tlvBytes(0x01, putSessionValue(session.session, session.aid)),
		tlvBytes(0x02, fileValue),
		tlvBytes(0x03, info),
	}, DefaultRequestTimeout)
	if err != nil {
		return protocol.Response{}, err
	}
	if err := cardResultOK(resp); err != nil {
		return protocol.Response{}, err
	}
	return resp, nil
}

func (r *Reader) readRecordResponse(
	ctx context.Context,
	session sessionRequest,
	path []byte,
	record uint16,
	length uint16,
) (protocol.Response, error) {
	fileValue, err := putFileValue(path)
	if err != nil {
		return protocol.Response{}, err
	}

	recordValue := joinBytes(
		binary.LittleEndian.AppendUint16(nil, record),
		binary.LittleEndian.AppendUint16(nil, length),
	)
	resp, err := r.request(ctx, protocol.QMIServiceUIM, r.ClientID, protocol.QMIUIMReadRecord, protocol.TLVs{
		tlvBytes(0x01, putSessionValue(session.session, session.aid)),
		tlvBytes(0x02, fileValue),
		tlvBytes(0x03, recordValue),
	}, DefaultRequestTimeout)
	if err != nil {
		return protocol.Response{}, err
	}
	if err := cardResultOK(resp); err != nil {
		return protocol.Response{}, err
	}
	return resp, nil
}

func (r *Reader) getFileAttributesResponse(
	ctx context.Context,
	session sessionRequest,
	path []byte,
) (protocol.Response, error) {
	fileValue, err := putFileValue(path)
	if err != nil {
		return protocol.Response{}, err
	}

	resp, err := r.request(ctx, protocol.QMIServiceUIM, r.ClientID, protocol.QMIUIMGetFileAttributes, protocol.TLVs{
		tlvBytes(0x01, putSessionValue(session.session, session.aid)),
		tlvBytes(0x02, fileValue),
	}, DefaultRequestTimeout)
	if err != nil {
		return protocol.Response{}, err
	}
	if err := cardResultOK(resp); err != nil {
		return protocol.Response{}, err
	}
	return resp, nil
}

func (r *Reader) authenticateResponse(
	ctx context.Context,
	session sessionRequest,
	authContext byte,
	data []byte,
) (protocol.Response, error) {
	value := append([]byte{authContext}, binary.LittleEndian.AppendUint16(nil, uint16(len(data)))...)
	value = append(value, data...)

	resp, err := r.request(ctx, protocol.QMIServiceUIM, r.ClientID, protocol.QMIUIMAuthenticate, protocol.TLVs{
		tlvBytes(0x01, putSessionValue(session.session, session.aid)),
		tlvBytes(0x02, value),
	}, DefaultRequestTimeout)
	if err != nil {
		return protocol.Response{}, err
	}
	if err := cardResultOK(resp); err != nil {
		return protocol.Response{}, err
	}
	return resp, nil
}

func decodeReaderFileAttributes(resp protocol.Response) (usimreader.FileAttributes, error) {
	value, ok := tlvValue(resp.TLVs, 0x11)
	if !ok {
		return usimreader.FileAttributes{}, errors.New("reading file attributes: attributes TLV missing")
	}

	attrs, err := decodeFileAttributes(value)
	if err != nil {
		return usimreader.FileAttributes{}, err
	}

	result := usimreader.FileAttributes{
		FileSize:    attrs.FileSize,
		RecordSize:  attrs.RecordSize,
		RecordCount: attrs.RecordCount,
		FileType:    fileTypeToSIMFileType(attrs.FileType),
	}
	if len(attrs.Raw) == 0 {
		result.FileStructure = fileTypeToSIMFileStructure(attrs.FileType)
		return result, nil
	}

	var fci simfile.FCI
	if err := fci.UnmarshalBinary(attrs.Raw); err != nil {
		result.FileStructure = fileTypeToSIMFileStructure(attrs.FileType)
		return result, nil
	}

	result.FileStructure = fci.FileStructure
	result.FileType = fci.FileType
	if result.FileSize == 0 {
		result.FileSize = fci.FileSize
	}
	if result.RecordSize == 0 {
		result.RecordSize = fci.RecordSize
	}
	if result.RecordCount == 0 {
		result.RecordCount = uint16(fci.RecordCount)
	}
	return result, nil
}

func packAuthenticateRequest(req usimreader.AuthenticateRequest) []byte {
	data := make([]byte, 0, len(req.Rand)+len(req.AUTN)+2)
	data = append(data, byte(len(req.Rand)))
	data = append(data, req.Rand...)
	data = append(data, byte(len(req.AUTN)))
	data = append(data, req.AUTN...)
	return data
}

func fileTypeToSIMFileStructure(fileType byte) byte {
	switch fileType {
	case 0:
		return simfile.StructureTransparent
	case 2:
		return simfile.StructureLinearFixed
	default:
		return 0
	}
}

func fileTypeToSIMFileType(fileType byte) byte {
	switch fileType {
	case 0, 1, 2:
		return 0x21
	case 3, 4:
		return 0x38
	default:
		return fileType
	}
}
