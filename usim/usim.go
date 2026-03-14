package usim

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	usimapdu "github.com/damonto/ims-client/usim/apdu"
	"github.com/damonto/ims-client/usim/command"
	usimreader "github.com/damonto/ims-client/usim/reader"
	"github.com/damonto/ims-client/usim/simfile"
)

var (
	masterFile = []byte{0x3F, 0x00}
	efDirFile  = []byte{0x2F, 0x00}
)

type reader struct {
	tx usimreader.Transmitter

	selected selection
}

type selection struct {
	valid bool
	file  usimreader.FileRef
	info  simfile.FCI
}

func New(tx usimreader.Transmitter) usimreader.Reader {
	return &reader{tx: tx}
}

func (r *reader) ListApplications(ctx context.Context) ([]usimreader.Application, error) {
	if _, err := r.selectID(ctx, masterFile); err != nil {
		return nil, err
	}

	info, err := r.selectID(ctx, efDirFile)
	if err != nil {
		return nil, fmt.Errorf("reading EF_DIR: %w", err)
	}
	if info.FileStructure != simfile.StructureLinearFixed {
		return nil, errors.New("reading EF_DIR: unexpected file structure")
	}

	apps := make([]usimreader.Application, 0, info.RecordCount)
	for recordID := uint16(1); recordID <= uint16(info.RecordCount); recordID++ {
		record, err := r.readRecordRaw(ctx, recordID, info.RecordSize)
		if err != nil {
			return nil, fmt.Errorf("parsing EF_DIR record %d: %w", recordID, err)
		}

		parsed, err := command.ReadEFDirRecord{RecordSize: info.RecordSize}.Decode(record)
		if err != nil {
			return nil, fmt.Errorf("parsing EF_DIR record %d: %w", recordID, err)
		}
		if len(parsed.AID) == 0 {
			continue
		}
		apps = append(apps, usimreader.Application{
			AID:   slices.Clone(parsed.AID),
			Label: parsed.Label,
		})
	}
	return apps, nil
}

func (r *reader) GetFileAttributes(ctx context.Context, file usimreader.FileRef) (usimreader.FileAttributes, error) {
	info, err := r.selectFile(ctx, file)
	if err != nil {
		return usimreader.FileAttributes{}, err
	}
	return usimreader.FileAttributes{
		FileStructure: info.FileStructure,
		FileType:      info.FileType,
		RecordSize:    info.RecordSize,
		RecordCount:   uint16(info.RecordCount),
		FileSize:      info.FileSize,
	}, nil
}

func (r *reader) ReadTransparent(ctx context.Context, req usimreader.TransparentRead) ([]byte, error) {
	info, err := r.selectFile(ctx, req.File)
	if err != nil {
		return nil, err
	}
	if info.FileStructure != simfile.StructureTransparent {
		return nil, errors.New("reading transparent file: unexpected file structure")
	}

	length := req.Length
	if length == 0 {
		if req.Offset > info.FileSize {
			return nil, errors.New("reading transparent file: offset exceeds file size")
		}
		length = info.FileSize - req.Offset
	}
	return r.readBinaryRaw(ctx, req.Offset, length)
}

func (r *reader) ReadRecord(ctx context.Context, req usimreader.RecordRead) ([]byte, error) {
	info, err := r.selectFile(ctx, req.File)
	if err != nil {
		return nil, err
	}
	if info.FileStructure != simfile.StructureLinearFixed {
		return nil, errors.New("reading record file: unexpected file structure")
	}

	length := req.Length
	if length == 0 {
		length = info.RecordSize
	}
	return r.readRecordRaw(ctx, req.Record, length)
}

func (r *reader) Authenticate3G(ctx context.Context, req usimreader.AuthenticateRequest) ([]byte, error) {
	raw, err := r.transmit(ctx, command.Authenticate3G{
		Rand: slices.Clone(req.Rand),
		AUTN: slices.Clone(req.AUTN),
	}.APDU())
	if err != nil {
		return nil, err
	}
	return slices.Clone(raw.Data()), nil
}

func (r *reader) Close() error {
	if r.tx == nil {
		return nil
	}
	return r.tx.Close()
}

func (r *reader) selectFile(ctx context.Context, file usimreader.FileRef) (simfile.FCI, error) {
	if len(file.Path) == 0 {
		return simfile.FCI{}, errors.New("selecting file: path is empty")
	}
	if r.selected.matches(file) {
		return r.selected.info, nil
	}

	if len(file.AID) > 0 {
		if _, err := r.selectName(ctx, file.AID); err != nil {
			return simfile.FCI{}, err
		}
	} else {
		if _, err := r.selectID(ctx, masterFile); err != nil {
			return simfile.FCI{}, err
		}
	}

	var (
		info simfile.FCI
		err  error
	)
	if len(file.Path) == 2 {
		info, err = r.selectID(ctx, file.Path)
	} else {
		info, err = r.selectPath(ctx, file.Path)
	}
	if err != nil {
		return simfile.FCI{}, err
	}

	r.selected = selection{
		valid: true,
		file: usimreader.FileRef{
			AID:  slices.Clone(file.AID),
			Path: slices.Clone(file.Path),
		},
		info: info,
	}
	return info, nil
}

func (r *reader) selectID(ctx context.Context, id []byte) (simfile.FCI, error) {
	return r.decodeFCI(ctx, command.SelectID{ID: slices.Clone(id)}.APDU())
}

func (r *reader) selectName(ctx context.Context, name []byte) (simfile.FCI, error) {
	return r.decodeFCI(ctx, command.SelectName{Name: slices.Clone(name)}.APDU())
}

func (r *reader) selectPath(ctx context.Context, path []byte) (simfile.FCI, error) {
	return r.decodeFCI(ctx, command.SelectPath{Path: slices.Clone(path)}.APDU())
}

func (r *reader) decodeFCI(ctx context.Context, req []byte) (simfile.FCI, error) {
	raw, err := r.transmit(ctx, req)
	if err != nil {
		return simfile.FCI{}, err
	}

	var info simfile.FCI
	if err := info.UnmarshalBinary(raw.Data()); err != nil {
		return simfile.FCI{}, err
	}
	return info, nil
}

func (r *reader) readBinaryRaw(ctx context.Context, offset, length uint16) ([]byte, error) {
	if length == 0 {
		return nil, nil
	}

	data := make([]byte, 0, length)
	for length > 0 {
		chunk := minUint16(length, 0xFF)
		raw, err := r.transmit(ctx, command.ReadBinary{
			Offset: offset,
			Length: byte(chunk),
		}.APDU())
		if err != nil {
			return nil, err
		}
		data = append(data, raw.Data()...)
		offset += chunk
		length -= chunk
	}
	return data, nil
}

func (r *reader) readRecordRaw(ctx context.Context, record, length uint16) ([]byte, error) {
	if record == 0 {
		return nil, errors.New("reading record file: record number is zero")
	}
	if length > 0xFF {
		return nil, fmt.Errorf("reading record file: record length %d exceeds APDU limit", length)
	}

	raw, err := r.transmit(ctx, command.ReadRecord{
		Record: byte(record),
		Length: byte(length),
	}.APDU())
	if err != nil {
		return nil, err
	}
	return slices.Clone(raw.Data()), nil
}

func (r *reader) transmit(ctx context.Context, req []byte) (usimapdu.Response, error) {
	if r.tx == nil {
		return nil, errors.New("transmitting APDU: transmitter is nil")
	}

	raw, err := r.tx.Transmit(ctx, req)
	if err != nil {
		return nil, err
	}
	resp := usimapdu.Response(raw)
	if len(resp) < 2 {
		return nil, usimapdu.ErrMalformedResponse
	}

	data := append([]byte(nil), resp.Data()...)
	for resp.HasMore() {
		length := resp.SW2()
		follow, err := r.tx.Transmit(ctx, usimapdu.Request{
			CLA: 0x00,
			INS: 0xC0,
			P1:  0x00,
			P2:  0x00,
			Le:  &length,
		}.APDU())
		if err != nil {
			return nil, fmt.Errorf("reading response body: %w", err)
		}
		resp = usimapdu.Response(follow)
		if len(resp) < 2 {
			return nil, usimapdu.ErrMalformedResponse
		}
		data = append(data, resp.Data()...)
	}

	if !resp.OK() {
		return nil, usimapdu.StatusError{SW: resp.SW()}
	}
	return append(data, byte(resp.SW()>>8), byte(resp.SW())), nil
}

func (s selection) matches(file usimreader.FileRef) bool {
	return s.valid && bytes.Equal(s.file.AID, file.AID) && bytes.Equal(s.file.Path, file.Path)
}

func minUint16(a, b uint16) uint16 {
	if a < b {
		return a
	}
	return b
}
