package command

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	usimreader "github.com/damonto/vowifi-go/usim/reader"
	"github.com/damonto/vowifi-go/usim/simfile"
)

type FindAID struct {
	Label    string
	Prefix   []byte
	NotFound error
}

type App struct {
	Reader usimreader.Reader
	AID    []byte
}

func (c FindAID) Run(ctx context.Context, r usimreader.Reader) ([]byte, error) {
	apps, err := r.ListApplications(ctx)
	if err != nil {
		return nil, err
	}
	for _, app := range apps {
		if len(app.AID) == 0 {
			continue
		}
		if strings.EqualFold(app.Label, c.Label) || (len(c.Prefix) > 0 && bytes.HasPrefix(app.AID, c.Prefix)) {
			return slices.Clone(app.AID), nil
		}
	}

	if c.NotFound != nil {
		return nil, c.NotFound
	}
	return nil, errors.New("application not found")
}

func (a App) ReadICCID(ctx context.Context, path []byte) (string, error) {
	file := a.file(path)
	attrs, err := a.fileStructure(ctx, file, "reading EF_ICCID", simfile.StructureTransparent)
	if err != nil {
		return "", err
	}

	data, err := a.Reader.ReadTransparent(ctx, usimreader.TransparentRead{
		File:   file,
		Length: attrs.FileSize,
	})
	if err != nil {
		return "", err
	}
	return ReadICCID{}.Decode(data)
}

func (a App) ReadIMSI(ctx context.Context, id []byte) (IMSI, error) {
	file := a.file(id)
	attrs, err := a.fileStructure(ctx, file, "reading EF_IMSI", simfile.StructureTransparent)
	if err != nil {
		return IMSI{}, err
	}

	data, err := a.Reader.ReadTransparent(ctx, usimreader.TransparentRead{
		File:   file,
		Length: attrs.FileSize,
	})
	if err != nil {
		return IMSI{}, err
	}
	return ReadIMSI{}.Decode(data)
}

func (a App) ReadMNCLength(ctx context.Context, id []byte) (int, error) {
	file := a.file(id)
	attrs, err := a.fileStructure(ctx, file, "reading EF_AD", simfile.StructureTransparent)
	if err != nil {
		return 0, err
	}

	data, err := a.Reader.ReadTransparent(ctx, usimreader.TransparentRead{
		File:   file,
		Length: attrs.FileSize,
	})
	if err != nil {
		return 0, err
	}
	return simfile.DecodeMNCLength(data)
}

func (a App) ReadTransparentHex(ctx context.Context, id []byte, action string) (string, error) {
	file := a.file(id)
	attrs, err := a.fileStructure(ctx, file, action, simfile.StructureTransparent)
	if err != nil {
		return "", err
	}

	data, err := a.Reader.ReadTransparent(ctx, usimreader.TransparentRead{
		File:   file,
		Length: attrs.FileSize,
	})
	if err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(data)), nil
}

func (a App) ReadTransparentText(ctx context.Context, id []byte, action string) (string, error) {
	file := a.file(id)
	attrs, err := a.fileStructure(ctx, file, action, simfile.StructureTransparent)
	if err != nil {
		return "", err
	}

	data, err := a.Reader.ReadTransparent(ctx, usimreader.TransparentRead{
		File:   file,
		Length: attrs.FileSize,
	})
	if err != nil {
		return "", err
	}
	return ReadTextBinary{}.Decode(data)
}

func (a App) ReadLinearFixedTextFirst(ctx context.Context, id []byte, action string) (string, error) {
	attrs, err := a.fileStructure(ctx, a.file(id), action, simfile.StructureLinearFixed)
	if err != nil {
		return "", err
	}
	return a.readLinearFixedTextFirst(ctx, a.file(id), attrs, action)
}

func (a App) ReadLinearFixedTextPathFirst(ctx context.Context, path []byte, action string) (string, error) {
	file := a.file(path)
	attrs, err := a.fileStructure(ctx, file, action, simfile.StructureLinearFixed)
	if err != nil {
		return "", err
	}
	return a.readLinearFixedTextFirst(ctx, file, attrs, action)
}

func (a App) readLinearFixedTextFirst(ctx context.Context, file usimreader.FileRef, attrs usimreader.FileAttributes, action string) (string, error) {
	if attrs.RecordCount == 0 {
		return "", fmt.Errorf("%s: file has no records", action)
	}
	for recordID := uint16(1); recordID <= attrs.RecordCount; recordID++ {
		record, err := a.Reader.ReadRecord(ctx, usimreader.RecordRead{
			File:   file,
			Record: recordID,
			Length: attrs.RecordSize,
		})
		if err != nil {
			return "", err
		}
		value, err := simfile.DecodeText(record)
		if err != nil {
			continue
		}
		if value != "" {
			return value, nil
		}
	}
	return "", fmt.Errorf("%s: no populated record", action)
}

func (a App) ReadSMSC(ctx context.Context, id []byte) (string, error) {
	file := a.file(id)
	attrs, err := a.fileStructure(ctx, file, "reading EF_SMSP", simfile.StructureLinearFixed)
	if err != nil {
		return "", err
	}

	for recordID := uint16(1); recordID <= attrs.RecordCount; recordID++ {
		record, err := a.Reader.ReadRecord(ctx, usimreader.RecordRead{
			File:   file,
			Record: recordID,
			Length: attrs.RecordSize,
		})
		if err != nil {
			return "", err
		}
		number, err := ReadSMSCRecord{RecordSize: attrs.RecordSize}.Decode(record)
		if err != nil {
			return "", err
		}
		if number != "" {
			return number, nil
		}
	}

	return "", errors.New("reading EF_SMSP: SMSC not found")
}

func (a App) file(path []byte) usimreader.FileRef {
	return usimreader.FileRef{
		AID:  slices.Clone(a.AID),
		Path: slices.Clone(path),
	}
}

func (a App) fileStructure(ctx context.Context, file usimreader.FileRef, action string, want byte) (usimreader.FileAttributes, error) {
	attrs, err := a.Reader.GetFileAttributes(ctx, file)
	if err != nil {
		return usimreader.FileAttributes{}, err
	}
	if attrs.FileStructure != want {
		return usimreader.FileAttributes{}, fmt.Errorf("%s: unexpected file structure", action)
	}
	return attrs, nil
}
