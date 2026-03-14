package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	usimreader "github.com/damonto/ims-client/usim/reader"
	"github.com/damonto/ims-client/usim/simfile"
)

var (
	masterFile = []byte{0x3F, 0x00}
	efDirFile  = []byte{0x2F, 0x00}
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
	if _, err := Execute(ctx, r, SelectID{ID: masterFile}); err != nil {
		return nil, err
	}

	fci, err := selectIDStructure(ctx, r, efDirFile, "reading EF_DIR", simfile.StructureLinearFixed)
	if err != nil {
		return nil, err
	}

	for recordID := byte(1); recordID <= fci.RecordCount; recordID++ {
		record, err := Execute(ctx, r, ReadEFDirRecord{
			Record:     recordID,
			RecordSize: fci.RecordSize,
		})
		if err != nil {
			return nil, fmt.Errorf("parsing EF_DIR record %d: %w", recordID, err)
		}
		if len(record.AID) == 0 {
			continue
		}
		if strings.EqualFold(record.Label, c.Label) || (len(c.Prefix) > 0 && bytes.HasPrefix(record.AID, c.Prefix)) {
			return record.AID, nil
		}
	}

	if c.NotFound != nil {
		return nil, c.NotFound
	}
	return nil, errors.New("application not found")
}

func (a App) ReadICCID(ctx context.Context, path []byte) (string, error) {
	fci, err := a.selectPathStructure(ctx, path, "reading EF_ICCID", simfile.StructureTransparent)
	if err != nil {
		return "", err
	}

	return Execute(ctx, a.Reader, ReadICCID{FileSize: fci.FileSize})
}

func (a App) ReadIMSI(ctx context.Context, id []byte) (IMSI, error) {
	fci, err := a.selectIDStructure(ctx, id, "reading EF_IMSI", simfile.StructureTransparent)
	if err != nil {
		return IMSI{}, err
	}

	return Execute(ctx, a.Reader, ReadIMSI{FileSize: fci.FileSize})
}

func (a App) ReadMNCLength(ctx context.Context, id []byte) (int, error) {
	fci, err := a.selectIDStructure(ctx, id, "reading EF_AD", simfile.StructureTransparent)
	if err != nil {
		return 0, err
	}

	data, err := Execute(ctx, a.Reader, ReadBinary{Length: byte(fci.FileSize)})
	if err != nil {
		return 0, err
	}
	return simfile.DecodeMNCLength(data)
}

func (a App) ReadTransparentText(ctx context.Context, id []byte, action string) (string, error) {
	fci, err := a.selectIDStructure(ctx, id, action, simfile.StructureTransparent)
	if err != nil {
		return "", err
	}

	return Execute(ctx, a.Reader, ReadTextBinary{FileSize: fci.FileSize})
}

func (a App) ReadLinearFixedTextFirst(ctx context.Context, id []byte, action string) (string, error) {
	fci, err := a.selectIDStructure(ctx, id, action, simfile.StructureLinearFixed)
	if err != nil {
		return "", err
	}
	return a.readLinearFixedTextFirst(ctx, fci, action)
}

func (a App) ReadLinearFixedTextPathFirst(ctx context.Context, path []byte, action string) (string, error) {
	fci, err := a.selectPathStructure(ctx, path, action, simfile.StructureLinearFixed)
	if err != nil {
		return "", err
	}
	return a.readLinearFixedTextFirst(ctx, fci, action)
}

func (a App) readLinearFixedTextFirst(ctx context.Context, fci simfile.FCI, action string) (string, error) {
	if fci.RecordCount == 0 {
		return "", fmt.Errorf("%s: file has no records", action)
	}
	for recordID := byte(1); recordID <= fci.RecordCount; recordID++ {
		record, err := Execute(ctx, a.Reader, ReadRecord{
			Record: recordID,
			Length: byte(fci.RecordSize),
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
	fci, err := a.selectIDStructure(ctx, id, "reading EF_SMSP", simfile.StructureLinearFixed)
	if err != nil {
		return "", err
	}

	for recordID := byte(1); recordID <= fci.RecordCount; recordID++ {
		number, err := Execute(ctx, a.Reader, ReadSMSCRecord{
			Record:     recordID,
			RecordSize: fci.RecordSize,
		})
		if err != nil {
			return "", err
		}
		if number != "" {
			return number, nil
		}
	}

	return "", errors.New("reading EF_SMSP: SMSC not found")
}

func (a App) selectIDStructure(ctx context.Context, id []byte, action string, want byte) (simfile.FCI, error) {
	if err := a.selectApp(ctx); err != nil {
		return simfile.FCI{}, err
	}
	return selectIDStructure(ctx, a.Reader, id, action, want)
}

func (a App) selectPathStructure(ctx context.Context, path []byte, action string, want byte) (simfile.FCI, error) {
	if err := a.selectApp(ctx); err != nil {
		return simfile.FCI{}, err
	}
	fci, err := Execute(ctx, a.Reader, SelectPath{Path: path})
	if err != nil {
		return simfile.FCI{}, err
	}
	return requireFileStructure(fci, want, action)
}

func (a App) selectApp(ctx context.Context) error {
	if len(a.AID) == 0 {
		return errors.New("selecting application: AID is empty")
	}
	_, err := Execute(ctx, a.Reader, SelectName{Name: a.AID})
	return err
}

func selectIDStructure(ctx context.Context, r usimreader.Reader, id []byte, action string, want byte) (simfile.FCI, error) {
	fci, err := Execute(ctx, r, SelectID{ID: id})
	if err != nil {
		return simfile.FCI{}, err
	}
	return requireFileStructure(fci, want, action)
}

func requireFileStructure(fci simfile.FCI, want byte, action string) (simfile.FCI, error) {
	if fci.FileStructure != want {
		return simfile.FCI{}, fmt.Errorf("%s: unexpected file structure", action)
	}
	return fci, nil
}
