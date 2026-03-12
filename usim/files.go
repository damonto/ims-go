package usim

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/damonto/ims-client/apdu"
)

const (
	tagFCI            = 0x62
	tagFileDescriptor = 0x82
	tagFileLength     = 0x80
	tagRecord         = 0x61
	tagRecordAID      = 0x4F
	tagRecordLabel    = 0x50

	fileStructTransparent = 0x41
	fileStructLinearFixed = 0x42
)

type fileControlInfo struct {
	FileStruct  byte
	FileType    byte
	RecordSize  uint16
	RecordCount byte
	FileSize    uint16
}

type efDirRecord struct {
	AID   []byte
	Label string
}

func (info *fileControlInfo) UnmarshalBinary(data []byte) error {
	var top apdu.TLVs
	if err := top.UnmarshalBinary(data); err != nil {
		return err
	}
	if len(top) != 1 || top[0].Tag != tagFCI {
		return fmt.Errorf("parsing FCI: %w", apdu.ErrMalformedResponse)
	}

	var inner apdu.TLVs
	if err := inner.UnmarshalBinary(top[0].Value); err != nil {
		return fmt.Errorf("parsing FCI children: %w", err)
	}

	parsed := fileControlInfo{}
	haveDescriptor := false
	for _, item := range inner {
		switch item.Tag {
		case tagFileDescriptor:
			haveDescriptor = true
			switch len(item.Value) {
			case 2:
				parsed.FileStruct = item.Value[0]
				parsed.FileType = item.Value[1]
			case 5:
				parsed.FileStruct = item.Value[0]
				parsed.FileType = item.Value[1]
				parsed.RecordSize = binary.BigEndian.Uint16(item.Value[2:4])
				parsed.RecordCount = item.Value[4]
			default:
				return errors.New("unexpected file descriptor length")
			}
		case tagFileLength:
			if len(item.Value) != 2 {
				return errors.New("unexpected file length encoding")
			}
			parsed.FileSize = binary.BigEndian.Uint16(item.Value)
		}
	}
	if !haveDescriptor {
		return errors.New("missing file descriptor")
	}

	*info = parsed
	return nil
}

func trimEFDirPadding(data []byte) []byte {
	for len(data) > 0 && data[len(data)-1] == 0xFF {
		data = data[:len(data)-1]
	}
	return data
}

func (rec *efDirRecord) UnmarshalBinary(data []byte) error {
	data = trimEFDirPadding(data)
	if len(data) == 0 {
		*rec = efDirRecord{}
		return nil
	}

	var top apdu.TLVs
	if err := top.UnmarshalBinary(data); err != nil {
		return err
	}
	if len(top) == 0 {
		return apdu.ErrMalformedResponse
	}
	if top[0].Tag != tagRecord {
		return errors.New("unexpected EF_DIR record tag")
	}

	var inner apdu.TLVs
	if err := inner.UnmarshalBinary(top[0].Value); err != nil {
		return err
	}

	parsed := efDirRecord{}
	for _, item := range inner {
		switch item.Tag {
		case tagRecordAID:
			parsed.AID = append([]byte(nil), item.Value...)
		case tagRecordLabel:
			parsed.Label = string(item.Value)
		}
	}
	if len(parsed.AID) == 0 {
		return errors.New("missing EF_DIR record AID")
	}

	*rec = parsed
	return nil
}

func decodeTLVText(data []byte) (string, error) {
	for len(data) > 0 && (data[len(data)-1] == 0xFF || data[len(data)-1] == 0x00) {
		data = data[:len(data)-1]
	}
	if len(data) == 0 {
		return "", errors.New("parsing TLV string: empty payload")
	}

	var tlvs apdu.TLVs
	err := tlvs.UnmarshalBinary(data)
	if err == nil {
		for _, item := range tlvs {
			if len(item.Value) == 0 {
				continue
			}
			return string(item.Value), nil
		}
		return "", errors.New("parsing TLV string: missing value")
	}

	for _, b := range data {
		if b < 0x20 || b > 0x7E {
			return "", err
		}
	}
	return string(data), nil
}
