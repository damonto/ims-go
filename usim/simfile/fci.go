package simfile

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/damonto/ims-client/usim/apdu"
	"github.com/damonto/ims-client/usim/tlv"
)

const (
	tagFCI            = 0x62
	tagFileDescriptor = 0x82
	tagFileLength     = 0x80

	StructureTransparent = 0x41
	StructureLinearFixed = 0x42
)

type FCI struct {
	FileStructure byte
	FileType      byte
	RecordSize    uint16
	RecordCount   byte
	FileSize      uint16
}

func (info *FCI) UnmarshalBinary(data []byte) error {
	var top tlv.Items
	if err := top.UnmarshalBinary(data); err != nil {
		return malformedTLV(err)
	}
	if len(top) != 1 || top[0].Tag != tagFCI {
		return fmt.Errorf("parsing FCI: %w", apdu.ErrMalformedResponse)
	}

	var inner tlv.Items
	if err := inner.UnmarshalBinary(top[0].Value); err != nil {
		return fmt.Errorf("parsing FCI children: %w", malformedTLV(err))
	}

	parsed := FCI{}
	haveDescriptor := false
	for _, item := range inner {
		switch item.Tag {
		case tagFileDescriptor:
			haveDescriptor = true
			switch len(item.Value) {
			case 2:
				parsed.FileStructure = item.Value[0]
				parsed.FileType = item.Value[1]
			case 5:
				parsed.FileStructure = item.Value[0]
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
