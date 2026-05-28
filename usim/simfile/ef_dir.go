package simfile

import (
	"errors"

	"github.com/damonto/vowifi-go/usim/apdu"
	"github.com/damonto/vowifi-go/usim/tlv"
)

const (
	tagRecord      = 0x61
	tagRecordAID   = 0x4F
	tagRecordLabel = 0x50
)

type EFDirRecord struct {
	AID   []byte
	Label string
}

func (rec *EFDirRecord) UnmarshalBinary(data []byte) error {
	data = trimEFDirPadding(data)
	if len(data) == 0 {
		*rec = EFDirRecord{}
		return nil
	}

	var top tlv.Items
	if err := top.UnmarshalBinary(data); err != nil {
		return malformedTLV(err)
	}
	if len(top) == 0 {
		return apdu.ErrMalformedResponse
	}
	if top[0].Tag != tagRecord {
		return errors.New("unexpected EF_DIR record tag")
	}

	var inner tlv.Items
	if err := inner.UnmarshalBinary(top[0].Value); err != nil {
		return malformedTLV(err)
	}

	parsed := EFDirRecord{}
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

func trimEFDirPadding(data []byte) []byte {
	for len(data) > 0 && data[len(data)-1] == 0xFF {
		data = data[:len(data)-1]
	}
	return data
}
