package simfile

import (
	"errors"

	"github.com/damonto/ims-client/tlv"
	"github.com/damonto/ims-client/usim/apdu"
)

func DecodeText(data []byte) (string, error) {
	for len(data) > 0 && (data[len(data)-1] == 0xFF || data[len(data)-1] == 0x00) {
		data = data[:len(data)-1]
	}
	if len(data) == 0 {
		return "", errors.New("parsing TLV string: empty payload")
	}

	var items tlv.Items
	err := items.UnmarshalBinary(data)
	if err == nil {
		for _, item := range items {
			if len(item.Value) == 0 {
				continue
			}
			return string(item.Value), nil
		}
		return "", errors.New("parsing TLV string: missing value")
	}

	for _, b := range data {
		if b < 0x20 || b > 0x7E {
			return "", malformedTLV(err)
		}
	}
	return string(data), nil
}

func malformedTLV(err error) error {
	if errors.Is(err, tlv.ErrMalformed) {
		return apdu.ErrMalformedResponse
	}
	return err
}
