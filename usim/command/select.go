package command

import (
	"slices"

	"github.com/damonto/vowifi-go/usim/apdu"
	"github.com/damonto/vowifi-go/usim/simfile"
)

type SelectID struct {
	ID []byte
}

type SelectName struct {
	Name []byte
}

type SelectPath struct {
	Path []byte
}

func (c SelectID) MarshalBinary() ([]byte, error) {
	return selectRequest(0x00, c.ID)
}

func (c SelectID) DecodeResponse(resp apdu.Response) (simfile.FCI, error) {
	return decodeFCI(resp)
}

func (c SelectName) MarshalBinary() ([]byte, error) {
	return selectRequest(0x04, c.Name)
}

func (c SelectName) DecodeResponse(resp apdu.Response) (simfile.FCI, error) {
	return decodeFCI(resp)
}

func (c SelectPath) MarshalBinary() ([]byte, error) {
	return selectRequest(0x08, c.Path)
}

func (c SelectPath) DecodeResponse(resp apdu.Response) (simfile.FCI, error) {
	return decodeFCI(resp)
}

func selectRequest(p1 byte, value []byte) ([]byte, error) {
	return apdu.Request{
		CLA:  0x00,
		INS:  0xA4,
		P1:   p1,
		P2:   0x04,
		Data: slices.Clone(value),
	}.MarshalBinary()
}

func decodeFCI(resp apdu.Response) (simfile.FCI, error) {
	var info simfile.FCI
	if err := info.UnmarshalBinary(resp.Data()); err != nil {
		return simfile.FCI{}, err
	}
	return info, nil
}
