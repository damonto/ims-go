package command

import (
	"errors"
	"fmt"
	"slices"

	"github.com/damonto/ims-client/usim/apdu"
)

type Authenticate3G struct {
	Rand []byte
	AUTN []byte
}

type Authenticate3GResult struct {
	RES    []byte
	CK     []byte
	IK     []byte
	AUTS   []byte
	Reject bool
}

func (r Authenticate3GResult) IsSuccess() bool {
	return len(r.RES) != 0 && len(r.CK) != 0 && len(r.IK) != 0
}

func (r Authenticate3GResult) IsSynchronizationFailure() bool {
	return len(r.AUTS) != 0
}

func (r Authenticate3GResult) IsAuthenticationReject() bool {
	return r.Reject
}

func (c Authenticate3G) APDU() []byte {
	data := make([]byte, 0, len(c.Rand)+len(c.AUTN)+2)
	data = append(data, byte(len(c.Rand)))
	data = append(data, c.Rand...)
	data = append(data, byte(len(c.AUTN)))
	data = append(data, c.AUTN...)

	return apdu.Request{
		CLA:  0x00,
		INS:  0x88,
		P1:   0x00,
		P2:   0x81,
		Data: data,
	}.APDU()
}

func (c Authenticate3G) Decode(data []byte) (Authenticate3GResult, error) {
	var result Authenticate3GResult
	if err := result.UnmarshalBinary(data); err != nil {
		return Authenticate3GResult{}, err
	}
	return result, nil
}

func (c Authenticate3G) DecodeResponse(resp apdu.Response) (Authenticate3GResult, error) {
	return c.Decode(resp.Data())
}

func (r *Authenticate3GResult) UnmarshalBinary(data []byte) error {
	if len(data) < 1 {
		return errors.New("authenticating USIM: authenticate response is empty")
	}

	original := slices.Clone(data)
	payload := data[1:]
	switch original[0] {
	case 0xDB:
		parsed := Authenticate3GResult{}
		var err error
		parsed.RES, payload, err = readAKAChunk(payload, "RES", original)
		if err != nil {
			return err
		}
		parsed.CK, payload, err = readAKAChunk(payload, "CK", original)
		if err != nil {
			return err
		}
		parsed.IK, payload, err = readAKAChunk(payload, "IK", original)
		if err != nil {
			return err
		}
		*r = parsed
		return nil
	case 0xDC:
		if len(payload) == 0 {
			*r = Authenticate3GResult{Reject: true}
			return nil
		}
		auts, _, err := readAKAChunk(payload, "AUTS", original)
		if err != nil {
			return err
		}
		if len(auts) == 0 {
			*r = Authenticate3GResult{Reject: true}
			return nil
		}
		if len(auts) != 14 {
			return fmt.Errorf("authenticating USIM: invalid AUTS length %d in %X", len(auts), original)
		}
		*r = Authenticate3GResult{AUTS: auts}
		return nil
	default:
		return fmt.Errorf("authenticating USIM: unexpected authenticate response %X", original)
	}
}

func readAKAChunk(data []byte, name string, original []byte) ([]byte, []byte, error) {
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("authenticating USIM: missing %s length in %X", name, original)
	}
	length := int(data[0])
	data = data[1:]
	if len(data) < length {
		return nil, nil, fmt.Errorf("authenticating USIM: truncated %s in %X", name, original)
	}
	chunk := slices.Clone(data[:length])
	return chunk, data[length:], nil
}
