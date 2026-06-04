package command

import (
	"encoding/hex"
	"errors"
	"slices"
	"strings"

	"github.com/damonto/vowifi-go/usim/apdu"
	"github.com/damonto/vowifi-go/usim/simfile"
)

type ReadBinary struct {
	Length byte
	Offset uint16
}

type ReadRecord struct {
	Record byte
	Length byte
}

type ReadIMSI struct {
	FileSize uint16
}

type IMSI struct {
	Digits string
	MCC    string
	MNC    string
}

type ReadICCID struct {
	FileSize uint16
}

type ReadEFDirRecord struct {
	Record     byte
	RecordSize uint16
}

type ReadTextBinary struct {
	FileSize uint16
}

type ReadTextRecord struct {
	Record     byte
	RecordSize uint16
}

type ReadSMSCRecord struct {
	Record     byte
	RecordSize uint16
}

func (c ReadBinary) MarshalBinary() ([]byte, error) {
	return apdu.Request{
		CLA: 0x00,
		INS: 0xB0,
		P1:  byte(c.Offset >> 8),
		P2:  byte(c.Offset),
		Le:  &c.Length,
	}.MarshalBinary()
}

func (c ReadBinary) DecodeResponse(resp apdu.Response) ([]byte, error) {
	return slices.Clone(resp.Data()), nil
}

func (c ReadRecord) MarshalBinary() ([]byte, error) {
	return apdu.Request{
		CLA: 0x00,
		INS: 0xB2,
		P1:  c.Record,
		P2:  0x04,
		Le:  &c.Length,
	}.MarshalBinary()
}

func (c ReadRecord) DecodeResponse(resp apdu.Response) ([]byte, error) {
	return slices.Clone(resp.Data()), nil
}

func (c ReadIMSI) MarshalBinary() ([]byte, error) {
	return ReadBinary{Length: byte(c.FileSize)}.MarshalBinary()
}

func (c ReadIMSI) Decode(data []byte) (IMSI, error) {
	data = slices.Clone(data)
	if len(data) == 0 {
		return IMSI{}, errors.New("reading EF_IMSI: empty payload")
	}
	length := int(data[0])
	if len(data) < length+1 {
		return IMSI{}, errors.New("reading EF_IMSI: truncated payload")
	}

	digits := decodeSwappedBCD(data[1:1+length], true)
	if len(digits) < 6 {
		return IMSI{}, errors.New("reading EF_IMSI: decoded payload is too short")
	}

	return IMSI{
		Digits: digits,
		MCC:    digits[:3],
		MNC:    digits[3:6],
	}, nil
}

func (c ReadIMSI) DecodeResponse(resp apdu.Response) (IMSI, error) {
	return c.Decode(resp.Data())
}

func (c ReadICCID) MarshalBinary() ([]byte, error) {
	return ReadBinary{Length: byte(c.FileSize)}.MarshalBinary()
}

func (c ReadICCID) Decode(data []byte) (string, error) {
	return decodeSwappedBCD(data, true), nil
}

func (c ReadICCID) DecodeResponse(resp apdu.Response) (string, error) {
	return c.Decode(resp.Data())
}

func (c ReadEFDirRecord) MarshalBinary() ([]byte, error) {
	return ReadRecord{Record: c.Record, Length: byte(c.RecordSize)}.MarshalBinary()
}

func (c ReadEFDirRecord) Decode(data []byte) (simfile.EFDirRecord, error) {
	var record simfile.EFDirRecord
	if err := record.UnmarshalBinary(data); err != nil {
		return simfile.EFDirRecord{}, err
	}
	return record, nil
}

func (c ReadEFDirRecord) DecodeResponse(resp apdu.Response) (simfile.EFDirRecord, error) {
	return c.Decode(resp.Data())
}

func (c ReadTextBinary) MarshalBinary() ([]byte, error) {
	return ReadBinary{Length: byte(c.FileSize)}.MarshalBinary()
}

func (c ReadTextBinary) Decode(data []byte) (string, error) {
	return simfile.DecodeText(data)
}

func (c ReadTextBinary) DecodeResponse(resp apdu.Response) (string, error) {
	return c.Decode(resp.Data())
}

func (c ReadTextRecord) MarshalBinary() ([]byte, error) {
	return ReadRecord{Record: c.Record, Length: byte(c.RecordSize)}.MarshalBinary()
}

func (c ReadTextRecord) Decode(data []byte) (string, error) {
	return simfile.DecodeText(data)
}

func (c ReadTextRecord) DecodeResponse(resp apdu.Response) (string, error) {
	return c.Decode(resp.Data())
}

func (c ReadSMSCRecord) MarshalBinary() ([]byte, error) {
	return ReadRecord{Record: c.Record, Length: byte(c.RecordSize)}.MarshalBinary()
}

func (c ReadSMSCRecord) Decode(data []byte) (string, error) {
	data = slices.Clone(data)
	y := int(c.RecordSize) - 28
	if len(data) != int(c.RecordSize) || y < 0 || y+26 > len(data) {
		return "", errors.New("reading EF_SMSP: malformed record")
	}

	sca := data[y+13 : y+25]
	if len(sca) < 2 {
		return "", nil
	}
	length := int(sca[0])
	// The length octet describes bytes after itself, so it must still fit inside
	// the fixed 12-byte SCA field.
	if length <= 1 || length+1 > len(sca) {
		return "", nil
	}
	if sca[1] != 0x91 {
		return "", nil
	}

	number := decodeSwappedBCD(sca[2:length+1], false)
	if number == "" {
		return "", nil
	}
	return "+" + number, nil
}

func (c ReadSMSCRecord) DecodeResponse(resp apdu.Response) (string, error) {
	return c.Decode(resp.Data())
}

func decodeSwappedBCD(data []byte, stripLeadingNine bool) string {
	encoded := strings.ToLower(hex.EncodeToString(data))
	var buf strings.Builder
	for i := 0; i+1 < len(encoded); i += 2 {
		buf.WriteByte(encoded[i+1])
		buf.WriteByte(encoded[i])
	}
	out := strings.TrimRight(buf.String(), "f")
	if stripLeadingNine && strings.HasPrefix(out, "9") {
		out = out[1:]
	}
	return out
}
