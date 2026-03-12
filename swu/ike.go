package swu

import (
	"encoding"
	"encoding/binary"
	"fmt"
)

const (
	ikeVersion20 byte = 0x20

	exchangeTypeIKESAInit     byte = 34
	exchangeTypeIKEAuth       byte = 35
	exchangeTypeInformational byte = 37
)

const (
	flagInitiator = 0x08
	flagVersion   = 0x10
	flagResponse  = 0x20
)

const (
	transformENCRAESCBC      uint16 = 12
	transformPRFHMACMD5      uint16 = 1
	transformPRFHMACSHA1     uint16 = 2
	transformPRFHMACSHA256   uint16 = 5
	transformINTEGHMACMD596  uint16 = 1
	transformINTEGHMACSHA196 uint16 = 2
	transformINTEGHMACSHA256 uint16 = 12
	transformDH1024MODP      uint16 = 2
	transformDH2048MODP      uint16 = 14
)

const ikeHeaderSize = 28

var (
	_ encoding.BinaryMarshaler   = IKEHeader{}
	_ encoding.BinaryUnmarshaler = (*IKEHeader)(nil)
	_ encoding.BinaryMarshaler   = IKEPacket{}
	_ encoding.BinaryUnmarshaler = (*IKEPacket)(nil)
)

type IKEHeader struct {
	InitiatorSPI uint64
	ResponderSPI uint64
	NextPayload  byte
	Version      byte
	ExchangeType byte
	Flags        byte
	MessageID    uint32
	Length       uint32
}

func (h IKEHeader) MarshalBinary() ([]byte, error) {
	buf := make([]byte, ikeHeaderSize)
	binary.BigEndian.PutUint64(buf[0:8], h.InitiatorSPI)
	binary.BigEndian.PutUint64(buf[8:16], h.ResponderSPI)
	buf[16] = h.NextPayload
	buf[17] = h.Version
	buf[18] = h.ExchangeType
	buf[19] = h.Flags
	binary.BigEndian.PutUint32(buf[20:24], h.MessageID)
	binary.BigEndian.PutUint32(buf[24:28], h.Length)
	return buf, nil
}

func (h *IKEHeader) UnmarshalBinary(data []byte) error {
	if len(data) < ikeHeaderSize {
		return fmt.Errorf("parse ike header: packet too short")
	}
	*h = IKEHeader{
		InitiatorSPI: binary.BigEndian.Uint64(data[0:8]),
		ResponderSPI: binary.BigEndian.Uint64(data[8:16]),
		NextPayload:  data[16],
		Version:      data[17],
		ExchangeType: data[18],
		Flags:        data[19],
		MessageID:    binary.BigEndian.Uint32(data[20:24]),
		Length:       binary.BigEndian.Uint32(data[24:28]),
	}
	return nil
}

type IKEPacket struct {
	Header   IKEHeader
	Payloads []Payload
	Raw      []byte
}

func (p IKEPacket) MarshalBinary() ([]byte, error) {
	firstPayload, body, err := marshalPayloadChain(p.Payloads)
	if err != nil {
		return nil, fmt.Errorf("marshalling ike packet: %w", err)
	}
	header := p.Header
	header.NextPayload = firstPayload
	header.Length = uint32(len(body) + ikeHeaderSize)
	buf, err := header.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshalling ike header: %w", err)
	}
	buf = append(buf, body...)
	return buf, nil
}

func (p *IKEPacket) UnmarshalBinary(data []byte) error {
	var header IKEHeader
	if err := header.UnmarshalBinary(data); err != nil {
		return err
	}
	if int(header.Length) < ikeHeaderSize || int(header.Length) > len(data) {
		return fmt.Errorf("parse ike packet: invalid packet length %d", header.Length)
	}
	payloads, err := decodePayloadChain(header.NextPayload, data[ikeHeaderSize:header.Length])
	if err != nil {
		return err
	}
	*p = IKEPacket{Header: header, Payloads: payloads, Raw: append([]byte(nil), data[:header.Length]...)}
	return nil
}
