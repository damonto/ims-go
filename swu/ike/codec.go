// Package ike encodes and decodes IKEv2 messages and payloads.
package ike

import (
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	ikeVersion20     byte = 0x20
	ikeMajorVersion2 byte = 2

	exchangeTypeIKESAInit     = 34
	exchangeTypeIKEAuth       = 35
	exchangeTypeCreateChildSA = 36
	exchangeTypeInformational = 37
)

const (
	flagInitiator = 0x08
	flagResponse  = 0x20
)

const ikeHeaderSize = 28

var (
	_ encoding.BinaryAppender    = Header{}
	_ encoding.BinaryMarshaler   = Header{}
	_ encoding.BinaryUnmarshaler = (*Header)(nil)
	_ encoding.BinaryAppender    = Packet{}
	_ encoding.BinaryMarshaler   = Packet{}
	_ encoding.BinaryUnmarshaler = (*Packet)(nil)
)

type Header struct {
	InitiatorSPI uint64
	ResponderSPI uint64
	NextPayload  byte
	Version      byte
	ExchangeType byte
	Flags        byte
	MessageID    uint32
	Length       uint32
}

func (h Header) MarshalBinary() ([]byte, error) {
	return h.AppendBinary(nil)
}

func (h Header) AppendBinary(dst []byte) ([]byte, error) {
	start := len(dst)
	dst = append(dst, make([]byte, ikeHeaderSize)...)
	binary.BigEndian.PutUint64(dst[start:start+8], h.InitiatorSPI)
	binary.BigEndian.PutUint64(dst[start+8:start+16], h.ResponderSPI)
	dst[start+16] = h.NextPayload
	dst[start+17] = h.Version
	dst[start+18] = h.ExchangeType
	dst[start+19] = h.Flags
	binary.BigEndian.PutUint32(dst[start+20:start+24], h.MessageID)
	binary.BigEndian.PutUint32(dst[start+24:start+28], h.Length)
	return dst, nil
}

func (h *Header) UnmarshalBinary(data []byte) error {
	if len(data) < ikeHeaderSize {
		return errors.New("parse ike header: packet too short")
	}
	*h = Header{
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

type Packet struct {
	Header   Header
	Payloads []Payload
	Raw      []byte
}

func (p Packet) MarshalBinary() ([]byte, error) {
	return p.AppendBinary(nil)
}

func (p Packet) AppendBinary(dst []byte) ([]byte, error) {
	firstPayload, body, err := MarshalPayloadChain(p.Payloads)
	if err != nil {
		return nil, fmt.Errorf("marshalling ike packet: %w", err)
	}
	header := p.Header
	header.NextPayload = firstPayload
	header.Length = uint32(len(body) + ikeHeaderSize)
	dst, err = header.AppendBinary(dst)
	if err != nil {
		return nil, fmt.Errorf("marshalling ike header: %w", err)
	}
	dst = append(dst, body...)
	return dst, nil
}

func (p *Packet) UnmarshalBinary(data []byte) error {
	var header Header
	if err := header.UnmarshalBinary(data); err != nil {
		return err
	}
	if header.Version>>4 != ikeMajorVersion2 {
		return fmt.Errorf("parse ike packet: invalid major version %d", header.Version>>4)
	}
	if !validExchangeType(header.ExchangeType) {
		return fmt.Errorf("parse ike packet: invalid exchange type %d", header.ExchangeType)
	}
	if header.Length != uint32(len(data)) {
		return fmt.Errorf("parse ike packet: invalid packet length %d", header.Length)
	}
	if header.Length <= ikeHeaderSize {
		return fmt.Errorf("parse ike packet: invalid packet length %d", header.Length)
	}
	payloads, err := DecodePayloadChain(header.NextPayload, data[ikeHeaderSize:header.Length])
	if err != nil {
		return err
	}
	*p = Packet{Header: header, Payloads: payloads, Raw: append([]byte(nil), data[:header.Length]...)}
	return nil
}

func validExchangeType(exchangeType byte) bool {
	switch exchangeType {
	case exchangeTypeIKESAInit, exchangeTypeIKEAuth, exchangeTypeCreateChildSA, exchangeTypeInformational:
		return true
	default:
		return false
	}
}
