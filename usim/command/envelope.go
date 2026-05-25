package command

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/damonto/ims-client/usim/apdu"
)

const (
	EnvelopeTagSMSPPDownload = 0xD1
)

type SMSPPDownload struct {
	ServiceCenterAddress string
	TPDU                 []byte
}

func (c SMSPPDownload) Envelope() ([]byte, error) {
	if len(c.TPDU) == 0 {
		return nil, errors.New("building SMS-PP download envelope: TPDU is empty")
	}

	body := make([]byte, 0, len(c.TPDU)+32)
	body = appendTLV(body, 0x82, []byte{0x83, 0x81})
	if strings.TrimSpace(c.ServiceCenterAddress) != "" {
		address, err := encodeEnvelopeAddress(c.ServiceCenterAddress)
		if err != nil {
			return nil, err
		}
		body = appendTLV(body, 0x86, address)
	}
	body = appendTLV(body, 0x8B, c.TPDU)

	out := []byte{EnvelopeTagSMSPPDownload}
	out = appendBERLength(out, len(body))
	out = append(out, body...)
	return out, nil
}

func (c SMSPPDownload) APDU() ([]byte, error) {
	envelope, err := c.Envelope()
	if err != nil {
		return nil, err
	}
	if len(envelope) <= 0xFF {
		le := byte(0)
		return apdu.Request{
			CLA:  0x80,
			INS:  0xC2,
			P1:   0x00,
			P2:   0x00,
			Data: envelope,
			Le:   &le,
		}.APDU(), nil
	}
	if len(envelope) > 0xFFFF {
		return nil, fmt.Errorf("building SMS-PP download APDU: envelope length %d exceeds extended APDU limit", len(envelope))
	}

	out := []byte{0x80, 0xC2, 0x00, 0x00, 0x00, byte(len(envelope) >> 8), byte(len(envelope))}
	out = append(out, envelope...)
	return append(out, 0x00, 0x00), nil
}

func appendTLV(out []byte, tag byte, value []byte) []byte {
	out = append(out, tag)
	out = appendBERLength(out, len(value))
	return append(out, value...)
}

func appendBERLength(out []byte, n int) []byte {
	switch {
	case n <= 0x7F:
		return append(out, byte(n))
	case n <= 0xFF:
		return append(out, 0x81, byte(n))
	default:
		return append(out, 0x82, byte(n>>8), byte(n))
	}
}

func encodeEnvelopeAddress(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}

	tonNPI := byte(0x81)
	if strings.HasPrefix(value, "+") {
		tonNPI = 0x91
		value = strings.TrimPrefix(value, "+")
	}
	value = strings.NewReplacer(" ", "", "-", "", "(", "", ")", "").Replace(value)
	if value == "" {
		return nil, errors.New("building SMS-PP download envelope: service centre address is empty")
	}
	if len(value)%2 == 1 {
		value += "F"
	}

	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("building SMS-PP download envelope: service centre address %q is not decimal", value)
	}

	out := make([]byte, 0, 1+len(raw))
	out = append(out, tonNPI)
	for _, b := range raw {
		out = append(out, b<<4|b>>4)
	}
	return out, nil
}
