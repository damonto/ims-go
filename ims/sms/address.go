package sms

import (
	"errors"
	"fmt"
	"strings"
)

const (
	tpTOAUnknownISDN       = 0x81
	tpTOAInternationalISDN = 0x91
	tpTONShift             = 4
	tpTONMask              = 0x07
	tpTONInternational     = 0x01
	tpTONAlphanumeric      = 0x05
)

const (
	semiOctetMask = 0x0F
	semiOctetFill = 0x0F
	semiOctetStar = 0x0A
	semiOctetHash = 0x0B
	semiOctetA    = 0x0C
	semiOctetB    = 0x0D
	semiOctetC    = 0x0E
)

const (
	minRPAddressValueOctets = 2
	maxRPAddressValueOctets = 11
	minTPAddressOctets      = 2
	maxTPAddressOctets      = 12
)

func encodeTPAddress(number string) ([]byte, error) {
	number = strings.TrimSpace(number)
	toa := byte(tpTOAUnknownISDN)
	if strings.HasPrefix(number, "+") {
		toa = tpTOAInternationalISDN
		number = strings.TrimPrefix(number, "+")
	}
	if number == "" {
		return nil, errors.New("encoding TP address: address is empty")
	}
	if err := validateTPAddressDigits(number); err != nil {
		return nil, err
	}
	packed := swapDigits(number)
	data := append([]byte{byte(len(number)), toa}, packed...)
	if len(data) < minTPAddressOctets || len(data) > maxTPAddressOctets {
		return nil, fmt.Errorf("encoding TP address: invalid length %d", len(data))
	}
	return data, nil
}

func digitOctetCount(digits int) int {
	return (digits + 1) / 2
}

func validateTPAddressDigits(number string) error {
	for i := range len(number) {
		b := number[i]
		switch {
		case b >= '0' && b <= '9':
		case b == '*', b == '#':
		case b == 'a' || b == 'A' || b == 'b' || b == 'B' || b == 'c' || b == 'C':
		default:
			return fmt.Errorf("encoding TP address: invalid digit %q", b)
		}
	}
	return nil
}

func decodeAlphanumericAddress(data []byte, lengthSemiOctets int) (string, error) {
	septetCount := lengthSemiOctets * 4 / 7
	if septetCount == 0 {
		return "", nil
	}
	return decodeGSM7(unpackSeptets(data, septetCount))
}

func decodeTPAddress(data []byte) (string, int, error) {
	if len(data) < 2 {
		return "", 0, errors.New("decoding TP address: packet too short")
	}
	lengthSemiOctets := int(data[0])
	ton := (data[1] >> tpTONShift) & tpTONMask
	numberBytes := digitOctetCount(lengthSemiOctets)
	fullLen := 2 + numberBytes
	if fullLen < minTPAddressOctets || fullLen > maxTPAddressOctets {
		return "", 0, fmt.Errorf("decoding TP address: invalid length %d", fullLen)
	}
	if len(data) < fullLen {
		return "", 0, errors.New("decoding TP address: truncated address")
	}
	raw := data[2:fullLen]
	if ton == tpTONAlphanumeric {
		number, err := decodeAlphanumericAddress(raw, lengthSemiOctets)
		if err != nil {
			return "", 0, fmt.Errorf("decoding TP address: %w", err)
		}
		return number, fullLen, nil
	}
	number := unswapDigits(raw)
	if len(number) > lengthSemiOctets {
		number = number[:lengthSemiOctets]
	}
	if ton == tpTONInternational {
		number = "+" + number
	}
	return number, fullLen, nil
}

func encodeRPAddress(number string) []byte {
	number = strings.TrimPrefix(number, "+")
	if number == "" {
		return []byte{0x00}
	}
	packed := swapDigits(number)
	return append([]byte{byte(len(packed) + 1), tpTOAInternationalISDN}, packed...)
}

func marshalRPAddress(number string) ([]byte, error) {
	data := encodeRPAddress(number)
	if data[0] == 0 {
		return data, nil
	}
	if data[0] < minRPAddressValueOctets || data[0] > maxRPAddressValueOctets {
		return nil, fmt.Errorf("invalid length %d", data[0])
	}
	return data, nil
}

func decodeRPAddress(data []byte) (string, int, error) {
	if len(data) == 0 {
		return "", 0, errors.New("decoding RP address: packet too short")
	}
	length := int(data[0])
	if length == 0 {
		return "", 1, nil
	}
	if length < minRPAddressValueOctets || length > maxRPAddressValueOctets {
		return "", 0, fmt.Errorf("decoding RP address: invalid length %d", length)
	}
	if len(data) < 1+length {
		return "", 0, errors.New("decoding RP address: truncated address")
	}
	ton := (data[1] >> tpTONShift) & tpTONMask
	number := unswapDigits(data[2 : 1+length])
	if ton == tpTONInternational {
		number = "+" + number
	}
	return number, 1 + length, nil
}

func swapDigits(number string) []byte {
	if len(number)%2 == 1 {
		number += "f"
	}
	buf := make([]byte, 0, len(number)/2)
	for i := 0; i < len(number); i += 2 {
		high := fromHexNibble(number[i])
		low := fromHexNibble(number[i+1])
		buf = append(buf, low<<4|high)
	}
	return buf
}

func unswapDigits(data []byte) string {
	b := strings.Builder{}
	for _, v := range data {
		low := v & semiOctetMask
		high := v >> 4
		b.WriteByte(toHexNibble(low))
		if high != semiOctetFill {
			b.WriteByte(toHexNibble(high))
		}
	}
	return strings.TrimRight(b.String(), "f")
}

func fromHexNibble(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b == '*':
		return semiOctetStar
	case b == '#':
		return semiOctetHash
	case b == 'a' || b == 'A':
		return semiOctetA
	case b == 'b' || b == 'B':
		return semiOctetB
	case b == 'c' || b == 'C':
		return semiOctetC
	case b == 'f' || b == 'F':
		return semiOctetFill
	default:
		return 0
	}
}

func toHexNibble(v byte) byte {
	switch {
	case v < 10:
		return '0' + v
	case v == semiOctetStar:
		return '*'
	case v == semiOctetHash:
		return '#'
	case v == semiOctetA:
		return 'a'
	case v == semiOctetB:
		return 'b'
	case v == semiOctetC:
		return 'c'
	case v == semiOctetFill:
		return 'f'
	default:
		return '0'
	}
}
