package ims

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

const (
	rpDataMSToNetwork  = 0x00
	rpDataNetworkToMS  = 0x01
	rpAckMSToNetwork   = 0x02
	rpAckNetworkToMS   = 0x03
	rpErrorMSToNetwork = 0x04
	rpErrorNetworkToMS = 0x05
)

const (
	rpCauseInvalidMandatoryInformation  = 96
)

const (
	smsSingleGSM7Limit = 160
	smsConcatGSM7Limit = 153
	smsSingleUCS2Units = 70
	smsConcatUCS2Units = 67
	smsConcatIEI8Bit   = 0x00
	smsConcatIEI16Bit  = 0x08
)

type IncomingSMS struct {
	From string
	To   string
	Text string
}

type rpMessage struct {
	Type        byte
	Reference   byte
	TPDU        []byte
	Destination string
	Cause       byte
	HasCause    bool
	UserData    []byte
}

type RPError struct {
	Cause byte
}

func (e *RPError) Error() string {
	return fmt.Sprintf("rp-error cause %d", e.Cause)
}

type smsConcatInfo struct {
	Reference  uint16
	Total      byte
	Sequence   byte
	SixteenBit bool
}

type smsUserDataPart struct {
	udhi     bool
	dcs      byte
	udl      int
	userData []byte
}

func encodeSMSSubmit(reference byte, to, text string) ([]byte, error) {
	parts, err := buildSMSUserDataParts(text)
	if err != nil {
		return nil, err
	}
	if len(parts) != 1 {
		return nil, fmt.Errorf("encoding SMS-SUBMIT: message requires %d segments", len(parts))
	}
	return newSMSSubmitTPDU(reference, to, parts[0]).MarshalBinary()
}

func buildSMSUserDataParts(text string) ([]smsUserDataPart, error) {
	septets, err := encodeGSM7(text)
	if err == nil {
		return buildGSM7UserDataParts(septets)
	}
	parts := buildUCS2UserDataParts([]rune(text))
	if parts == nil {
		return nil, fmt.Errorf("encoding SMS-SUBMIT: UCS2 message exceeds 255-part limit")
	}
	return parts, nil
}

func buildGSM7UserDataParts(septets []byte) ([]smsUserDataPart, error) {
	if len(septets) <= smsSingleGSM7Limit {
		return []smsUserDataPart{{dcs: 0x00, udl: len(septets), userData: packSeptets(septets)}}, nil
	}
	chunks := splitGSM7Septets(septets, smsConcatGSM7Limit)
	if len(chunks) > 255 {
		return nil, fmt.Errorf("encoding SMS-SUBMIT: %d GSM7 segments exceed 255-part limit", len(chunks))
	}
	ref := byte(randomUint32())
	parts := make([]smsUserDataPart, 0, len(chunks))
	for i, chunk := range chunks {
		header := buildConcatUDH8(ref, byte(len(chunks)), byte(i+1))
		packed, headerSeptets := packSeptetsWithHeader(header, chunk)
		parts = append(parts, smsUserDataPart{udhi: true, dcs: 0x00, udl: headerSeptets + len(chunk), userData: packed})
	}
	return parts, nil
}

func buildUCS2UserDataParts(runes []rune) []smsUserDataPart {
	words := utf16.Encode(runes)
	if len(words) <= smsSingleUCS2Units {
		userData := encodeUCS2Words(words)
		return []smsUserDataPart{{dcs: 0x08, udl: len(userData), userData: userData}}
	}
	chunks := splitUCS2Words(words, smsConcatUCS2Units)
	if len(chunks) > 255 {
		return nil
	}
	ref := byte(randomUint32())
	parts := make([]smsUserDataPart, 0, len(chunks))
	for i, chunk := range chunks {
		header := buildConcatUDH8(ref, byte(len(chunks)), byte(i+1))
		userData := append(header, encodeUCS2Words(chunk)...)
		parts = append(parts, smsUserDataPart{udhi: true, dcs: 0x08, udl: len(userData), userData: userData})
	}
	return parts
}

func (p smsUserDataPart) marshalDeliver(from string) []byte {
	payload, _ := newSMSDeliverTPDU(from, p).MarshalBinary()
	return payload
}

func decodeSMSDeliver(data []byte) (IncomingSMS, error) {
	var deliver smsDeliverTPDU
	if err := deliver.UnmarshalBinary(data); err != nil {
		return IncomingSMS{}, err
	}
	return deliver.Message, nil
}

func buildSMSDeliver(from, text string) ([]byte, error) {
	parts, err := buildSMSUserDataParts(text)
	if err != nil {
		return nil, err
	}
	if len(parts) != 1 {
		return nil, fmt.Errorf("building SMS-DELIVER: message requires %d segments", len(parts))
	}
	return newSMSDeliverTPDU(from, parts[0]).MarshalBinary()
}

func decodeRPUserData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) < 2 {
		return nil, errors.New("decoding RP user data: truncated field")
	}
	if data[0] != 0x41 {
		return nil, fmt.Errorf("decoding RP user data: unexpected IEI 0x%02X", data[0])
	}
	length := int(data[1])
	if len(data) < 2+length {
		return nil, errors.New("decoding RP user data: truncated payload")
	}
	return append([]byte(nil), data[2:2+length]...), nil
}

func encodeTPAddress(number string) []byte {
	number = strings.TrimPrefix(number, "+")
	packed := swapDigits(number)
	return append([]byte{byte(len(number)), 0x91}, packed...)
}

func digitOctetCount(digits int) int {
	return (digits + 1) / 2
}

func decodeTPAddress(data []byte) (string, int, error) {
	if len(data) < 2 {
		return "", 0, errors.New("decoding TP address: packet too short")
	}
	lengthDigits := int(data[0])
	numberBytes := digitOctetCount(lengthDigits)
	if len(data) < 2+numberBytes {
		return "", 0, errors.New("decoding TP address: truncated address")
	}
	number := unswapDigits(data[2 : 2+numberBytes])
	if len(number) > lengthDigits {
		number = number[:lengthDigits]
	}
	return number, 2 + numberBytes, nil
}

func encodeRPAddress(number string) []byte {
	number = strings.TrimPrefix(number, "+")
	packed := swapDigits(number)
	return append([]byte{byte(len(packed) + 1), 0x91}, packed...)
}

func decodeRPAddress(data []byte) (string, int, error) {
	if len(data) == 0 {
		return "", 0, errors.New("decoding RP address: packet too short")
	}
	length := int(data[0])
	if length == 0 {
		return "", 1, nil
	}
	if len(data) < 1+length {
		return "", 0, errors.New("decoding RP address: truncated address")
	}
	number := unswapDigits(data[2 : 1+length])
	return number, 1 + length, nil
}

func encodeUserData(text string) ([]byte, byte, byte, error) {
	septets, err := encodeGSM7(text)
	if err == nil {
		return packSeptets(septets), 0x00, byte(len(septets)), nil
	}
	ucs2 := encodeUCS2(text)
	return ucs2, 0x08, byte(len(ucs2)), nil
}

func buildConcatUDH8(reference, total, sequence byte) []byte {
	return []byte{0x05, smsConcatIEI8Bit, 0x03, reference, total, sequence}
}

func decodeSMSUserDataHeader(payload []byte) (int, *smsConcatInfo, error) {
	if len(payload) == 0 {
		return 0, nil, errors.New("decoding SMS UDH: missing UDHL")
	}
	headerLen := int(payload[0]) + 1
	if len(payload) < headerLen {
		return 0, nil, errors.New("decoding SMS UDH: truncated header")
	}
	concat, err := decodeSMSConcatInfo(payload[:headerLen])
	if err != nil {
		return 0, nil, err
	}
	return headerLen, concat, nil
}

func decodeSMSConcatInfo(header []byte) (*smsConcatInfo, error) {
	if len(header) == 0 {
		return nil, nil
	}
	limit := int(header[0]) + 1
	if len(header) < limit {
		return nil, errors.New("decoding SMS UDH: truncated information elements")
	}
	for idx := 1; idx < limit; {
		if idx+2 > limit {
			return nil, errors.New("decoding SMS UDH: truncated information element")
		}
		iei := header[idx]
		length := int(header[idx+1])
		idx += 2
		if idx+length > limit {
			return nil, errors.New("decoding SMS UDH: truncated information element data")
		}
		data := header[idx : idx+length]
		idx += length
		switch iei {
		case smsConcatIEI8Bit:
			if length != 3 {
				continue
			}
			if data[1] == 0 || data[2] == 0 || data[2] > data[1] {
				continue
			}
			return &smsConcatInfo{Reference: uint16(data[0]), Total: data[1], Sequence: data[2]}, nil
		case smsConcatIEI16Bit:
			if length != 4 {
				continue
			}
			if data[2] == 0 || data[3] == 0 || data[3] > data[2] {
				continue
			}
			return &smsConcatInfo{Reference: binary.BigEndian.Uint16(data[:2]), Total: data[2], Sequence: data[3], SixteenBit: true}, nil
		}
	}
	return nil, nil
}

func splitGSM7Septets(septets []byte, limit int) [][]byte {
	parts := make([][]byte, 0, (len(septets)+limit-1)/limit)
	for len(septets) > 0 {
		end := min(len(septets), limit)
		if end < len(septets) && septets[end-1] == 0x1B {
			end--
		}
		if end <= 0 {
			end = min(len(septets), limit)
		}
		parts = append(parts, append([]byte(nil), septets[:end]...))
		septets = septets[end:]
	}
	return parts
}

func splitUCS2Words(words []uint16, limit int) [][]uint16 {
	parts := make([][]uint16, 0, (len(words)+limit-1)/limit)
	for len(words) > 0 {
		end := min(len(words), limit)
		parts = append(parts, append([]uint16(nil), words[:end]...))
		words = words[end:]
	}
	return parts
}

func encodeUCS2Words(words []uint16) []byte {
	buf := make([]byte, len(words)*2)
	for i, word := range words {
		binary.BigEndian.PutUint16(buf[i*2:], word)
	}
	return buf
}

func gsm7OctetCount(septets int) int {
	return (septets*7 + 7) / 8
}

func septetCountForOctets(octets int) int {
	return (octets*8 + 6) / 7
}

func packSeptetsWithHeader(header []byte, septets []byte) ([]byte, int) {
	headerSeptets := septetCountForOctets(len(header))
	bitPos := headerSeptets * 7
	out := make([]byte, (bitPos+len(septets)*7+7)/8)
	copy(out, header)
	for _, septet := range septets {
		for bit := range 7 {
			if septet&(1<<bit) == 0 {
				bitPos++
				continue
			}
			out[bitPos/8] |= 1 << (bitPos % 8)
			bitPos++
		}
	}
	return out, headerSeptets
}

func unpackSeptetsAt(octets []byte, bitOffset, count int) []byte {
	septets := make([]byte, 0, count)
	for i := range count {
		bitPos := bitOffset + i*7
		var septet byte
		for bit := range 7 {
			pos := bitPos + bit
			if pos/8 >= len(octets) {
				break
			}
			if octets[pos/8]&(1<<(pos%8)) != 0 {
				septet |= 1 << bit
			}
		}
		septets = append(septets, septet)
	}
	return septets
}

func encodeGSM7(text string) ([]byte, error) {
	septets := make([]byte, 0, len(text))
	for _, r := range text {
		if value, ok := gsm7EncodeMap[r]; ok {
			septets = append(septets, value)
			continue
		}
		if value, ok := gsm7ExtensionEncodeMap[r]; ok {
			septets = append(septets, 0x1B, value)
			continue
		}
		return nil, fmt.Errorf("encoding GSM7: unsupported rune %q", r)
	}
	return septets, nil
}

func decodeGSM7(septets []byte) (string, error) {
	b := strings.Builder{}
	for i := 0; i < len(septets); i++ {
		septet := septets[i]
		if septet == 0x1B {
			if i+1 >= len(septets) {
				b.WriteRune('�')
				continue
			}
			i++
			if r, ok := gsm7ExtensionDecodeMap[septets[i]]; ok {
				b.WriteRune(r)
			} else {
				b.WriteRune('�')
			}
			continue
		}
		if r, ok := gsm7DecodeMap[septet]; ok {
			b.WriteRune(r)
			continue
		}
		b.WriteRune('�')
	}
	return b.String(), nil
}

func packSeptets(septets []byte) []byte {
	var out []byte
	var bitBuf uint64
	var bitCount uint
	for _, septet := range septets {
		bitBuf |= uint64(septet&0x7F) << bitCount
		bitCount += 7
		for bitCount >= 8 {
			out = append(out, byte(bitBuf))
			bitBuf >>= 8
			bitCount -= 8
		}
	}
	if bitCount > 0 {
		out = append(out, byte(bitBuf))
	}
	return out
}

func unpackSeptets(octets []byte, count int) []byte {
	septets := make([]byte, 0, count)
	var bitBuf uint64
	var bitCount uint
	for _, octet := range octets {
		bitBuf |= uint64(octet) << bitCount
		bitCount += 8
		for bitCount >= 7 && len(septets) < count {
			septets = append(septets, byte(bitBuf&0x7F))
			bitBuf >>= 7
			bitCount -= 7
		}
	}
	return septets
}

func encodeUCS2(text string) []byte {
	return encodeUCS2Words(utf16.Encode([]rune(text)))
}

func decodeUCS2(data []byte) string {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	words := make([]uint16, 0, len(data)/2)
	for len(data) >= 2 {
		words = append(words, binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	return string(utf16.Decode(words))
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
		low := v & 0x0F
		high := v >> 4
		b.WriteByte(toHexNibble(low))
		if high != 0x0F {
			b.WriteByte(toHexNibble(high))
		}
	}
	return strings.TrimRight(b.String(), "f")
}

func fromHexNibble(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b == 'f' || b == 'F':
		return 0x0F
	default:
		return 0
	}
}

func toHexNibble(v byte) byte {
	if v < 10 {
		return '0' + v
	}
	return 'a' + (v - 10)
}

var gsm7EncodeMap = map[rune]byte{
	'@': 0x00, '£': 0x01, '$': 0x02, '¥': 0x03, 'è': 0x04, 'é': 0x05, 'ù': 0x06, 'ì': 0x07,
	'ò': 0x08, 'Ç': 0x09, '\n': 0x0A, 'Ø': 0x0B, 'ø': 0x0C, '\r': 0x0D, 'Å': 0x0E, 'å': 0x0F,
	'Δ': 0x10, '_': 0x11, 'Φ': 0x12, 'Γ': 0x13, 'Λ': 0x14, 'Ω': 0x15, 'Π': 0x16, 'Ψ': 0x17,
	'Σ': 0x18, 'Θ': 0x19, 'Ξ': 0x1A, 'Æ': 0x1C, 'æ': 0x1D, 'ß': 0x1E, 'É': 0x1F, ' ': 0x20,
	'!': 0x21, '"': 0x22, '#': 0x23, '¤': 0x24, '%': 0x25, '&': 0x26, '\'': 0x27, '(': 0x28,
	')': 0x29, '*': 0x2A, '+': 0x2B, ',': 0x2C, '-': 0x2D, '.': 0x2E, '/': 0x2F,
	'0': 0x30, '1': 0x31, '2': 0x32, '3': 0x33, '4': 0x34, '5': 0x35, '6': 0x36, '7': 0x37,
	'8': 0x38, '9': 0x39, ':': 0x3A, ';': 0x3B, '<': 0x3C, '=': 0x3D, '>': 0x3E, '?': 0x3F,
	'¡': 0x40,
	'A': 0x41, 'B': 0x42, 'C': 0x43, 'D': 0x44, 'E': 0x45, 'F': 0x46, 'G': 0x47, 'H': 0x48,
	'I': 0x49, 'J': 0x4A, 'K': 0x4B, 'L': 0x4C, 'M': 0x4D, 'N': 0x4E, 'O': 0x4F,
	'P': 0x50, 'Q': 0x51, 'R': 0x52, 'S': 0x53, 'T': 0x54, 'U': 0x55, 'V': 0x56, 'W': 0x57,
	'X': 0x58, 'Y': 0x59, 'Z': 0x5A,
	'Ä': 0x5B, 'Ö': 0x5C, 'Ñ': 0x5D, 'Ü': 0x5E, '§': 0x5F,
	'¿': 0x60,
	'a': 0x61, 'b': 0x62, 'c': 0x63, 'd': 0x64, 'e': 0x65, 'f': 0x66, 'g': 0x67, 'h': 0x68,
	'i': 0x69, 'j': 0x6A, 'k': 0x6B, 'l': 0x6C, 'm': 0x6D, 'n': 0x6E, 'o': 0x6F,
	'p': 0x70, 'q': 0x71, 'r': 0x72, 's': 0x73, 't': 0x74, 'u': 0x75, 'v': 0x76, 'w': 0x77,
	'x': 0x78, 'y': 0x79, 'z': 0x7A,
	'ä': 0x7B, 'ö': 0x7C, 'ñ': 0x7D, 'ü': 0x7E, 'à': 0x7F,
}

var gsm7ExtensionEncodeMap = map[rune]byte{
	'^':  0x14,
	'{':  0x28,
	'}':  0x29,
	'\\': 0x2F,
	'[':  0x3C,
	'~':  0x3D,
	']':  0x3E,
	'|':  0x40,
	'€':  0x65,
}

var gsm7DecodeMap map[byte]rune
var gsm7ExtensionDecodeMap map[byte]rune

func init() {
	gsm7DecodeMap = make(map[byte]rune, len(gsm7EncodeMap))
	for r, v := range gsm7EncodeMap {
		gsm7DecodeMap[v] = r
	}
	gsm7ExtensionDecodeMap = make(map[byte]rune, len(gsm7ExtensionEncodeMap))
	for r, v := range gsm7ExtensionEncodeMap {
		gsm7ExtensionDecodeMap[v] = r
	}
}
