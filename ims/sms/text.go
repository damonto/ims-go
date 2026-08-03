package sms

import (
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	gsm7EscapeSeptet = 0x1B
	gsm7SeptetBits   = 7
	gsm7SeptetMask   = 0x7F
	octetBits        = 8
)

type GSM7 struct {
	septets []byte
}

type UCS2 string

var (
	_ encoding.BinaryAppender    = GSM7{}
	_ encoding.BinaryMarshaler   = GSM7{}
	_ encoding.BinaryUnmarshaler = (*GSM7)(nil)
	_ encoding.TextAppender      = GSM7{}
	_ encoding.TextMarshaler     = GSM7{}
	_ encoding.TextUnmarshaler   = (*GSM7)(nil)
	_ encoding.BinaryAppender    = UCS2("")
	_ encoding.BinaryMarshaler   = UCS2("")
	_ encoding.BinaryUnmarshaler = (*UCS2)(nil)
	_ encoding.TextAppender      = UCS2("")
	_ encoding.TextMarshaler     = UCS2("")
	_ encoding.TextUnmarshaler   = (*UCS2)(nil)
)

func NewGSM7(text string) (GSM7, error) {
	septets, err := encodeGSM7Septets(text)
	if err != nil {
		return GSM7{}, err
	}
	return GSM7{septets: septets}, nil
}

func (g GSM7) MarshalBinary() ([]byte, error) {
	return g.AppendBinary(nil)
}

func (g GSM7) AppendBinary(dst []byte) ([]byte, error) {
	return append(dst, g.septets...), nil
}

func (g *GSM7) UnmarshalBinary(data []byte) error {
	g.septets = slices.Clone(data)
	return nil
}

func (g GSM7) MarshalText() ([]byte, error) {
	return g.AppendText(nil)
}

func (g GSM7) AppendText(dst []byte) ([]byte, error) {
	if err := validateGSM7Septets(g.septets); err != nil {
		return nil, err
	}
	return append(dst, g.String()...), nil
}

func (g *GSM7) UnmarshalText(text []byte) error {
	value, err := NewGSM7(string(text))
	if err != nil {
		return err
	}
	*g = value
	return nil
}

func (g GSM7) String() string {
	return decodeGSM7Septets(g.septets)
}

func (g GSM7) Packed() []byte {
	return packSeptets(g.septets)
}

func (g GSM7) SeptetCount() int {
	return len(g.septets)
}

func (u UCS2) MarshalBinary() ([]byte, error) {
	return u.AppendBinary(nil)
}

func (u UCS2) AppendBinary(dst []byte) ([]byte, error) {
	return append(dst, encodeUCS2Words(utf16.Encode([]rune(string(u))))...), nil
}

func (u *UCS2) UnmarshalBinary(data []byte) error {
	if len(data)%2 != 0 {
		return fmt.Errorf("decoding UCS2: byte length %d is odd", len(data))
	}
	*u = UCS2(decodeUCS2String(data))
	return nil
}

func (u UCS2) MarshalText() ([]byte, error) {
	return u.AppendText(nil)
}

func (u UCS2) AppendText(dst []byte) ([]byte, error) {
	if !utf8.ValidString(string(u)) {
		return nil, errors.New("marshaling UCS2 text: invalid UTF-8")
	}
	return append(dst, u...), nil
}

func (u *UCS2) UnmarshalText(text []byte) error {
	if !utf8.Valid(text) {
		return errors.New("parsing UCS2 text: invalid UTF-8")
	}
	*u = UCS2(text)
	return nil
}

func encodeGSM7(text string) ([]byte, error) {
	value, err := NewGSM7(text)
	if err != nil {
		return nil, err
	}
	return value.MarshalBinary()
}

func encodeGSM7Septets(text string) ([]byte, error) {
	septets := make([]byte, 0, len(text))
	for _, r := range text {
		if value, ok := gsm7EncodeMap[r]; ok {
			septets = append(septets, value)
			continue
		}
		if value, ok := gsm7ExtensionEncodeMap[r]; ok {
			septets = append(septets, gsm7EscapeSeptet, value)
			continue
		}
		return nil, fmt.Errorf("encoding GSM7: unsupported rune %q", r)
	}
	return septets, nil
}

func decodeGSM7(septets []byte) (string, error) {
	var value GSM7
	if err := value.UnmarshalBinary(septets); err != nil {
		return "", err
	}
	return value.String(), nil
}

func decodeGSM7Septets(septets []byte) string {
	b := strings.Builder{}
	for i := 0; i < len(septets); i++ {
		septet := septets[i]
		if septet == gsm7EscapeSeptet {
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
	return b.String()
}

func validateGSM7Septets(septets []byte) error {
	for i := 0; i < len(septets); i++ {
		septet := septets[i]
		if septet != gsm7EscapeSeptet {
			if _, ok := gsm7DecodeMap[septet]; !ok {
				return fmt.Errorf("marshaling GSM7 text: invalid septet 0x%02X", septet)
			}
			continue
		}
		if i+1 >= len(septets) {
			return errors.New("marshaling GSM7 text: escape septet is missing its extension")
		}
		i++
		if _, ok := gsm7ExtensionDecodeMap[septets[i]]; !ok {
			return fmt.Errorf("marshaling GSM7 text: invalid extension septet 0x%02X", septets[i])
		}
	}
	return nil
}

func gsm7OctetCount(septets int) int {
	return (septets*gsm7SeptetBits + gsm7SeptetBits) / octetBits
}

func septetCountForOctets(octets int) int {
	return (octets*octetBits + gsm7SeptetBits - 1) / gsm7SeptetBits
}

func packSeptetsWithHeader(header []byte, septets []byte) ([]byte, int) {
	headerSeptets := septetCountForOctets(len(header))
	bitPos := headerSeptets * gsm7SeptetBits
	out := make([]byte, (bitPos+len(septets)*gsm7SeptetBits+gsm7SeptetBits)/octetBits)
	copy(out, header)
	for _, septet := range septets {
		for bit := range gsm7SeptetBits {
			if septet&(1<<bit) == 0 {
				bitPos++
				continue
			}
			out[bitPos/octetBits] |= 1 << (bitPos % octetBits)
			bitPos++
		}
	}
	return out, headerSeptets
}

func unpackSeptetsAt(octets []byte, bitOffset, count int) []byte {
	septets := make([]byte, 0, count)
	for i := range count {
		bitPos := bitOffset + i*gsm7SeptetBits
		var septet byte
		for bit := range gsm7SeptetBits {
			pos := bitPos + bit
			if pos/octetBits >= len(octets) {
				break
			}
			if octets[pos/octetBits]&(1<<(pos%octetBits)) != 0 {
				septet |= 1 << bit
			}
		}
		septets = append(septets, septet)
	}
	return septets
}

func packSeptets(septets []byte) []byte {
	var out []byte
	var bitBuf uint64
	var bitCount uint
	for _, septet := range septets {
		bitBuf |= uint64(septet&gsm7SeptetMask) << bitCount
		bitCount += gsm7SeptetBits
		for bitCount >= octetBits {
			out = append(out, byte(bitBuf))
			bitBuf >>= octetBits
			bitCount -= octetBits
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
		bitCount += octetBits
		for bitCount >= gsm7SeptetBits && len(septets) < count {
			septets = append(septets, byte(bitBuf&gsm7SeptetMask))
			bitBuf >>= gsm7SeptetBits
			bitCount -= gsm7SeptetBits
		}
	}
	return septets
}

func encodeUCS2(text string) []byte {
	return encodeUCS2Words(utf16.Encode([]rune(text)))
}

func decodeUCS2(data []byte) (string, error) {
	var value UCS2
	if err := value.UnmarshalBinary(data); err != nil {
		return "", err
	}
	return string(value), nil
}

func encodeUCS2Words(words []uint16) []byte {
	buf := make([]byte, len(words)*2)
	for i, word := range words {
		binary.BigEndian.PutUint16(buf[i*2:], word)
	}
	return buf
}

func decodeUCS2String(data []byte) string {
	words := make([]uint16, 0, len(data)/2)
	for len(data) >= 2 {
		words = append(words, binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	return string(utf16.Decode(words))
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
