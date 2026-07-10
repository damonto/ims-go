package bitstream

import (
	"fmt"
	"io"
)

const (
	bitsPerByte       = 8
	maxParameterWidth = 15
)

// Params carries AMR analysis parameters and their bit widths.
type Params struct {
	Widths []int
	Values []int16
}

// Speech carries ETS serial bits and the speech-payload bit order.
type Speech struct {
	Order  []int
	BitLen int
	Serial []byte
}

// BitLen returns the total number of serial bits described by widths.
func BitLen(widths []int) int {
	total := 0
	for _, width := range widths {
		total += width
	}
	return total
}

// ByteLen returns the number of bytes needed to carry bits.
func ByteLen(bits int) int {
	if bits <= 0 {
		return 0
	}
	return (bits + bitsPerByte - 1) / bitsPerByte
}

// Pack converts analysis parameters into ETS serial bits.
func (p Params) Pack(dst []byte) ([]byte, error) {
	if len(p.Values) != len(p.Widths) {
		return nil, fmt.Errorf("parameter count %d, want %d", len(p.Values), len(p.Widths))
	}
	bits, err := checkedBitLen(p.Widths)
	if err != nil {
		return nil, err
	}
	for i, width := range p.Widths {
		value := int(p.Values[i])
		if value < 0 || value >= 1<<width {
			return nil, fmt.Errorf("parameter %d value %d does not fit %d bits", i, value, width)
		}
	}
	dst = resizeBytes(dst, bits)

	offset := 0
	for i, width := range p.Widths {
		value := int(p.Values[i])
		for bit := width - 1; bit >= 0; bit-- {
			dst[offset] = byte((value >> bit) & 1)
			offset++
		}
	}
	return dst, nil
}

// AppendBinary appends ETS serial bits for p.
func (p Params) AppendBinary(dst []byte) ([]byte, error) {
	out, err := p.Pack(dst[len(dst):])
	if err != nil {
		return nil, err
	}
	return append(dst, out...), nil
}

// MarshalBinary returns ETS serial bits for p.
func (p Params) MarshalBinary() ([]byte, error) {
	return p.AppendBinary(nil)
}

// WriteTo writes ETS serial bits for p to w.
func (p Params) WriteTo(w io.Writer) (int64, error) {
	data, err := p.AppendBinary(nil)
	if err != nil {
		return 0, err
	}
	return writeBytes(w, data)
}

// UnmarshalBinary converts ETS serial bits into p.Values.
func (p *Params) UnmarshalBinary(bits []byte) error {
	total, err := checkedBitLen(p.Widths)
	if err != nil {
		return err
	}
	if len(bits) != total {
		return fmt.Errorf("serial bit count %d, want %d", len(bits), total)
	}
	if err := validateSerialBits(bits); err != nil {
		return err
	}
	if cap(p.Values) < len(p.Widths) {
		p.Values = make([]int16, len(p.Widths))
	} else {
		p.Values = p.Values[:len(p.Widths)]
	}

	offset := 0
	for i, width := range p.Widths {
		value := 0
		for range width {
			value = (value << 1) | int(bits[offset])
			offset++
		}
		p.Values[i] = int16(value)
	}
	return nil
}

// ReadFrom reads ETS serial bits for p from r.
func (p *Params) ReadFrom(r io.Reader) (int64, error) {
	bits, err := checkedBitLen(p.Widths)
	if err != nil {
		return 0, err
	}
	data := make([]byte, bits)
	n, err := io.ReadFull(r, data)
	if err != nil {
		return int64(n), fmt.Errorf("reading serial parameters: %w", err)
	}
	if err := p.UnmarshalBinary(data); err != nil {
		return int64(n), err
	}
	return int64(n), nil
}

// Pack packs serial bits into MSB-first speech payload order.
//
// Order maps payload bit index to source serial bit index. A nil order means
// identity ordering.
func (s Speech) Pack(dst []byte) ([]byte, error) {
	if err := validateBitLen(s.BitLen); err != nil {
		return nil, err
	}
	if len(s.Serial) != s.BitLen {
		return nil, fmt.Errorf("serial bit count %d, want %d", len(s.Serial), s.BitLen)
	}
	if err := validateOrder(s.Order, s.BitLen); err != nil {
		return nil, err
	}
	if err := validateSerialBits(s.Serial); err != nil {
		return nil, err
	}
	dst = resizeBytes(dst, ByteLen(s.BitLen))

	for i := range s.BitLen {
		src := orderedIndex(s.Order, i)
		if src < 0 || src >= s.BitLen {
			return nil, fmt.Errorf("bit order %d maps to %d outside 0..%d", i, src, s.BitLen-1)
		}
		bit := s.Serial[src]
		if bit != 0 {
			dst[i/bitsPerByte] |= 1 << (bitsPerByte - 1 - i%bitsPerByte)
		}
	}
	return dst, nil
}

// AppendBinary appends speech payload bytes for s.
func (s Speech) AppendBinary(dst []byte) ([]byte, error) {
	out, err := s.Pack(dst[len(dst):])
	if err != nil {
		return nil, err
	}
	return append(dst, out...), nil
}

// MarshalBinary returns speech payload bytes for s.
func (s Speech) MarshalBinary() ([]byte, error) {
	return s.AppendBinary(nil)
}

// WriteTo writes packed speech payload bytes for s to w.
func (s Speech) WriteTo(w io.Writer) (int64, error) {
	data, err := s.AppendBinary(nil)
	if err != nil {
		return 0, err
	}
	return writeBytes(w, data)
}

// UnmarshalBinary unpacks MSB-first speech payload bytes into s.Serial.
//
// Order maps payload bit index to destination serial bit index. A nil order
// means identity ordering.
func (s *Speech) UnmarshalBinary(speech []byte) error {
	if err := validateBitLen(s.BitLen); err != nil {
		return err
	}
	byteLen := ByteLen(s.BitLen)
	if len(speech) != byteLen {
		return fmt.Errorf("speech byte count %d, want %d", len(speech), byteLen)
	}
	if err := validateOrder(s.Order, s.BitLen); err != nil {
		return err
	}
	s.Serial = resizeBytes(s.Serial, s.BitLen)

	for i := range s.BitLen {
		dstIndex := orderedIndex(s.Order, i)
		if dstIndex < 0 || dstIndex >= s.BitLen {
			return fmt.Errorf("bit order %d maps to %d outside 0..%d", i, dstIndex, s.BitLen-1)
		}
		s.Serial[dstIndex] = (speech[i/bitsPerByte] >> (bitsPerByte - 1 - i%bitsPerByte)) & 1
	}
	return nil
}

// ReadFrom reads packed speech payload bytes for s from r.
func (s *Speech) ReadFrom(r io.Reader) (int64, error) {
	if err := validateBitLen(s.BitLen); err != nil {
		return 0, err
	}
	data := make([]byte, ByteLen(s.BitLen))
	n, err := io.ReadFull(r, data)
	if err != nil {
		return int64(n), fmt.Errorf("reading speech payload: %w", err)
	}
	if err := s.UnmarshalBinary(data); err != nil {
		return int64(n), err
	}
	return int64(n), nil
}

func resizeBytes(dst []byte, n int) []byte {
	if cap(dst) < n {
		return make([]byte, n)
	}
	dst = dst[:n]
	clear(dst)
	return dst
}

func checkedBitLen(widths []int) (int, error) {
	total := 0
	for i, width := range widths {
		if width < 0 {
			return 0, fmt.Errorf("parameter %d bit width %d is negative", i, width)
		}
		if width > maxParameterWidth {
			return 0, fmt.Errorf("parameter %d bit width %d exceeds %d", i, width, maxParameterWidth)
		}
		total += width
	}
	return total, nil
}

func validateBitLen(bits int) error {
	if bits < 0 {
		return fmt.Errorf("bit count %d is negative", bits)
	}
	return nil
}

func validateOrder(order []int, bits int) error {
	if order == nil {
		return nil
	}
	if len(order) < bits {
		return fmt.Errorf("bit order length %d, want at least %d", len(order), bits)
	}
	seen := make([]bool, bits)
	for i, index := range order[:bits] {
		if index < 0 || index >= bits {
			return fmt.Errorf("bit order %d maps to %d outside 0..%d", i, index, bits-1)
		}
		if seen[index] {
			return fmt.Errorf("bit order %d duplicates serial bit %d", i, index)
		}
		seen[index] = true
	}
	return nil
}

func validateSerialBits(bits []byte) error {
	for i, bit := range bits {
		if bit > 1 {
			return fmt.Errorf("serial bit %d is %d, want 0 or 1", i, bit)
		}
	}
	return nil
}

func orderedIndex(order []int, i int) int {
	if order == nil {
		return i
	}
	return order[i]
}

func writeBytes(w io.Writer, data []byte) (int64, error) {
	n, err := w.Write(data)
	if n != len(data) && err == nil {
		err = io.ErrShortWrite
	}
	return int64(n), err
}
