package bitstream

import (
	"fmt"
	"io"
)

// ParamSpec describes how one AMR codec maps mode-specific parameters to ETS
// serial bits.
type ParamSpec struct {
	Codec      string
	Widths     func(mode int) ([]int, error)
	SerialBits func(mode int) (int, error)
}

// SpeechSpec describes how one AMR codec maps ETS serial bits to payload bytes.
type SpeechSpec struct {
	Codec  string
	Order  func(mode int) ([]int, error)
	BitLen func(mode int) (int, error)
}

// ParameterSerialBits returns the serial bit count for mode.
func (s ParamSpec) ParameterSerialBits(mode int) (int, error) {
	widths, err := s.widths(mode)
	if err != nil {
		return 0, err
	}
	return s.serialBits(mode, BitLen(widths))
}

// Pack converts mode-specific parameters into ETS serial bits.
func (s ParamSpec) Pack(dst []byte, mode int, values []int16) ([]byte, error) {
	widths, err := s.widths(mode)
	if err != nil {
		return nil, err
	}
	widthBits := BitLen(widths)
	serialBits, err := s.serialBits(mode, widthBits)
	if err != nil {
		return nil, err
	}
	out, err := (Params{Widths: widths, Values: values}).Pack(dst)
	if err != nil {
		return nil, fmt.Errorf("%s mode %d params to serial: %w", s.Codec, mode, err)
	}
	if len(out) > serialBits {
		return nil, fmt.Errorf("%s mode %d serial bit count %d, want %d", s.Codec, mode, len(out), serialBits)
	}
	return padBits(out, serialBits), nil
}

// AppendParams appends ETS serial bits for mode-specific parameters.
func (s ParamSpec) AppendParams(dst []byte, mode int, values []int16) ([]byte, error) {
	out, err := s.Pack(dst[len(dst):], mode, values)
	if err != nil {
		return nil, err
	}
	return append(dst, out...), nil
}

// MarshalParams returns ETS serial bits for mode-specific parameters.
func (s ParamSpec) MarshalParams(mode int, values []int16) ([]byte, error) {
	return s.AppendParams(nil, mode, values)
}

// UnmarshalParams converts ETS serial bits into mode-specific parameters.
func (s ParamSpec) UnmarshalParams(values []int16, mode int, data []byte) ([]int16, error) {
	widths, err := s.widths(mode)
	if err != nil {
		return nil, err
	}
	widthBits := BitLen(widths)
	serialBits, err := s.serialBits(mode, widthBits)
	if err != nil {
		return nil, err
	}
	if len(data) != serialBits {
		return nil, fmt.Errorf("%s mode %d serial bit count %d, want %d", s.Codec, mode, len(data), serialBits)
	}
	if serialBits < widthBits {
		return nil, fmt.Errorf("%s mode %d serial bit count %d below parameter bits %d", s.Codec, mode, serialBits, widthBits)
	}
	out := Params{Widths: widths, Values: values}
	if err := out.UnmarshalBinary(data[:widthBits]); err != nil {
		return nil, fmt.Errorf("%s mode %d serial to params: %w", s.Codec, mode, err)
	}
	return out.Values, nil
}

// WriteParamsTo writes ETS serial bits for mode-specific parameters to w.
func (s ParamSpec) WriteParamsTo(w io.Writer, mode int, values []int16) (int64, error) {
	data, err := s.MarshalParams(mode, values)
	if err != nil {
		return 0, err
	}
	return writeBytes(w, data)
}

// ReadParamsFrom reads ETS serial bits for mode-specific parameters from r.
func (s ParamSpec) ReadParamsFrom(r io.Reader, values []int16, mode int) ([]int16, int64, error) {
	bits, err := s.ParameterSerialBits(mode)
	if err != nil {
		return nil, 0, err
	}
	data := make([]byte, bits)
	n, err := io.ReadFull(r, data)
	if err != nil {
		return nil, int64(n), fmt.Errorf("reading %s mode %d serial parameters: %w", s.Codec, mode, err)
	}
	out, err := s.UnmarshalParams(values, mode, data)
	if err != nil {
		return nil, int64(n), err
	}
	return out, int64(n), nil
}

// Pack packs ETS serial bits into mode-specific speech payload bytes.
func (s SpeechSpec) Pack(dst []byte, mode int, bits []byte) ([]byte, error) {
	bitLen, err := s.bitLen(mode)
	if err != nil {
		return nil, err
	}
	order, err := s.order(mode)
	if err != nil {
		return nil, err
	}
	out, err := (Speech{Order: order, BitLen: bitLen, Serial: bits}).Pack(dst)
	if err != nil {
		return nil, fmt.Errorf("%s mode %d serial to speech: %w", s.Codec, mode, err)
	}
	return out, nil
}

// AppendSpeech appends mode-specific speech payload bytes.
func (s SpeechSpec) AppendSpeech(dst []byte, mode int, bits []byte) ([]byte, error) {
	out, err := s.Pack(dst[len(dst):], mode, bits)
	if err != nil {
		return nil, err
	}
	return append(dst, out...), nil
}

// MarshalSpeech returns mode-specific speech payload bytes.
func (s SpeechSpec) MarshalSpeech(mode int, bits []byte) ([]byte, error) {
	return s.AppendSpeech(nil, mode, bits)
}

// UnmarshalSpeech unpacks mode-specific speech payload bytes into ETS serial bits.
func (s SpeechSpec) UnmarshalSpeech(bits []byte, mode int, data []byte) ([]byte, error) {
	bitLen, err := s.bitLen(mode)
	if err != nil {
		return nil, err
	}
	order, err := s.order(mode)
	if err != nil {
		return nil, err
	}
	out := Speech{Order: order, BitLen: bitLen, Serial: bits}
	if err := out.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("%s mode %d speech to serial: %w", s.Codec, mode, err)
	}
	return out.Serial, nil
}

// WriteSpeechTo writes mode-specific speech payload bytes to w.
func (s SpeechSpec) WriteSpeechTo(w io.Writer, mode int, bits []byte) (int64, error) {
	data, err := s.MarshalSpeech(mode, bits)
	if err != nil {
		return 0, err
	}
	return writeBytes(w, data)
}

// ReadSpeechFrom reads mode-specific speech payload bytes from r.
func (s SpeechSpec) ReadSpeechFrom(r io.Reader, bits []byte, mode int) ([]byte, int64, error) {
	bitLen, err := s.bitLen(mode)
	if err != nil {
		return nil, 0, err
	}
	data := make([]byte, ByteLen(bitLen))
	n, err := io.ReadFull(r, data)
	if err != nil {
		return nil, int64(n), fmt.Errorf("reading %s mode %d speech payload: %w", s.Codec, mode, err)
	}
	out, err := s.UnmarshalSpeech(bits, mode, data)
	if err != nil {
		return nil, int64(n), err
	}
	return out, int64(n), nil
}

func (s ParamSpec) widths(mode int) ([]int, error) {
	if s.Widths == nil {
		return nil, fmt.Errorf("%s parameter widths are not configured", s.Codec)
	}
	return s.Widths(mode)
}

func (s ParamSpec) serialBits(mode, widthBits int) (int, error) {
	if s.SerialBits == nil {
		if widthBits < 0 {
			return 0, fmt.Errorf("%s mode %d serial bit count %d is negative", s.Codec, mode, widthBits)
		}
		return widthBits, nil
	}
	bits, err := s.SerialBits(mode)
	if err != nil {
		return 0, err
	}
	if bits < 0 {
		return 0, fmt.Errorf("%s mode %d serial bit count %d is negative", s.Codec, mode, bits)
	}
	return bits, nil
}

func (s SpeechSpec) order(mode int) ([]int, error) {
	if s.Order == nil {
		return nil, nil
	}
	return s.Order(mode)
}

func (s SpeechSpec) bitLen(mode int) (int, error) {
	if s.BitLen == nil {
		return 0, fmt.Errorf("%s speech bit length is not configured", s.Codec)
	}
	bits, err := s.BitLen(mode)
	if err != nil {
		return 0, err
	}
	if bits < 0 {
		return 0, fmt.Errorf("%s mode %d speech bit count %d is negative", s.Codec, mode, bits)
	}
	return bits, nil
}

func padBits(bits []byte, n int) []byte {
	if len(bits) >= n {
		return bits
	}
	if cap(bits) < n {
		out := make([]byte, n)
		copy(out, bits)
		return out
	}
	old := len(bits)
	bits = bits[:n]
	clear(bits[old:])
	return bits
}
