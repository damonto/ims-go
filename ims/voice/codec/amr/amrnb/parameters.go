package amrnb

import (
	"fmt"
	"io"
	"slices"

	amrbitstream "github.com/damonto/ims-go/ims/voice/codec/amr/bitstream"
)

const (
	// MaxParameters is the largest AMR-NB analysis parameter vector.
	MaxParameters = 57
	// MaxSerialBits is the largest AMR-NB serial bit vector.
	MaxSerialBits = 244
)

// Params carries one AMR-NB analysis parameter vector.
type Params struct {
	Mode   Mode
	Values []int16
}

var paramSpec = amrbitstream.ParamSpec{
	Codec: "AMR-NB",
	Widths: func(mode int) ([]int, error) {
		return parameterBitsForMode(Mode(mode))
	},
}

var parameterBits = [...][]int{
	Mode475:  {8, 8, 7, 8, 7, 2, 8, 4, 7, 2, 4, 7, 2, 8, 4, 7, 2},
	Mode515:  {8, 8, 7, 8, 7, 2, 6, 4, 7, 2, 6, 4, 7, 2, 6, 4, 7, 2, 6},
	Mode590:  {8, 9, 9, 8, 9, 2, 6, 4, 9, 2, 6, 8, 9, 2, 6, 4, 9, 2, 6},
	Mode670:  {8, 9, 9, 8, 11, 3, 7, 4, 11, 3, 7, 8, 11, 3, 7, 4, 11, 3, 7},
	Mode740:  {8, 9, 9, 8, 13, 4, 7, 5, 13, 4, 7, 8, 13, 4, 7, 5, 13, 4, 7},
	Mode795:  {9, 9, 9, 8, 13, 4, 4, 5, 6, 13, 4, 4, 5, 8, 13, 4, 4, 5, 6, 13, 4, 4, 5},
	Mode1020: {8, 9, 9, 8, 1, 1, 1, 1, 10, 10, 7, 7, 5, 1, 1, 1, 1, 10, 10, 7, 7, 8, 1, 1, 1, 1, 10, 10, 7, 7, 5, 1, 1, 1, 1, 10, 10, 7, 7},
	Mode1220: {7, 8, 9, 8, 6, 9, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 5, 6, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 5, 9, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 5, 6, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 5},
	ModeDTX:  {3, 8, 9, 9, 6},
}

// ParameterBits returns the bit width of each AMR-NB analysis parameter.
func ParameterBits(mode Mode) ([]int, error) {
	bits, err := parameterBitsForMode(mode)
	if err != nil {
		return nil, err
	}
	return slices.Clone(bits), nil
}

func parameterBitsForMode(mode Mode) ([]int, error) {
	if !ValidMode(mode) {
		return nil, fmt.Errorf("AMR-NB parameter mode %d is not supported", mode)
	}
	return parameterBits[mode], nil
}

// ParameterCount returns the number of analysis parameters for mode.
func ParameterCount(mode Mode) (int, error) {
	bits, err := parameterBitsForMode(mode)
	if err != nil {
		return 0, err
	}
	return len(bits), nil
}

// ParameterSerialBits returns the serial bit count represented by the parameter table.
func ParameterSerialBits(mode Mode) (int, error) {
	return paramSpec.ParameterSerialBits(int(mode))
}

// Pack converts p into ETS serial bits.
func (p Params) Pack(dst []byte) ([]byte, error) {
	return paramSpec.Pack(dst, int(p.Mode), p.Values)
}

// AppendBinary appends ETS serial bits for p.
func (p Params) AppendBinary(dst []byte) ([]byte, error) {
	return paramSpec.AppendParams(dst, int(p.Mode), p.Values)
}

// MarshalBinary returns ETS serial bits for p.
func (p Params) MarshalBinary() ([]byte, error) {
	return paramSpec.MarshalParams(int(p.Mode), p.Values)
}

// WriteTo writes ETS serial bits for p to w.
func (p Params) WriteTo(w io.Writer) (int64, error) {
	return paramSpec.WriteParamsTo(w, int(p.Mode), p.Values)
}

// UnmarshalBinary fills p.Values from ETS serial bits.
func (p *Params) UnmarshalBinary(serial []byte) error {
	values, err := paramSpec.UnmarshalParams(p.Values, int(p.Mode), serial)
	if err != nil {
		return err
	}
	p.Values = values
	return nil
}

// ReadFrom reads ETS serial bits for p from r.
func (p *Params) ReadFrom(r io.Reader) (int64, error) {
	values, n, err := paramSpec.ReadParamsFrom(r, p.Values, int(p.Mode))
	if err != nil {
		return n, err
	}
	p.Values = values
	return n, nil
}
