/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * The parameter ordering follows pvamrwbdecoder.cpp Serial_parm calls.
 */

package amrwb

import (
	"fmt"
	"io"
	"slices"

	amrbitstream "github.com/damonto/ims-go/ims/voice/codec/amr/bitstream"
)

const amrWBSIDRxTypeBitOffset = 35

// Params carries one AMR-WB decoder parameter vector.
type Params struct {
	Mode   Mode
	Values []int16
}

var paramSpec = amrbitstream.ParamSpec{
	Codec: "AMR-WB",
	Widths: func(mode int) ([]int, error) {
		return parameterBitsForMode(Mode(mode))
	},
	SerialBits: func(mode int) (int, error) {
		return FrameBitLen(Mode(mode))
	},
}

var parameterBits = [...][]int{
	{
		1, 8, 8, 14, 6,
		8, 12, 6,
		5, 12, 6,
		5, 12, 6,
		5, 12, 6,
	},
	{
		1, 8, 8, 6, 7, 7, 5, 5,
		8, 5, 5, 5, 5, 6,
		5, 5, 5, 5, 5, 6,
		8, 5, 5, 5, 5, 6,
		5, 5, 5, 5, 5, 6,
	},
	{
		1, 8, 8, 6, 7, 7, 5, 5,
		9, 1, 9, 9, 9, 9, 7,
		6, 1, 9, 9, 9, 9, 7,
		9, 1, 9, 9, 9, 9, 7,
		6, 1, 9, 9, 9, 9, 7,
	},
	{
		1, 8, 8, 6, 7, 7, 5, 5,
		9, 1, 13, 13, 9, 9, 7,
		6, 1, 13, 13, 9, 9, 7,
		9, 1, 13, 13, 9, 9, 7,
		6, 1, 13, 13, 9, 9, 7,
	},
	{
		1, 8, 8, 6, 7, 7, 5, 5,
		9, 1, 13, 13, 13, 13, 7,
		6, 1, 13, 13, 13, 13, 7,
		9, 1, 13, 13, 13, 13, 7,
		6, 1, 13, 13, 13, 13, 7,
	},
	{
		1, 8, 8, 6, 7, 7, 5, 5,
		9, 1, 2, 2, 2, 2, 14, 14, 14, 14, 7,
		6, 1, 2, 2, 2, 2, 14, 14, 14, 14, 7,
		9, 1, 2, 2, 2, 2, 14, 14, 14, 14, 7,
		6, 1, 2, 2, 2, 2, 14, 14, 14, 14, 7,
	},
	{
		1, 8, 8, 6, 7, 7, 5, 5,
		9, 1, 10, 10, 2, 2, 10, 10, 14, 14, 7,
		6, 1, 10, 10, 2, 2, 10, 10, 14, 14, 7,
		9, 1, 10, 10, 2, 2, 10, 10, 14, 14, 7,
		6, 1, 10, 10, 2, 2, 10, 10, 14, 14, 7,
	},
	{
		1, 8, 8, 6, 7, 7, 5, 5,
		9, 1, 11, 11, 11, 11, 11, 11, 11, 11, 7,
		6, 1, 11, 11, 11, 11, 11, 11, 11, 11, 7,
		9, 1, 11, 11, 11, 11, 11, 11, 11, 11, 7,
		6, 1, 11, 11, 11, 11, 11, 11, 11, 11, 7,
	},
	{
		1, 8, 8, 6, 7, 7, 5, 5,
		9, 1, 11, 11, 11, 11, 11, 11, 11, 11, 7, 4,
		6, 1, 11, 11, 11, 11, 11, 11, 11, 11, 7, 4,
		9, 1, 11, 11, 11, 11, 11, 11, 11, 11, 7, 4,
		6, 1, 11, 11, 11, 11, 11, 11, 11, 11, 7, 4,
	},
	{6, 6, 6, 5, 5, 6, 1},
}

// ParameterBits returns the AMR-WB decoder parameter widths for mode.
func ParameterBits(mode Mode) ([]int, error) {
	widths, err := parameterBitsForMode(mode)
	if err != nil {
		return nil, err
	}
	return slices.Clone(widths), nil
}

func parameterBitsForMode(mode Mode) ([]int, error) {
	if !ValidMode(mode) && mode != ModeSID {
		return nil, fmt.Errorf("AMR-WB parameter mode %d is not supported", mode)
	}
	return parameterBits[mode], nil
}

// ParameterCount returns the number of decoder parameters for mode.
func ParameterCount(mode Mode) (int, error) {
	widths, err := parameterBitsForMode(mode)
	if err != nil {
		return 0, err
	}
	return len(widths), nil
}

// UnmarshalBinary fills p.Values from AMR-WB serial bits.
func (p *Params) UnmarshalBinary(serial []byte) error {
	values, err := paramSpec.UnmarshalParams(p.Values, int(p.Mode), serial)
	if err != nil {
		return err
	}
	p.Values = values
	return nil
}

// Pack converts p to AMR-WB serial bits.
func (p Params) Pack(dst []byte) ([]byte, error) {
	return paramSpec.Pack(dst, int(p.Mode), p.Values)
}

// AppendBinary appends AMR-WB serial bits for p.
func (p Params) AppendBinary(dst []byte) ([]byte, error) {
	return paramSpec.AppendParams(dst, int(p.Mode), p.Values)
}

// MarshalBinary returns AMR-WB serial bits for p.
func (p Params) MarshalBinary() ([]byte, error) {
	return paramSpec.MarshalParams(int(p.Mode), p.Values)
}

// WriteTo writes AMR-WB serial bits for p to w.
func (p Params) WriteTo(w io.Writer) (int64, error) {
	return paramSpec.WriteParamsTo(w, int(p.Mode), p.Values)
}

// ReadParamsFrom reads one AMR-WB serial-bit sequence for p from r.
func (p *Params) ReadParamsFrom(r io.Reader) (int64, error) {
	values, n, err := paramSpec.ReadParamsFrom(r, p.Values, int(p.Mode))
	if err != nil {
		return n, err
	}
	p.Values = values
	return n, nil
}
