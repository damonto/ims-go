/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This frame-level LPC flow follows amr_wb/dec/src/pvamrwbdecoder.cpp.
 */

package amrwb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

type decodedLPC struct {
	isf         [lpcOrder]int16
	isp         [lpcOrder]int16
	az          [4 * lpcCoeffCount]int16
	stability   int16
	paramsAfter int
}

func (s *decoderCoreState) decodeLPC(mode Mode, params []int16, badFrame bool) (decodedLPC, error) {
	var out decodedLPC
	if mode < Mode660 || mode > Mode2385 {
		return out, fmt.Errorf("decode LPC: invalid speech mode %d", mode)
	}

	offset := 1
	decoder := isfDecodeState{
		pastResidual: s.pastISFQ[:],
		history:      s.isfBuf[:],
	}
	if mode == Mode660 {
		if len(params) < offset+4 {
			return out, errors.New("decode LPC: 6.60 mode parameters are truncated")
		}
		if badFrame {
			var err error
			out.isf, err = decoder.conceal(s.isfOld[:])
			if err != nil {
				return out, fmt.Errorf("decode LPC: %w", err)
			}
		} else {
			indices := [5]int16{
				params[offset],
				params[offset+1],
				params[offset+2] >> 7,
				params[offset+2] & 0x007f,
				params[offset+3],
			}
			var err error
			out.isf, err = decoder.decode36(indices[:])
			if err != nil {
				return out, fmt.Errorf("decode LPC: %w", err)
			}
		}
		offset += 4
	} else {
		if len(params) < offset+7 {
			return out, errors.New("decode LPC: ISF parameters are truncated")
		}
		if badFrame {
			var err error
			out.isf, err = decoder.conceal(s.isfOld[:])
			if err != nil {
				return out, fmt.Errorf("decode LPC: %w", err)
			}
		} else {
			var err error
			out.isf, err = decoder.decode46(params[offset : offset+7])
			if err != nil {
				return out, fmt.Errorf("decode LPC: %w", err)
			}
		}
		offset += 7
	}
	out.paramsAfter = offset

	var err error
	out.isp, err = isfToISP(out.isf[:])
	if err != nil {
		return out, fmt.Errorf("decode LPC: %w", err)
	}
	if s.firstFrame {
		s.firstFrame = false
		copy(s.ispOld[:], out.isp[:])
	}
	interpolated, err := interpolateISP(s.ispOld[:], out.isp[:])
	if err != nil {
		return out, fmt.Errorf("decode LPC: %w", err)
	}
	out.az = interpolated
	copy(s.ispOld[:], out.isp[:])
	out.stability = isfStability(out.isf[:], s.isfOld[:])
	copy(s.isfOld[:], out.isf[:])
	return out, nil
}

func isfStability(isf []int16, old []int16) int16 {
	var acc int32
	for i := range lpcOrder - 1 {
		delta := fxp.Sub16(isf[i], old[i])
		acc = fxp.Add32(acc, fxp.LMult(delta, delta))
	}
	tmp := fxp.ExtractH(fxp.Shl32(acc, 8))
	tmp = fxp.Mult(tmp, 26214)
	tmp = fxp.Sub16(20480, tmp)
	stability := fxp.Shl16(tmp, 1)
	if stability < 0 {
		return 0
	}
	return stability
}
