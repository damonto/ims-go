/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This file ports the AMR-NB decoder adaptive post-filter from
 * amr_nb/dec/src/pstfilt.cpp, preemph.cpp, and agc.cpp.
 */

package amrnb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const (
	postFilterImpulseLen = 22
	postFilterMu         = 26214
	postFilterAGCFactor  = 29491
)

var postFilterGamma3MR122 = [...]int16{
	22938, 16057, 11240, 7868, 5508, 3856, 2699, 1889, 1322, 925,
}

var postFilterGamma3 = [...]int16{
	18022, 9912, 5451, 2998, 1649, 907, 499, 274, 151, 83,
}

var postFilterGamma4MR122 = [...]int16{
	24576, 18432, 13824, 10368, 7776, 5832, 4374, 3281, 2461, 1846,
}

var postFilterGamma4 = [...]int16{
	22938, 16057, 11240, 7868, 5508, 3856, 2699, 1889, 1322, 925,
}

type postFilterState struct {
	residual2  [subframeSamples]int16
	memSyn     [lpcOrder]int16
	preemphMem int16
	pastGain   int16
	synthBuf   [lpcOrder + FrameSamples]int16
}

func (s *postFilterState) reset() {
	clear(s.residual2[:])
	clear(s.memSyn[:])
	s.preemphMem = 0
	s.pastGain = 4096
	clear(s.synthBuf[:])
}

func (s *postFilterState) process(mode Mode, speech []int16, az [azFrameCount]int16) ([FrameSamples]int16, error) {
	var filtered [FrameSamples]int16
	if mode < Mode475 || mode > ModeDTX {
		return filtered, fmt.Errorf("post-filtering AMR-NB speech: invalid mode %d", mode)
	}
	if len(speech) < FrameSamples {
		return filtered, fmt.Errorf(
			"post-filtering AMR-NB speech: sample count %d, want at least %d",
			len(speech),
			FrameSamples,
		)
	}
	copy(s.synthBuf[lpcOrder:], speech[:FrameSamples])
	copy(filtered[:], speech[:FrameSamples])

	for subframe := 0; subframe < FrameSamples; subframe += subframeSamples {
		azSubframe := az[(subframe/subframeSamples)*lpcCoeffCount:]
		var ap3, ap4 [lpcCoeffCount]int16
		var err error
		if mode == Mode1220 || mode == Mode1020 {
			ap3, err = weightLPC(azSubframe, postFilterGamma3MR122[:])
			if err != nil {
				return [FrameSamples]int16{}, err
			}
			ap4, err = weightLPC(azSubframe, postFilterGamma4MR122[:])
		} else {
			ap3, err = weightLPC(azSubframe, postFilterGamma3[:])
			if err != nil {
				return [FrameSamples]int16{}, err
			}
			ap4, err = weightLPC(azSubframe, postFilterGamma4[:])
		}
		if err != nil {
			return [FrameSamples]int16{}, err
		}

		residual(ap3[:], s.synthBuf[subframe:], s.residual2[:])
		tilt := postFilterTilt(ap3[:], ap4[:])
		s.preemphMem = preemphasis(s.residual2[:], tilt, s.preemphMem)
		out := filtered[subframe : subframe+subframeSamples]
		s.memSyn = synthesisFilter(ap4[:], s.residual2[:], out, s.memSyn[:])
		s.agc(
			s.synthBuf[lpcOrder+subframe:lpcOrder+subframe+subframeSamples],
			out,
			postFilterAGCFactor,
		)
	}

	copy(s.synthBuf[:lpcOrder], s.synthBuf[FrameSamples:FrameSamples+lpcOrder])
	return filtered, nil
}

func weightLPC(a []int16, factor []int16) ([lpcCoeffCount]int16, error) {
	var out [lpcCoeffCount]int16
	if len(a) < lpcCoeffCount || len(factor) < lpcOrder {
		return out, fmt.Errorf(
			"weighting AMR-NB LPC: coefficient/factor counts %d/%d, want at least %d/%d",
			len(a),
			len(factor),
			lpcCoeffCount,
			lpcOrder,
		)
	}
	out[0] = a[0]
	for i := 1; i <= lpcOrder; i++ {
		out[i] = fxp.MultRound(a[i], factor[i-1])
	}
	return out, nil
}

func postFilterTilt(ap3 []int16, ap4 []int16) int16 {
	var h [postFilterImpulseLen]int16
	copy(h[:], ap3)
	synthesisFilter(ap4, h[:], h[:], h[lpcOrder+1:])

	corr0 := int32(0)
	for _, sample := range h {
		corr0 = fxp.Add32(corr0, fxp.LMult(sample, sample))
	}
	temp1 := fxp.ExtractH(corr0)

	corr1 := int32(0)
	for i := range postFilterImpulseLen - 1 {
		corr1 = fxp.Add32(corr1, fxp.LMult(h[i], h[i+1]))
	}
	temp2 := fxp.ExtractH(corr1)
	if temp2 <= 0 || temp1 <= 0 {
		return 0
	}
	return fxp.DivS(fxp.Mult(temp2, postFilterMu), temp1)
}

func preemphasis(signal []int16, g int16, mem int16) int16 {
	if len(signal) == 0 {
		return mem
	}
	last := signal[len(signal)-1]
	for i := len(signal) - 1; i > 0; i-- {
		signal[i] = fxp.Sub16(signal[i], fxp.Mult(g, signal[i-1]))
	}
	signal[0] = fxp.Sub16(signal[0], fxp.Mult(g, mem))
	return last
}

func (s *postFilterState) agc(input []int16, output []int16, factor int16) {
	energyOut := agcEnergyNew(output)
	if energyOut == 0 {
		s.pastGain = 0
		return
	}
	exp := fxp.NormL(energyOut) - 1
	gainOut := fxp.Round(fxp.Shl32(energyOut, exp))

	energyIn := agcEnergyNew(input)
	var g0 int16
	if energyIn != 0 {
		inExp := fxp.NormL(energyIn)
		gainIn := fxp.Round(fxp.Shl32(energyIn, inExp))
		exp -= inExp

		scale := int32(fxp.DivS(gainOut, gainIn))
		scale = fxp.Shl32(scale, 7)
		scale = fxp.Shr32(scale, exp)
		root := invSqrt(scale)
		rootGain := fxp.Round(fxp.Shl32(root, 9))
		g0 = fxp.Mult(rootGain, fxp.Sub16(fxp.Max16, factor))
	}

	gain := s.pastGain
	for i := range output {
		gain = fxp.Mult(gain, factor)
		gain = fxp.Add16(gain, g0)
		output[i] = fxp.ExtractH(fxp.Shl32(fxp.LMult(output[i], gain), 3))
	}
	s.pastGain = gain
}
