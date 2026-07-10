/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * These algorithms are ported from amr_wb/dec/src/wb_syn_filt.cpp,
 * deemphasis_32.cpp, and scale_signal.cpp.
 */

package amrwb

import (
	"errors"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const deemphasisFactor = 22282

type synthesis32Result struct {
	high       [subframeSamples]int16
	low        [subframeSamples]int16
	memoryHigh [lpcOrder]int16
	memoryLow  [lpcOrder]int16
}

type wbSynthesisResult struct {
	signal [subframeSamples16k]int16
	memory [lpcOrder16k]int16
}

func wbSynthesisFilter(a []int16, x []int16, memory []int16) (wbSynthesisResult, error) {
	var out wbSynthesisResult
	order := len(memory)
	if order <= 0 || order > lpcOrder16k || len(a) <= order || len(x) != subframeSamples16k {
		return out, errors.New("run high-band synthesis filter: invalid coefficients, signal, or memory")
	}
	var history [lpcOrder16k + subframeSamples16k]int16
	copy(history[:order], memory)

	shift := fxp.Sub16(fxp.NormS(a[0]), 2)
	a0 := fxp.Shr16(a[0], 1)
	for i := range x {
		sum := fxp.LMult(x[i], a0)
		for j := 1; j <= order; j++ {
			sum = fxp.LMsu(sum, a[j], history[order+i-j])
		}
		sum = fxp.Shl32(sum, fxp.Add16(3, shift))
		sample := fxp.Round(sum)
		history[order+i] = sample
		out.signal[i] = sample
	}

	copy(out.memory[:order], out.signal[subframeSamples16k-order:])
	return out, nil
}

func synthesisFilter32(
	a []int16,
	exc []int16,
	qNew int16,
	memoryHigh [lpcOrder]int16,
	memoryLow [lpcOrder]int16,
) (synthesis32Result, error) {
	var out synthesis32Result
	if len(a) < lpcCoeffCount {
		return out, errors.New("run 32-bit synthesis filter: LPC buffer is too short")
	}
	if len(exc) > subframeSamples {
		return out, errors.New("run 32-bit synthesis filter: excitation exceeds one subframe")
	}
	var high [lpcOrder + subframeSamples]int16
	var low [lpcOrder + subframeSamples]int16
	copy(high[:], memoryHigh[:])
	copy(low[:], memoryLow[:])

	shift := fxp.Sub16(fxp.NormS(a[0]), 2)
	a0 := fxp.Shr16(a[0], fxp.Add16(4, qNew))
	for i := range exc {
		base := lpcOrder + i
		acc := int32(0)
		for j := 1; j <= lpcOrder; j++ {
			acc = fxp.LMsu(acc, low[base-j], a[j])
		}
		acc = fxp.Shr32(acc, 12)
		acc = fxp.LMac(acc, exc[i], a0)
		for j := 1; j <= lpcOrder; j++ {
			acc = fxp.LMsu(acc, high[base-j], a[j])
		}
		acc = fxp.Shl32(acc, fxp.Add16(3, shift))
		hi := fxp.ExtractH(acc)
		high[base] = hi
		acc = fxp.Shr32(acc, 4)
		low[base] = fxp.ExtractL(fxp.LMsu(acc, hi, 2048))
	}
	copy(out.high[:], high[lpcOrder:lpcOrder+len(exc)])
	copy(out.low[:], low[lpcOrder:lpcOrder+len(exc)])
	copy(out.memoryHigh[:], high[len(exc):])
	copy(out.memoryLow[:], low[len(exc):])
	return out, nil
}

type deemphasis32Result struct {
	signal [subframeSamples]int16
	memory int16
}

func deemphasis32(
	xHi [subframeSamples]int16,
	xLo [subframeSamples]int16,
	mu int16,
	memory int16,
) deemphasis32Result {
	var out deemphasis32Result
	fac := fxp.Shr16(mu, 1)
	for i := range out.signal {
		acc := int32(xHi[i]) << 16
		acc = fxp.LMac(acc, xLo[i], 8)
		acc = fxp.Shl32(acc, 3)
		prev := memory
		if i > 0 {
			prev = out.signal[i-1]
		}
		acc = fxp.LMac(acc, prev, fac)
		acc = fxp.Shl32(acc, 1)
		out.signal[i] = fxp.Round(acc)
	}
	out.memory = out.signal[subframeSamples-1]
	return out
}

func scaleSignal(signal []int16, exp int16) {
	for i := range signal {
		signal[i] = fxp.Round(fxp.Shl32(fxp.LDepositH(signal[i]), exp))
	}
}

func scaleSignalExact(signal []int16, exp int16) {
	for i := range signal {
		signal[i] = fxp.Round(fxp.Shl32(int32(signal[i])<<16, exp))
	}
}
