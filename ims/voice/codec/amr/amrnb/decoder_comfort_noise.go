/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_nb/dec/src/b_cn_cod.cpp.
 */

package amrnb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

const cnPulseCount = 10

func pseudoNoise(seed int32, bits int16) (int16, int32) {
	var noise int16
	for range bits {
		sn := int16(0)
		if seed&0x00000001 != 0 {
			sn = 1
		}
		if seed&0x10000000 != 0 {
			sn ^= 1
		}

		noise <<= 1
		noise |= int16(seed & 1)

		seed >>= 1
		if sn&1 != 0 {
			seed |= 0x40000000
		}
	}
	return noise, seed
}

func buildCNParam(seed int16, mode Mode, dst []int16) ([]int16, int16, error) {
	widths, err := parameterBitsForMode(mode)
	if err != nil {
		return nil, seed, err
	}
	if cap(dst) < len(widths) {
		dst = make([]int16, len(widths))
	} else {
		dst = dst[:len(widths)]
	}

	next := fxp.LMult(seed, 31821)
	next >>= 1
	seed = int16(fxp.Add32(next, 13849))

	offset := int(seed) & 0x7f
	for i, width := range widths {
		mask := int16((1 << width) - 1)
		dst[i] = window20040[offset+i] & mask
	}
	return dst, seed, nil
}

func buildCNCode(seed int32, code []int16) ([]int16, int32) {
	if cap(code) < subframeSamples {
		code = make([]int16, subframeSamples)
	} else {
		code = code[:subframeSamples]
		clear(code)
	}

	for k := int16(0); k < cnPulseCount; k++ {
		pos, nextSeed := pseudoNoise(seed, 2)
		seed = nextSeed
		pos = int16(int32(pos) * 10)
		pos = fxp.Add16(pos, k)

		sign, nextSeed := pseudoNoise(seed, 1)
		seed = nextSeed
		if sign > 0 {
			code[pos] = 4096
		} else {
			code[pos] = -4096
		}
	}
	return code, seed
}
