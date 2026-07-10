/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * These algorithms are ported from amr_nb/dec/src/d2_9pf.cpp,
 * d2_11pf.cpp, d3_14pf.cpp, d4_17pf.cpp, d8_31pf.cpp, and d1035pf.cpp.
 */

package amrnb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

const pulseCount2 = 2

var startPos2i40 = [...]int16{
	0, 2, 0, 3,
	0, 2, 0, 3,
	1, 3, 2, 4,
	1, 4, 1, 4,
}

var dgray = [...]int16{0, 1, 3, 2, 5, 6, 4, 7}

func decode2i40_9bits(subframeNumber, sign, index int16) [subframeSamples]int16 {
	var code [subframeSamples]int16
	track := (index & 64) >> 3
	first := index & 7
	start := (subframeNumber << 1) + track
	pos0 := first*5 + startPos2i40[start]

	index >>= 3
	second := index & 7
	pos1 := second*5 + startPos2i40[start+1]

	code[pos0] = signedPulse(sign & 1)
	sign >>= 1
	code[pos1] = signedPulse(sign & 1)
	return code
}

func decode2i40_11bits(sign, index int16) [subframeSamples]int16 {
	var code [subframeSamples]int16
	track0 := index & 1
	index >>= 1
	grid0 := index & 7
	pos0 := grid0*5 + track0*2 + 1

	index >>= 3
	track1 := index & 3
	index >>= 2
	grid1 := index & 7
	pos1 := grid1 * 5
	if track1 == 3 {
		pos1 += 4
	} else {
		pos1 += track1
	}

	code[pos0] = signedPulse(sign & 1)
	sign >>= 1
	code[pos1] = signedPulse(sign & 1)
	return code
}

func decode3i40_14bits(sign, index int16) [subframeSamples]int16 {
	var code [subframeSamples]int16
	pos0 := (index & 7) * 5

	index >>= 3
	j := index & 1
	index >>= 1
	pos1 := (index&7)*5 + j*2 + 1

	index >>= 3
	j = index & 1
	index >>= 1
	pos2 := (index&7)*5 + j*2 + 2

	code[pos0] = signedPulse(sign & 1)
	sign >>= 1
	code[pos1] = signedPulse(sign & 1)
	sign >>= 1
	code[pos2] = signedPulse(sign & 1)
	return code
}

func decode4i40_17bits(sign, index int16) [subframeSamples]int16 {
	var code [subframeSamples]int16
	pos0 := dgray[index&7] * 5

	index >>= 3
	pos1 := dgray[index&7]*5 + 1

	index >>= 3
	pos2 := dgray[index&7]*5 + 2

	index >>= 3
	j := index & 1
	index >>= 1
	pos3 := dgray[index&7]*5 + 3 + j

	code[pos0] = signedPulse(sign & 1)
	sign >>= 1
	code[pos1] = signedPulse(sign & 1)
	sign >>= 1
	code[pos2] = signedPulse(sign & 1)
	sign >>= 1
	code[pos3] = signedPulse(sign & 1)
	return code
}

func decode8i40_31bits(index []int16) [subframeSamples]int16 {
	var code [subframeSamples]int16
	signs, positions := decompressCode31(index)

	for track := range int16(4) {
		pos1 := (positions[track] << 2) + track
		sign := int16(8191)
		if signs[track] != 0 {
			sign = -8191
		}
		code[pos1] = sign

		pos2 := (positions[track+4] << 2) + track
		if pos2 < pos1 {
			sign = fxp.Neg16(sign)
		}
		code[pos2] = fxp.Add16(code[pos2], sign)
	}
	return code
}

func decode10i40_35bits(index []int16) [subframeSamples]int16 {
	var code [subframeSamples]int16
	for track := range int16(5) {
		tmp := index[track]
		pos1 := dgray[tmp&7]*5 + track
		sign := int16(4096)
		if ((tmp >> 3) & 1) != 0 {
			sign = -4096
		}
		code[pos1] = sign

		pos2 := dgray[index[track+5]&7]*5 + track
		if pos2 < pos1 {
			sign = fxp.Neg16(sign)
		}
		code[pos2] = fxp.Add16(code[pos2], sign)
	}
	return code
}

func decompressCode31(index []int16) ([4]int16, [8]int16) {
	var signs [4]int16
	copy(signs[:], index[:4])
	var positions [8]int16

	msbs := index[4] >> 3
	lsbs := index[4] & 7
	group := decompress10(msbs, lsbs)
	positions[0], positions[4], positions[1] = group[0], group[1], group[2]

	msbs = index[5] >> 3
	lsbs = index[5] & 7
	group = decompress10(msbs, lsbs)
	positions[2], positions[6], positions[5] = group[0], group[1], group[2]

	msbs = index[6] >> 2
	lsbs = index[6] & 3
	msbs0_24 := (msbs*25 + 12) >> 5
	div5 := msbs0_24 / 5
	rem5 := msbs0_24 - div5*5
	if div5&1 == 1 {
		rem5 = 4 - rem5
	}
	positions[3] = rem5*2 + (lsbs & 1)
	positions[7] = div5*2 + (lsbs >> 1)
	return signs, positions
}

func decompress10(msbs, lsbs int16) [3]int16 {
	msbs = min(msbs, 124)

	div25 := msbs / 25
	rem25 := msbs - div25*25
	div5 := rem25 / 5
	rem5 := rem25 - div5*5
	lsbsMod4 := lsbs & 3

	return [3]int16{
		rem5*2 + (lsbsMod4 & 1),
		div5*2 + (lsbsMod4 >> 1),
		div25*2 + (lsbs >> 2),
	}
}

func clearCodeVector(code []int16) {
	clear(code)
}

func signedPulse(signBit int16) int16 {
	return signBit*16383 - 8192
}
