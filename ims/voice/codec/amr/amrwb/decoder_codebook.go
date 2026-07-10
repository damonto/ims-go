/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * These algorithms are ported from amr_wb/dec/src/dec_alg_codebook.cpp,
 * dec_acelp_2p_in_64.cpp, and dec_acelp_4p_in_64.cpp.
 */

package amrwb

import (
	"errors"
	"fmt"
)

const (
	codePulseAmplitude = 512
	codeTrackCount     = 4
	codeTrackPositions = 16
)

type pulsePositions [6]int16

func decodeAcelp2PIn64(index int16) ([subframeSamples]int16, error) {
	var code [subframeSamples]int16
	if index < 0 || index >= 1<<12 {
		return code, fmt.Errorf("decode 2-pulse ACELP codebook: index %d is outside 12 bits", index)
	}

	pos := int((index >> 5) & 0x003e)
	if ((index >> 6) & 32) == 0 {
		code[pos] = codePulseAmplitude
	} else {
		code[pos] = -codePulseAmplitude
	}

	pos = int((index&0x001f)<<1) + 1
	if (index & 32) == 0 {
		code[pos] = codePulseAmplitude
	} else {
		code[pos] = -codePulseAmplitude
	}
	return code, nil
}

func decodeAcelp4PIn64(index []int16, nbits int16) ([subframeSamples]int16, error) {
	var code [subframeSamples]int16
	widths, err := acelpIndexWidths(nbits)
	if err != nil {
		return code, err
	}
	if len(index) < len(widths) {
		return code, errors.New("decode 4-track ACELP codebook: index buffer is too short")
	}
	for i, width := range widths {
		if index[i] < 0 || int(index[i]) >= 1<<width {
			return code, fmt.Errorf("decode 4-track ACELP codebook: index %d value %d is outside %d bits", i, index[i], width)
		}
	}

	switch nbits {
	case 20:
		for k := range codeTrackCount {
			pos := decode1pN1(int32(index[k]), 4, 0)
			code = addPulses(code, pos, 1, int16(k))
		}
	case 36:
		for k := range codeTrackCount {
			pos := decode2p2N1(int32(index[k]), 4, 0)
			code = addPulses(code, pos, 2, int16(k))
		}
	case 44:
		for k := range codeTrackCount - 2 {
			pos := decode3p3N1(int32(index[k]), 4, 0)
			code = addPulses(code, pos, 3, int16(k))
		}
		for k := 2; k < codeTrackCount; k++ {
			pos := decode2p2N1(int32(index[k]), 4, 0)
			code = addPulses(code, pos, 2, int16(k))
		}
	case 52:
		for k := range codeTrackCount {
			pos := decode3p3N1(int32(index[k]), 4, 0)
			code = addPulses(code, pos, 3, int16(k))
		}
	case 64:
		for k := range codeTrackCount {
			combined := (int32(index[k]) << 14) + int32(index[k+codeTrackCount])
			pos := decode4p4N(combined, 4, 0)
			code = addPulses(code, pos, 4, int16(k))
		}
	case 72:
		for k := range codeTrackCount - 2 {
			combined := (int32(index[k]) << 10) + int32(index[k+codeTrackCount])
			pos := decode5p5N(combined, 4, 0)
			code = addPulses(code, pos, 5, int16(k))
		}
		for k := 2; k < codeTrackCount; k++ {
			combined := (int32(index[k]) << 14) + int32(index[k+codeTrackCount])
			pos := decode4p4N(combined, 4, 0)
			code = addPulses(code, pos, 4, int16(k))
		}
	case 88:
		for k := range codeTrackCount {
			combined := (int32(index[k]) << 11) + int32(index[k+codeTrackCount])
			pos := decode6p6N2(combined, 4, 0)
			code = addPulses(code, pos, 6, int16(k))
		}
	}
	return code, nil
}

func acelpIndexWidths(nbits int16) ([]int, error) {
	switch nbits {
	case 20:
		return []int{5, 5, 5, 5}, nil
	case 36:
		return []int{9, 9, 9, 9}, nil
	case 44:
		return []int{13, 13, 9, 9}, nil
	case 52:
		return []int{13, 13, 13, 13}, nil
	case 64:
		return []int{2, 2, 2, 2, 14, 14, 14, 14}, nil
	case 72:
		return []int{10, 10, 2, 2, 10, 10, 14, 14}, nil
	case 88:
		return []int{11, 11, 11, 11, 11, 11, 11, 11}, nil
	default:
		return nil, fmt.Errorf("decode 4-track ACELP codebook: unsupported width %d", nbits)
	}
}

func addPulses(code [subframeSamples]int16, pos pulsePositions, count int16, track int16) [subframeSamples]int16 {
	for k := range count {
		i := ((pos[k] & (codeTrackPositions - 1)) << 2) + track
		if (pos[k] & codeTrackPositions) == 0 {
			code[i] += codePulseAmplitude
		} else {
			code[i] -= codePulseAmplitude
		}
	}
	return code
}

func decode1pN1(index int32, n int16, offset int16) pulsePositions {
	var pos pulsePositions
	mask := int32((1 << n) - 1)
	pos1 := int16(index&mask) + offset
	if ((index >> n) & 1) == 1 {
		pos1 += codeTrackPositions
	}
	pos[0] = pos1
	return pos
}

func decode2p2N1(index int32, n int16, offset int16) pulsePositions {
	var pos pulsePositions
	mask := int32((1 << n) - 1)
	pos1 := int16((index>>n)&mask) + offset
	pos2 := int16(index&mask) + offset
	sign := (index >> (n << 1)) & 1

	if pos2 < pos1 {
		if sign == 1 {
			pos1 += codeTrackPositions
		} else {
			pos2 += codeTrackPositions
		}
	} else if sign == 1 {
		pos1 += codeTrackPositions
		pos2 += codeTrackPositions
	}
	pos[0] = pos1
	pos[1] = pos2
	return pos
}

func decode3p3N1(index int32, n int16, offset int16) pulsePositions {
	mask := int32((1 << ((2 * n) - 1)) - 1)
	idx := index & mask
	j := offset
	if ((index >> ((n << 1) - 1)) & 1) != 0 {
		j += 1 << (n - 1)
	}
	pos := decode2p2N1(idx, n-1, j)

	mask = int32((1 << (n + 1)) - 1)
	idx = (index >> (n << 1)) & mask
	last := decode1pN1(idx, n, offset)
	pos[2] = last[0]
	return pos
}

func decode4p4N1(index int32, n int16, offset int16) pulsePositions {
	mask := int32((1 << ((n << 1) - 1)) - 1)
	idx := index & mask
	j := offset
	if ((index >> ((n << 1) - 1)) & 1) != 0 {
		j += 1 << (n - 1)
	}
	pos := decode2p2N1(idx, n-1, j)

	mask = int32((1 << ((n << 1) + 1)) - 1)
	idx = (index >> (n << 1)) & mask
	last := decode2p2N1(idx, n, offset)
	copy(pos[2:4], last[:2])
	return pos
}

func decode4p4N(index int32, n int16, offset int16) pulsePositions {
	var pos pulsePositions
	n1 := n - 1
	j := offset + (1 << n1)
	switch (index >> ((n << 2) - 2)) & 3 {
	case 0:
		if ((index >> ((n1 << 2) + 1)) & 1) != 0 {
			pos = decode4p4N1(index, n1, j)
		} else {
			pos = decode4p4N1(index, n1, offset)
		}
	case 1:
		first := decode1pN1(index>>((3*n1)+1), n1, offset)
		last := decode3p3N1(index, n1, j)
		pos[0] = first[0]
		copy(pos[1:4], last[:3])
	case 2:
		first := decode2p2N1(index>>((n1<<1)+1), n1, offset)
		last := decode2p2N1(index, n1, j)
		copy(pos[:2], first[:2])
		copy(pos[2:4], last[:2])
	case 3:
		first := decode3p3N1(index>>(n1+1), n1, offset)
		last := decode1pN1(index, n1, j)
		copy(pos[:3], first[:3])
		pos[3] = last[0]
	}
	return pos
}

func decode5p5N(index int32, n int16, offset int16) pulsePositions {
	n1 := n - 1
	j := offset + (1 << n1)
	idx := index >> ((n << 1) + 1)
	var pos pulsePositions
	if ((index >> ((5 * n) - 1)) & 1) != 0 {
		pos = decode3p3N1(idx, n1, j)
	} else {
		pos = decode3p3N1(idx, n1, offset)
	}
	last := decode2p2N1(index, n, offset)
	copy(pos[3:5], last[:2])
	return pos
}

func decode6p6N2(index int32, n int16, offset int16) pulsePositions {
	n1 := n - 1
	j := offset + (1 << n1)
	offsetA := j
	offsetB := j
	if ((index >> ((6 * n) - 5)) & 1) == 0 {
		offsetA = offset
	} else {
		offsetB = offset
	}

	var pos pulsePositions
	switch (index >> ((6 * n) - 4)) & 3 {
	case 0:
		pos = decode5p5N(index>>n, n1, offsetA)
		last := decode1pN1(index, n1, offsetA)
		pos[5] = last[0]
	case 1:
		pos = decode5p5N(index>>n, n1, offsetA)
		last := decode1pN1(index, n1, offsetB)
		pos[5] = last[0]
	case 2:
		pos = decode4p4N(index>>((2*n1)+1), n1, offsetA)
		last := decode2p2N1(index, n1, offsetB)
		copy(pos[4:6], last[:2])
	case 3:
		first := decode3p3N1(index>>((3*n1)+1), n1, offset)
		last := decode3p3N1(index, n1, j)
		copy(pos[:3], first[:3])
		copy(pos[3:6], last[:3])
	}
	return pos
}
