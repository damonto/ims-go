/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_nb/dec/src/dec_lag3.cpp and dec_lag6.cpp.
 */

package amrnb

func decodeLag3(index, t0Min, t0Max, subframe, previousT0 int16, flag4 bool) (t0, t0Frac int16) {
	if subframe == 0 {
		if index < 197 {
			tmp := int16((int32(index+2) * 10923) >> 15)
			i := tmp + 19
			t0 = i
			i = i + (i << 1)
			t0Frac = index - i + 58
			return t0, t0Frac
		}
		return index - 112, 0
	}

	if !flag4 {
		i := int16((int32(index+2) * 10923) >> 15)
		i--
		t0 = i + t0Min
		i = i + (i << 1)
		t0Frac = index - 2 - i
		return t0, t0Frac
	}

	tmpLag := previousT0
	if tmpLag-t0Min > 5 {
		tmpLag = t0Min + 5
	}
	if t0Max-tmpLag > 4 {
		tmpLag = t0Max - 4
	}

	if index < 4 {
		t0 = tmpLag - 5 + index
		return t0, 0
	}
	if index < 12 {
		i := int16((int32(index-5) * 10923) >> 15)
		i--
		t0 = i + tmpLag
		t0Frac = index - 9 - (i + (i << 1))
		return t0, t0Frac
	}

	t0 = index - 12 + tmpLag + 1
	return t0, 0
}

func decodeLag6(index, pitchMin, pitchMax, subframe int16, previousT0 int16) (t0, t0Frac int16) {
	if subframe == 0 {
		if index < 463 {
			i := int16((int32(index+5) * 5462) >> 15)
			i += 17
			t0 = i
			i = i + (i << 1)
			i <<= 1
			t0Frac = index - i + 105
			return t0, t0Frac
		}
		return index - 368, 0
	}

	t0Min := previousT0 - 5

	t0Min = max(t0Min, pitchMin)

	t0Max := t0Min + 9
	if t0Max > pitchMax {
		t0Max = pitchMax
		t0Min = t0Max - 9
	}

	i := int16((int32(index+5) * 5462) >> 15)
	i--
	t0 = i + t0Min
	i = i + (i << 1)
	i <<= 1
	t0Frac = index - 3 - i
	return t0, t0Frac
}
