/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This pitch-lag decoding logic is ported from amr_wb/dec/src/pvamrwbdecoder.cpp.
 */

package amrwb

const (
	pitchMin      int16 = 34
	pitchFrac2    int16 = 128
	pitchFrac1_9b int16 = 160
	pitchFrac1_8b int16 = 92
	nBits660      int16 = 132
	nBits885      int16 = 177
	nBits1265     int16 = 253
	nBits1425     int16 = 285
	nBits1585     int16 = 317
	nBits1825     int16 = 365
	nBits1985     int16 = 397
	nBits2305     int16 = 461
	nBits2385     int16 = 477
)

type pitchLagState struct {
	t0Min int16
	t0Max int16
}

func decodePitchLag(index int16, nbits int16, pitFlag int16, state pitchLagState) (int16, int16, pitchLagState) {
	var t0 int16
	var t0Frac int16
	if pitFlag == 0 {
		if nbits <= nBits885 {
			if index < (pitchFrac1_8b-pitchMin)*2 {
				t0 = pitchMin + (index >> 1)
				t0Frac = index - ((t0 - pitchMin) << 1)
				t0Frac <<= 1
			} else {
				t0 = index + pitchFrac1_8b - ((pitchFrac1_8b - pitchMin) * 2)
				t0Frac = 0
			}
		} else if index < (pitchFrac2-pitchMin)*4 {
			t0 = pitchMin + (index >> 2)
			t0Frac = index - ((t0 - pitchMin) << 2)
		} else if index < (((pitchFrac2 - pitchMin) << 2) + ((pitchFrac1_9b - pitchFrac2) << 1)) {
			adjusted := index - ((pitchFrac2 - pitchMin) << 2)
			t0 = pitchFrac2 + (adjusted >> 1)
			t0Frac = adjusted - ((t0 - pitchFrac2) << 1)
			t0Frac <<= 1
		} else {
			t0 = index + pitchFrac1_9b -
				((pitchFrac2 - pitchMin) * 4) -
				((pitchFrac1_9b - pitchFrac2) * 2)
			t0Frac = 0
		}

		state.t0Min = t0 - 8
		state.t0Min = max(state.t0Min, pitchMin)
		state.t0Max = state.t0Min + 15
		if state.t0Max > pitchMax {
			state.t0Max = pitchMax
			state.t0Min = pitchMax - 15
		}
		return t0, t0Frac, state
	}

	if nbits <= nBits885 {
		t0 = state.t0Min + (index >> 1)
		t0Frac = index - ((t0 - state.t0Min) << 1)
		t0Frac <<= 1
	} else {
		t0 = state.t0Min + (index >> 2)
		t0Frac = index - ((t0 - state.t0Min) << 2)
	}
	return t0, t0Frac, state
}
