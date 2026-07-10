/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * This pitch-lag index mapping follows amrwbenc/src/voAMRWBEnc.c.
 */

package amrwb

func encodePitchLag(t0 int16, t0Frac int16, nbits int16, pitFlag int16, state pitchLagState) (int16, pitchLagState) {
	var index int16
	if pitFlag == 0 {
		if nbits <= nBits885 {
			if t0 < pitchFrac1_8b {
				index = (t0 << 1) + (t0Frac >> 1) - (pitchMin << 1)
			} else {
				index = (t0 - pitchFrac1_8b) + ((pitchFrac1_8b - pitchMin) * 2)
			}
		} else if t0 < pitchFrac2 {
			index = ((t0 << 2) + t0Frac) - (pitchMin << 2)
		} else if t0 < pitchFrac1_9b {
			index = ((t0 << 1) + (t0Frac >> 1)) - (pitchFrac2 << 1)
			index += (pitchFrac2 - pitchMin) << 2
		} else {
			index = (t0 - pitchFrac1_9b) + ((pitchFrac2 - pitchMin) << 2)
			index += (pitchFrac1_9b - pitchFrac2) << 1
		}

		state.t0Min = t0 - 8
		state.t0Min = max(state.t0Min, pitchMin)
		state.t0Max = state.t0Min + 15
		if state.t0Max > pitchMax {
			state.t0Max = pitchMax
			state.t0Min = pitchMax - 15
		}
		return index, state
	}

	delta := t0 - state.t0Min
	if nbits <= nBits885 {
		index = (delta << 1) + (t0Frac >> 1)
	} else {
		index = (delta << 2) + t0Frac
	}
	return index, state
}
