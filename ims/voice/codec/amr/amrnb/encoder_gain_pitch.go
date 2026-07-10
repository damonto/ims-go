/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This pitch-gain quantizer is ported from enc/src/q_gain_p.cpp.
 */

package amrnb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

type pitchGainQuantization struct {
	index            int16
	gain             int16
	candidates       [3]int16
	candidateIndices [3]int16
}

func quantizePitchGain(mode Mode, gpLimit int16, gain int16) pitchGainQuantization {
	index := int16(0)
	errMin := fxp.Abs16(fxp.Sub16(gain, quaGainPitch[0]))
	for i := int16(1); i < int16(len(quaGainPitch)); i++ {
		if quaGainPitch[i] <= gpLimit {
			err := fxp.Abs16(fxp.Sub16(gain, quaGainPitch[i]))
			if err < errMin {
				errMin = err
				index = i
			}
		}
	}

	out := pitchGainQuantization{
		index: index,
		gain:  quaGainPitch[index],
	}
	if mode == Mode795 {
		ii := index
		if index != 0 {
			if index == int16(len(quaGainPitch)-1) || quaGainPitch[index+1] > gpLimit {
				ii = index - 2
			} else {
				ii = index - 1
			}
		}

		ii = max(ii, 0)

		if int(ii)+2 >= len(quaGainPitch) {
			ii = int16(len(quaGainPitch) - 3)
		}
		for i := range out.candidates {
			out.candidateIndices[i] = ii + int16(i)
			out.candidates[i] = quaGainPitch[ii+int16(i)]
		}
		return out
	}

	if mode == Mode1220 {
		out.gain &^= 3
	}
	return out
}
