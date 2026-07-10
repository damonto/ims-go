/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_nb/common/src/pred_lt.cpp.
 */

package amrnb

import "fmt"

const (
	upSampleMax       = 6
	interpolationTaps = interpolationLen - 1
)

var inter6PredLT = [...]int16{
	29443,
	28346, 25207, 20449, 14701, 8693, 3143,
	-1352, -4402, -5865, -5850, -4673, -2783,
	-672, 1211, 2536, 3130, 2991, 2259,
	1170, 0, -1001, -1652, -1868, -1666,
	-1147, -464, 218, 756, 1060, 1099,
	904, 550, 135, -245, -514, -634,
	-602, -451, -231, 0, 191, 308,
	340, 296, 198, 78, -36, -120,
	-163, -165, -132, -79, -19, 34,
	73, 91, 89, 70, 38, 0,
}

func predictAdaptiveCodebook(exc []int16, offset int, t0, frac int16, samples int, useThirdResolution bool) error {
	if samples < 0 {
		return fmt.Errorf("AMR-NB adaptive codebook sample count %d is negative", samples)
	}
	if offset < 0 || offset+samples > len(exc) {
		return fmt.Errorf("AMR-NB adaptive codebook offset %d samples %d outside excitation length %d", offset, samples, len(exc))
	}

	base := offset - int(t0)
	phase := -frac
	if useThirdResolution {
		phase <<= 1
	}
	if phase < 0 {
		phase += upSampleMax
		base--
	}
	if phase < 0 || phase > upSampleMax {
		return fmt.Errorf("AMR-NB adaptive codebook fraction phase %d outside 0..%d", phase, upSampleMax)
	}
	if base-interpolationTaps+1 < 0 || base+samples+interpolationTaps >= len(exc) {
		return fmt.Errorf("AMR-NB adaptive codebook history base %d outside excitation length %d", base, len(exc))
	}
	for j := range samples {
		x1 := base + j
		x2 := x1 + 1
		c1 := int(phase)
		c2 := upSampleMax - int(phase)
		sum := int32(0x4000)
		for i := range interpolationTaps {
			k := i * upSampleMax
			sum += int32(exc[x1-i]) * int32(inter6PredLT[c1+k])
			sum += int32(exc[x2+i]) * int32(inter6PredLT[c2+k])
		}
		exc[offset+j] = int16(sum >> 15)
	}
	return nil
}
