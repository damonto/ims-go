/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * These pitch-lag encoders are ported from enc/src/enc_lag3.cpp
 * and enc/src/enc_lag6.cpp.
 */

package amrnb

func encodeLag3(t0, t0Frac, previousT0, t0Min, t0Max int16, deltaSearch bool, flag4 bool) int16 {
	if !deltaSearch {
		if t0 <= 85 {
			return (t0 << 1) + t0 - 58 + t0Frac
		}
		return t0 + 112
	}

	if !flag4 {
		i := t0 - t0Min
		return i + (i << 1) + 2 + t0Frac
	}

	tmpLag := previousT0
	if tmpLag-t0Min > 5 {
		tmpLag = t0Min + 5
	}
	if t0Max-tmpLag > 4 {
		tmpLag = t0Max - 4
	}

	uplag := t0 + (t0 << 1) + t0Frac
	i := tmpLag - 2
	tmpIndex := i + (i << 1)
	if tmpIndex >= uplag {
		return t0 - tmpLag + 5
	}

	i = tmpLag + 1
	i += i << 1
	if i > uplag {
		return uplag - tmpIndex + 3
	}
	return t0 - tmpLag + 11
}

func encodeLag6(t0, t0Frac, t0Min int16, deltaSearch bool) int16 {
	if !deltaSearch {
		if t0 <= 94 {
			return (t0 << 3) - (t0 << 1) - 105 + t0Frac
		}
		return t0 + 368
	}

	temp := t0 - t0Min
	return (temp << 3) - (temp << 1) + 3 + t0Frac
}
