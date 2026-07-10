/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_wb/dec/src/lagconceal.cpp.
 */

package amrwb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

const (
	oneThird     int16 = 10923
	oneOverLag5  int16 = 6554
	lagHistCount       = 5
)

func initialLagHistory() [lagHistCount]int16 {
	var lagHist [lagHistCount]int16
	for i := range lagHist {
		lagHist[i] = initialOldT0
	}
	return lagHist
}

func concealLag(
	gainHist [lagHistCount]int16,
	lagHist [lagHistCount]int16,
	t0 int16,
	oldT0 int16,
	seed int16,
	unusableFrame bool,
) (int16, int16) {
	lastGain := gainHist[4]
	secLastGain := gainHist[3]
	lastLag := lagHist[0]
	minLag, maxLag := minMaxLag(lagHist)
	minGain := gainHist[0]
	for i := 1; i < lagHistCount; i++ {
		minGain = min(minGain, gainHist[i])
	}
	lagDiff := fxp.Sub16(maxLag, minLag)

	if unusableFrame {
		if minGain > 8192 && lagDiff < 10 {
			t0 = oldT0
		} else if lastGain > 8192 && secLastGain > 8192 {
			t0 = lagHist[0]
		} else {
			t0, seed = concealedLagFromSortedHistory(lagHist, seed)
		}
		return clampLag(t0, minLag, maxLag), seed
	}

	meanLag := int16(0)
	for i := range lagHistCount {
		meanLag = fxp.Add16(meanLag, lagHist[i])
	}
	meanLag = fxp.Mult(meanLag, oneOverLag5)

	tmp := t0 - maxLag
	tmp2 := t0 - lastLag
	switch {
	case lagDiff < 10 && t0 > minLag-5 && tmp < 5:
		return t0, seed
	case lastGain > 8192 && secLastGain > 8192 && tmp2+10 > 0 && tmp2 < 10:
		return t0, seed
	case minGain < 6554 && lastGain == minGain && t0 > minLag && t0 < maxLag:
		return t0, seed
	case lagDiff < 70 && t0 > minLag && t0 < maxLag:
		return t0, seed
	case t0 > meanLag && t0 < maxLag:
		return t0, seed
	}

	if minGain > 8192 && lagDiff < 10 {
		t0 = lagHist[0]
	} else if lastGain > 8192 && secLastGain > 8192 {
		t0 = lagHist[0]
	} else {
		t0, seed = concealedLagFromSortedHistory(lagHist, seed)
	}
	return clampLag(t0, minLag, maxLag), seed
}

func concealedLagFromSortedHistory(lagHist [lagHistCount]int16, seed int16) (int16, int16) {
	sorted := lagHist
	insertionSort16(sorted[:])
	diff := fxp.Sub16(sorted[4], sorted[2])
	diff = min(diff, 40)

	seed = nextNoise(seed)
	random := seed
	delta := fxp.Mult(diff>>1, random)
	sum := fxp.Add16(fxp.Add16(sorted[2], sorted[3]), sorted[4])
	return fxp.Add16(fxp.Mult(sum, oneThird), delta), seed
}

func minMaxLag(lagHist [lagHistCount]int16) (int16, int16) {
	minLag := lagHist[0]
	maxLag := lagHist[0]
	for i := 1; i < lagHistCount; i++ {
		minLag = min(minLag, lagHist[i])
		maxLag = max(maxLag, lagHist[i])
	}
	return minLag, maxLag
}

func clampLag(lag int16, minLag int16, maxLag int16) int16 {
	if lag > maxLag {
		return maxLag
	}
	if lag < minLag {
		return minLag
	}
	return lag
}

func insertionSort16(values []int16) {
	for i := range values {
		insert16(values, i, values[i])
	}
}

func insert16(values []int16, n int, x int16) {
	i := n - 1
	for ; i >= 0; i-- {
		if x < values[i] {
			values[i+1] = values[i]
			continue
		}
		break
	}
	values[i+1] = x
}
