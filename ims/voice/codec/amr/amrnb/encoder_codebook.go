/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * These AMR-NB fixed-codebook encoder primitives are ported from
 * enc/src/c2_9pf.cpp, enc/src/cor_h_x.cpp, enc/src/cor_h.cpp, and
 * enc/src/set_sign.cpp.
 */

package amrnb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

const (
	codebookTracks = 5
	codebookStep   = 5
	mr102Tracks    = 4
	mr102Step      = 4
	pulseCount8    = 8
	pulseCount10   = 10
)

var trackTable2i40 = [...]int16{
	0, 1, 0, 1, -1,
	0, -1, 1, 0, 1,
	0, 1, 0, -1, 1,
	0, 1, -1, 0, 1,
}

var startPos2i40_11First = [...]int16{1, 3}
var startPos2i40_11Second = [...]int16{0, 1, 2, 4}
var gray = [...]int16{0, 1, 3, 2, 6, 4, 5, 7}

type code2i40Result struct {
	index       int16
	sign        int16
	codeNoSharp [subframeSamples]int16
}

type code3i40Result struct {
	index int16
	sign  int16
}

type code4i40Result struct {
	index int16
	sign  int16
}

type code8i40Result struct {
	params [7]int16
}

type code10i40Result struct {
	params [10]int16
}

type lowRateSearch struct {
	dn   [subframeSamples]int16
	dn2  [subframeSamples]int16
	sign [subframeSamples]int16
	rr   [subframeSamples][subframeSamples]int16
}

type highRateSearch struct {
	dn     [subframeSamples]int16
	sign   [subframeSamples]int16
	posMax [codebookTracks]int16
	ipos   [pulseCount10]int16
	rr     [subframeSamples][subframeSamples]int16
}

func code2i40_9bits(
	subframeNumber int16,
	x []int16,
	h []int16,
	t0 int16,
	pitchSharp int16,
	code []int16,
	y []int16,
) code2i40Result {
	addPitchSharpness(h, t0, pitchSharp)
	search := lowRateCodebookSearch(h, x, 8)

	codvec := search2i40(subframeNumber, search.dn[:], &search.rr)
	result := buildCode2i40(subframeNumber, codvec, search.sign[:], code, h, y)
	copy(result.codeNoSharp[:], code)
	addPitchSharpness(code, t0, pitchSharp)
	return result
}

func code2i40_11bits(
	x []int16,
	h []int16,
	t0 int16,
	pitchSharp int16,
	code []int16,
	y []int16,
) code2i40Result {
	addPitchSharpness(h, t0, pitchSharp)
	search := lowRateCodebookSearch(h, x, 8)

	codvec := search2i40_11(search.dn[:], &search.rr)
	result := buildCode2i40_11(codvec, search.sign[:], code, h, y)
	copy(result.codeNoSharp[:], code)
	addPitchSharpness(code, t0, pitchSharp)
	return result
}

func code3i40_14bits(
	x []int16,
	h []int16,
	t0 int16,
	pitchSharp int16,
	code []int16,
	y []int16,
) code3i40Result {
	addPitchSharpness(h, t0, pitchSharp)
	search := lowRateCodebookSearch(h, x, 6)

	codvec := search3i40(search.dn[:], search.dn2[:], &search.rr)
	result := buildCode3i40(codvec, search.sign[:], code, h, y)
	addPitchSharpness(code, t0, pitchSharp)
	return result
}

func code4i40_17bits(
	x []int16,
	h []int16,
	t0 int16,
	pitchSharp int16,
	code []int16,
	y []int16,
) code4i40Result {
	addPitchSharpness(h, t0, pitchSharp)
	search := lowRateCodebookSearch(h, x, 4)

	codvec := search4i40(search.dn[:], search.dn2[:], &search.rr)
	result := buildCode4i40(codvec, search.sign[:], code, h, y)
	addPitchSharpness(code, t0, pitchSharp)
	return result
}

func code8i40_31bits(
	x []int16,
	cn []int16,
	h []int16,
	code []int16,
	y []int16,
) code8i40Result {
	search := mr102CodebookSearch(x, cn, h)
	codvec := search8i40(search.dn[:], &search.rr, search.ipos[:pulseCount8], search.posMax[:mr102Tracks])
	return buildCode8i40(codvec, search.sign[:], code, h, y)
}

func code10i40_35bits(
	x []int16,
	cn []int16,
	h []int16,
	code []int16,
	y []int16,
) code10i40Result {
	search := mr122CodebookSearch(x, cn, h)
	codvec := search10i40(search.dn[:], &search.rr, search.ipos[:], search.posMax[:])
	return buildCode10i40(codvec, search.sign[:], code, h, y)
}

func addPitchSharpness(samples []int16, t0 int16, pitchSharp int16) {
	if t0 >= subframeSamples {
		return
	}
	sharp := fxp.Shl16(pitchSharp, 1)
	for i := int(t0); i < len(samples); i++ {
		samples[i] = fxp.Add16(samples[i], fxp.Mult(samples[i-int(t0)], sharp))
	}
}

func lowRateCodebookSearch(h []int16, x []int16, signKeep int16) lowRateSearch {
	var out lowRateSearch
	corHX(h, x, out.dn[:], 1)
	setSign(out.dn[:], out.sign[:], out.dn2[:], signKeep)
	out.rr = impulseResponseCorrelations(h, out.sign[:])
	return out
}

func mr102CodebookSearch(x []int16, cn []int16, h []int16) highRateSearch {
	var out highRateSearch
	corHXTracks(h, x, out.dn[:], 2, mr102Tracks, mr102Step)
	setSign12k2(out.dn[:], cn, out.sign[:], out.posMax[:mr102Tracks], out.ipos[:pulseCount8], mr102Tracks, mr102Step)
	out.rr = impulseResponseCorrelations(h, out.sign[:])
	return out
}

func mr122CodebookSearch(x []int16, cn []int16, h []int16) highRateSearch {
	var out highRateSearch
	corHX(h, x, out.dn[:], 2)
	setSign12k2(out.dn[:], cn, out.sign[:], out.posMax[:], out.ipos[:], codebookTracks, codebookStep)
	out.rr = impulseResponseCorrelations(h, out.sign[:])
	return out
}

func corHX(h []int16, x []int16, dn []int16, sf int16) {
	corHXTracks(h, x, dn, sf, codebookTracks, codebookStep)
}

func corHXTracks(h []int16, x []int16, dn []int16, sf int16, tracks int, step int) {
	corr := impulseTargetCorrelation(h, x, tracks, step)
	writeScaledCorrelation(corr, dn, sf)
}

type targetCorrelation struct {
	values [subframeSamples]int32
	energy int32
}

func impulseTargetCorrelation(h []int16, x []int16, tracks int, step int) targetCorrelation {
	var out targetCorrelation
	out.energy = 5
	for track := range tracks {
		maxCorr := int32(0)
		for i := track; i < subframeSamples; i += step {
			sum := targetCorrelationAt(h, x, i)
			out.values[i] = sum
			maxCorr = max(maxCorr, fxp.Abs32(sum))
		}
		out.energy = fxp.Add32(out.energy, fxp.Shr32(maxCorr, 1))
	}
	return out
}

func targetCorrelationAt(h []int16, x []int16, pos int) int32 {
	sum := int32(0)
	for j := pos; j < subframeSamples; j++ {
		hIndex := j - pos
		sum = fxp.LMac(sum, x[j], h[hIndex])
	}
	return sum
}

func writeScaledCorrelation(corr targetCorrelation, dn []int16, sf int16) {
	shift := fxp.Sub16(fxp.NormL(corr.energy), sf)
	for i := range subframeSamples {
		dn[i] = fxp.Round(fxp.Shl32(corr.values[i], shift))
	}
}

func setSign12k2(
	dn []int16,
	cn []int16,
	sign []int16,
	posMax []int16,
	ipos []int16,
	tracks int,
	step int,
) {
	weights := normalizedCorrelationWeights(cn, dn)
	en := signedCorrelation(dn, cn, sign, weights)
	startTrack := trackMaxPositions(en, posMax, tracks, step)
	initialPulseTracks(ipos, tracks, startTrack)
}

type correlationWeights struct {
	cn int16
	dn int16
}

func normalizedCorrelationWeights(cn []int16, dn []int16) correlationWeights {
	cnEnergy := int32(256)
	dnEnergy := int32(256)
	for i := range subframeSamples {
		cnEnergy = fxp.LMac(cnEnergy, cn[i], cn[i])
		dnEnergy = fxp.LMac(dnEnergy, dn[i], dn[i])
	}

	return correlationWeights{
		cn: int16(fxp.Shl32(invSqrt(cnEnergy), 5) >> 16),
		dn: int16(fxp.Shl32(invSqrt(dnEnergy), 5) >> 16),
	}
}

func signedCorrelation(dn []int16, cn []int16, sign []int16, weights correlationWeights) [subframeSamples]int16 {
	var en [subframeSamples]int16
	for i := subframeSamples - 1; i >= 0; i-- {
		val := dn[i]
		cor := fxp.Round(fxp.Shl32(
			fxp.Add32(fxp.LMult(weights.cn, cn[i]), fxp.LMult(weights.dn, val)),
			10,
		))
		if cor >= 0 {
			sign[i] = fxp.Max16
		} else {
			sign[i] = -fxp.Max16
			cor = fxp.Neg16(cor)
			dn[i] = fxp.Neg16(val)
		}
		en[i] = cor
	}
	return en
}

func trackMaxPositions(en [subframeSamples]int16, posMax []int16, tracks int, step int) int {
	maxOfAll := int16(-1)
	startTrack := 0
	for track := range tracks {
		maxCorr := int16(-1)
		pos := int16(track)
		for j := track; j < subframeSamples; j += step {
			if en[j] > maxCorr {
				maxCorr = en[j]
				pos = int16(j)
			}
		}
		posMax[track] = pos
		if maxCorr > maxOfAll {
			maxOfAll = maxCorr
			startTrack = track
		}
	}
	return startTrack
}

func initialPulseTracks(ipos []int16, tracks int, startTrack int) {
	pos := startTrack
	ipos[0] = int16(pos)
	ipos[tracks] = int16(pos)
	for i := 1; i < tracks; i++ {
		pos++
		if pos >= tracks {
			pos = 0
		}
		ipos[i] = int16(pos)
		ipos[i+tracks] = int16(pos)
	}
}

func setSign(dn []int16, sign []int16, dn2 []int16, n int16) {
	limit := signedLowRateCorrelation(dn, sign, dn2)
	pruneWeakTrackPositions(dn2, n, limit)
}

func signedLowRateCorrelation(dn []int16, sign []int16, dn2 []int16) int {
	for i := subframeSamples - 1; i >= 0; i-- {
		value := dn[i]
		if value >= 0 {
			sign[i] = fxp.Max16
		} else {
			sign[i] = -fxp.Max16
			value = fxp.Neg16(value)
			dn[i] = value
		}
		dn2[i] = value
	}
	return subframeSamples
}

func pruneWeakTrackPositions(dn2 []int16, n int16, limit int) {
	for track := range codebookTracks {
		for k := int16(0); k < 8-n; k++ {
			minValue := fxp.Max16
			pos := track
			for j := track; j < limit; j += codebookStep {
				if dn2[j] >= 0 && dn2[j] < minValue {
					minValue = dn2[j]
					pos = j
				}
			}
			dn2[pos] = -1
		}
	}
}

func impulseResponseCorrelations(h []int16, sign []int16) [subframeSamples][subframeSamples]int16 {
	h2 := normalizedImpulseResponse(h)
	correlations := diagonalCorrelations(h2)
	return signedCorrelations(h2, sign, correlations)
}

func normalizedImpulseResponse(h []int16) [subframeSamples]int16 {
	var out [subframeSamples]int16
	energy := int32(2)
	for i := range subframeSamples {
		energy = fxp.LMac(energy, h[i], h[i])
	}

	if fxp.Sub16(fxp.ExtractH(energy), fxp.Max16) == 0 {
		for i := range subframeSamples {
			out[i] = fxp.Shr16(h[i], 1)
		}
		return out
	}

	scale := invSqrt(fxp.Shr32(energy, 1))
	k := fxp.ExtractH(fxp.Shl32(scale, 7))
	k = fxp.Mult(k, 32440)
	for i := range subframeSamples {
		out[i] = fxp.Round(fxp.Shl32(fxp.LMult(h[i], k), 9))
	}
	return out
}

func diagonalCorrelations(h [subframeSamples]int16) [subframeSamples][subframeSamples]int16 {
	var correlations [subframeSamples][subframeSamples]int16
	sum := int32(0)
	for k := range subframeSamples {
		sum = fxp.LMac(sum, h[k], h[k])
		i := subframeSamples - 1 - k
		correlations[i][i] = fxp.Round(sum)
	}
	return correlations
}

func signedCorrelations(h [subframeSamples]int16, sign []int16, correlations [subframeSamples][subframeSamples]int16) [subframeSamples][subframeSamples]int16 {
	for dec := 1; dec < subframeSamples; dec++ {
		sum := int32(0)
		j := subframeSamples - 1
		i := j - dec
		for k := range subframeSamples - dec {
			sum = fxp.LMac(sum, h[k], h[k+dec])
			corr := fxp.Round(sum)
			signProduct := fxp.Mult(sign[i], sign[j])
			signed := fxp.Mult(corr, signProduct)
			correlations[j][i] = signed
			correlations[i][j] = signed
			i--
			j--
		}
	}
	return correlations
}

func search2i40(
	subframeNumber int16,
	dn []int16,
	rr *[subframeSamples][subframeSamples]int16,
) [pulseCount2]int16 {
	codvec := [pulseCount2]int16{0, 1}
	psk := int16(-1)
	alpk := int16(1)

	for trackPair := range int16(2) {
		start := (subframeNumber << 1) + (trackPair << 3)
		ipos0 := startPos2i40[start]
		ipos1 := startPos2i40[start+1]
		for i0 := ipos0; i0 < subframeSamples; i0 += codebookStep {
			ps0 := dn[i0]
			alp0 := fxp.LMult(rr[i0][i0], 8192)
			sq := int16(-1)
			alp := int16(1)
			ix := ipos1
			for i1 := ipos1; i1 < subframeSamples; i1 += codebookStep {
				ps1 := fxp.Add16(ps0, dn[i1])
				alp1 := fxp.LMac(alp0, rr[i1][i1], 8192)
				alp1 = fxp.LMac(alp1, rr[i0][i1], 16384)
				sq1 := fxp.Mult(ps1, ps1)
				alp16 := fxp.Round(alp1)
				score := fxp.LMsu(fxp.LMult(alp, sq1), sq, alp16)
				if score > 0 {
					sq = sq1
					alp = alp16
					ix = i1
				}
			}
			score := fxp.LMsu(fxp.LMult(alpk, sq), psk, alp)
			if score > 0 {
				psk = sq
				alpk = alp
				codvec[0] = i0
				codvec[1] = ix
			}
		}
	}

	return codvec
}

func search2i40_11(
	dn []int16,
	rr *[subframeSamples][subframeSamples]int16,
) [pulseCount2]int16 {
	codvec := [pulseCount2]int16{0, 1}
	psk := int16(-1)
	alpk := int16(1)
	for track1 := range len(startPos2i40_11First) {
		for track2 := range len(startPos2i40_11Second) {
			ipos0 := startPos2i40_11First[track1]
			ipos1 := startPos2i40_11Second[track2]
			for i0 := ipos0; i0 < subframeSamples; i0 += codebookStep {
				ps0 := dn[i0]
				alp0 := int32(rr[i0][i0]) << 14
				sq := int16(-1)
				alp := int16(1)
				ix := ipos1
				for i1 := ipos1; i1 < subframeSamples; i1 += codebookStep {
					ps1 := fxp.Add16(ps0, dn[i1])
					alp1 := alp0 + (int32(rr[i1][i1]) << 14) + (int32(rr[i0][i1]) << 15)
					sq1 := int16((int32(ps1) * int32(ps1)) >> 15)
					alp16 := int16((alp1 + 0x8000) >> 16)
					score := ((int32(alp) * int32(sq1)) << 1) - ((int32(sq) * int32(alp16)) << 1)
					if score > 0 {
						sq = sq1
						alp = alp16
						ix = i1
					}
				}
				score := ((int32(alpk) * int32(sq)) << 1) - ((int32(psk) * int32(alp)) << 1)
				if score > 0 {
					psk = sq
					alpk = alp
					codvec[0] = i0
					codvec[1] = ix
				}
			}
		}
	}

	return codvec
}

func search3i40(
	dn []int16,
	dn2 []int16,
	rr *[subframeSamples][subframeSamples]int16,
) [3]int16 {
	codvec := [3]int16{0, 1, 2}
	psk := int16(-1)
	alpk := int16(1)

	for track1 := int16(1); track1 < 4; track1 += 2 {
		for track2 := int16(2); track2 < 5; track2 += 2 {
			ipos := [3]int16{0, track1, track2}
			for range 3 {
				for i0 := ipos[0]; i0 < subframeSamples; i0 += codebookStep {
					if dn2[i0] < 0 {
						continue
					}

					ps0 := dn[i0]
					alp0 := int32(rr[i0][i0]) << 14

					sq := int16(-1)
					alp := int16(1)
					ps := int16(0)
					ix := ipos[1]
					for i1 := ipos[1]; i1 < subframeSamples; i1 += codebookStep {
						ps1 := ps0 + dn[i1]
						alp1 := alp0 + (int32(rr[i1][i1]) << 14) + (int32(rr[i0][i1]) << 15)
						sq1 := int16((int32(ps1) * int32(ps1)) >> 15)
						alp16 := int16((alp1 + 0x8000) >> 16)
						score := ((int32(alp) * int32(sq1)) << 1) - ((int32(sq) * int32(alp16)) << 1)
						if score > 0 {
							sq = sq1
							ps = ps1
							alp = alp16
							ix = i1
						}
					}
					i1 := ix

					ps0 = ps
					alp0 = int32(alp) << 14
					sq = -1
					alp = 1
					ix = ipos[2]
					for i2 := ipos[2]; i2 < subframeSamples; i2 += codebookStep {
						ps1 := ps0 + dn[i2]
						alp1 := alp0 +
							(int32(rr[i2][i2]) << 12) +
							(int32(rr[i1][i2]) << 13) +
							(int32(rr[i0][i2]) << 13)
						sq1 := int16((int32(ps1) * int32(ps1)) >> 15)
						alp16 := int16((alp1 + 0x8000) >> 16)
						score := ((int32(alp) * int32(sq1)) << 1) - ((int32(sq) * int32(alp16)) << 1)
						if score > 0 {
							sq = sq1
							alp = alp16
							ix = i2
						}
					}
					i2 := ix

					score := ((int32(alpk) * int32(sq)) << 1) - ((int32(psk) * int32(alp)) << 1)
					if score > 0 {
						psk = sq
						alpk = alp
						codvec[0] = i0
						codvec[1] = i1
						codvec[2] = i2
					}
				}

				ipos[0], ipos[1], ipos[2] = ipos[2], ipos[0], ipos[1]
			}
		}
	}

	return codvec
}

func search4i40(
	dn []int16,
	dn2 []int16,
	rr *[subframeSamples][subframeSamples]int16,
) [4]int16 {
	codvec := [4]int16{0, 1, 2, 3}
	psk := int16(-1)
	alpk := int16(1)

	for track := int16(3); track < 5; track++ {
		ipos := [4]int16{0, 1, 2, track}
		for range 4 {
			for i0 := ipos[0]; i0 < subframeSamples; i0 += codebookStep {
				if dn2[i0] < 0 {
					continue
				}

				ps0 := dn[i0]
				alp0 := int32(rr[i0][i0]) << 14

				sq := int16(-1)
				alp := int16(1)
				ps := int16(0)
				ix := ipos[1]
				for i1 := ipos[1]; i1 < subframeSamples; i1 += codebookStep {
					ps1 := ps0 + dn[i1]
					alp1 := alp0 + (int32(rr[i1][i1]) << 14) + (int32(rr[i0][i1]) << 15)
					sq1 := int16((int32(ps1) * int32(ps1)) >> 15)
					alp16 := int16((alp1 + 0x8000) >> 16)
					score := ((int32(alp) * int32(sq1)) << 1) - ((int32(sq) * int32(alp16)) << 1)
					if score > 0 {
						sq = sq1
						ps = ps1
						alp = alp16
						ix = i1
					}
				}
				i1 := ix

				ps0 = ps
				alp0 = int32(alp) << 14
				sq = -1
				alp = 1
				ix = ipos[2]
				for i2 := ipos[2]; i2 < subframeSamples; i2 += codebookStep {
					ps1 := ps0 + dn[i2]
					alp1 := alp0 +
						(int32(rr[i2][i2]) << 12) +
						(int32(rr[i1][i2]) << 13) +
						(int32(rr[i0][i2]) << 13)
					sq1 := int16((int32(ps1) * int32(ps1)) >> 15)
					alp16 := int16((alp1 + 0x8000) >> 16)
					score := ((int32(alp) * int32(sq1)) << 1) - ((int32(sq) * int32(alp16)) << 1)
					if score > 0 {
						sq = sq1
						ps = ps1
						alp = alp16
						ix = i2
					}
				}
				i2 := ix

				ps0 = ps
				alp0 = int32(alp) << 16
				sq = -1
				alp = 1
				ix = ipos[3]
				for i3 := ipos[3]; i3 < subframeSamples; i3 += codebookStep {
					ps1 := ps0 + dn[i3]
					alp1 := alp0 +
						(int32(rr[i3][i3]) << 12) +
						(int32(rr[i2][i3]) << 13) +
						(int32(rr[i1][i3]) << 13) +
						(int32(rr[i0][i3]) << 13)
					sq1 := int16((int32(ps1) * int32(ps1)) >> 15)
					alp16 := int16((alp1 + 0x8000) >> 16)
					score := ((int32(alp) * int32(sq1)) << 1) - ((int32(sq) * int32(alp16)) << 1)
					if score > 0 {
						sq = sq1
						alp = alp16
						ix = i3
					}
				}

				score := ((int32(alpk) * int32(sq)) << 1) - ((int32(psk) * int32(alp)) << 1)
				if score > 0 {
					psk = sq
					alpk = alp
					codvec[0] = i0
					codvec[1] = i1
					codvec[2] = i2
					codvec[3] = ix
				}
			}

			ipos[0], ipos[1], ipos[2], ipos[3] = ipos[3], ipos[0], ipos[1], ipos[2]
		}
	}

	return codvec
}

type pulsePairWeights struct {
	firstSelf  int16
	firstFixed int16
	secondTail int16
	pair       int16
}

type pulsePairSearch struct {
	sq     int16
	alp    int16
	ps     int16
	first  int16
	second int16
}

func newPulsePairSearch(first int16, second int16) pulsePairSearch {
	return pulsePairSearch{
		sq:     -1,
		alp:    1,
		first:  first,
		second: second,
	}
}

func (s *pulsePairSearch) keep(ps int16, alp32 int32, first int16, second int16) {
	sq := fxp.Mult(ps, ps)
	alp := fxp.Round(alp32)
	score := fxp.LMsu(fxp.LMult(s.alp, sq), s.sq, alp)
	if score <= 0 {
		return
	}

	s.sq = sq
	s.ps = ps
	s.alp = alp
	s.first = first
	s.second = second
}

func codebookSearchSeed(
	dn []int16,
	rr *[subframeSamples][subframeSamples]int16,
	first int16,
	second int16,
) (int16, int32) {
	ps := fxp.Add16(dn[first], dn[second])
	alp := fxp.LMult(rr[first][first], 2048)
	alp = fxp.LMac(alp, rr[second][second], 2048)
	alp = fxp.LMac(alp, rr[first][second], 4096)
	return ps, alp
}

func fillPulseTailCorrelation(
	rr *[subframeSamples][subframeSamples]int16,
	rrv *[subframeSamples]int16,
	fixed []int16,
	start int16,
	step int16,
	selfWeight int16,
	fixedWeight int16,
) {
	for target := start; target < subframeSamples; target += step {
		s := fxp.LMult(rr[target][target], selfWeight)
		for _, pos := range fixed {
			s = fxp.LMac(s, rr[pos][target], fixedWeight)
		}
		rrv[target] = fxp.Round(s)
	}
}

func searchPulsePair(
	dn []int16,
	rr *[subframeSamples][subframeSamples]int16,
	rrv *[subframeSamples]int16,
	fixed []int16,
	firstStart int16,
	secondStart int16,
	step int16,
	ps0 int16,
	alp0 int32,
	weights pulsePairWeights,
) pulsePairSearch {
	out := newPulsePairSearch(firstStart, secondStart)
	for first := firstStart; first < subframeSamples; first += step {
		ps1 := fxp.Add16(ps0, dn[first])
		alp1 := fxp.LMac(alp0, rr[first][first], weights.firstSelf)
		for _, pos := range fixed {
			alp1 = fxp.LMac(alp1, rr[pos][first], weights.firstFixed)
		}

		for second := secondStart; second < subframeSamples; second += step {
			ps2 := fxp.Add16(ps1, dn[second])
			alp2 := fxp.LMac(alp1, rrv[second], weights.secondTail)
			alp2 = fxp.LMac(alp2, rr[first][second], weights.pair)
			out.keep(ps2, alp2, first, second)
		}
	}
	return out
}

func betterCodebookScore(bestSq int16, bestAlp int16, sq int16, alp int16) bool {
	score := fxp.LMsu(fxp.LMult(bestAlp, sq), bestSq, alp)
	return score > 0
}

func rotatePulseTracks(ipos []int16, count int) {
	pos := ipos[1]
	copy(ipos[1:], ipos[2:count])
	ipos[count-1] = pos
}

func search8i40(
	dn []int16,
	rr *[subframeSamples][subframeSamples]int16,
	ipos []int16,
	posMax []int16,
) [pulseCount8]int16 {
	var codvec [pulseCount8]int16
	for i := range codvec {
		codvec[i] = int16(i)
	}
	i0 := posMax[ipos[0]]
	psk := int16(-1)
	alpk := int16(1)
	var rrv [subframeSamples]int16

	for range mr102Tracks - 1 {
		i1 := posMax[ipos[1]]
		ps0, alp0 := codebookSearchSeed(dn, rr, i0, i1)

		fixed2 := [...]int16{i0, i1}
		fillPulseTailCorrelation(rr, &rrv, fixed2[:], ipos[3], mr102Step, 4096, 8192)
		pair23 := searchPulsePair(dn, rr, &rrv, fixed2[:], ipos[2], ipos[3], mr102Step, ps0, alp0, pulsePairWeights{
			firstSelf:  2048,
			firstFixed: 4096,
			secondTail: 16384,
			pair:       4096,
		})

		fixed4 := [...]int16{i0, i1, pair23.first, pair23.second}
		fillPulseTailCorrelation(rr, &rrv, fixed4[:], ipos[5], mr102Step, 4096, 8192)
		pair45 := searchPulsePair(dn, rr, &rrv, fixed4[:], ipos[4], ipos[5], mr102Step, pair23.ps, fxp.LMult(pair23.alp, 16384), pulsePairWeights{
			firstSelf:  1024,
			firstFixed: 2048,
			secondTail: 8192,
			pair:       2048,
		})

		fixed6 := [...]int16{i0, i1, pair23.first, pair23.second, pair45.first, pair45.second}
		fillPulseTailCorrelation(rr, &rrv, fixed6[:], ipos[7], mr102Step, 2048, 4096)
		pair67 := searchPulsePair(dn, rr, &rrv, fixed6[:], ipos[6], ipos[7], mr102Step, pair45.ps, fxp.LMult(pair45.alp, 16384), pulsePairWeights{
			firstSelf:  512,
			firstFixed: 1024,
			secondTail: 8192,
			pair:       1024,
		})

		if betterCodebookScore(psk, alpk, pair67.sq, pair67.alp) {
			psk = pair67.sq
			alpk = pair67.alp
			codvec = [pulseCount8]int16{
				i0, i1,
				pair23.first, pair23.second,
				pair45.first, pair45.second,
				pair67.first, pair67.second,
			}
		}

		rotatePulseTracks(ipos, pulseCount8)
	}

	return codvec
}

func search10i40(
	dn []int16,
	rr *[subframeSamples][subframeSamples]int16,
	ipos []int16,
	posMax []int16,
) [pulseCount10]int16 {
	var codvec [pulseCount10]int16
	for i := range codvec {
		codvec[i] = int16(i)
	}
	i0 := posMax[ipos[0]]
	psk := int16(-1)
	alpk := int16(1)
	var rrv [subframeSamples]int16

	for range codebookTracks - 1 {
		i1 := posMax[ipos[1]]
		ps0, alp0 := codebookSearchSeed(dn, rr, i0, i1)

		fixed2 := [...]int16{i0, i1}
		fillPulseTailCorrelation(rr, &rrv, fixed2[:], ipos[3], codebookStep, 4096, 8192)
		pair23 := searchPulsePair(dn, rr, &rrv, fixed2[:], ipos[2], ipos[3], codebookStep, ps0, alp0, pulsePairWeights{
			firstSelf:  2048,
			firstFixed: 4096,
			secondTail: 16384,
			pair:       4096,
		})

		fixed4 := [...]int16{i0, i1, pair23.first, pair23.second}
		fillPulseTailCorrelation(rr, &rrv, fixed4[:], ipos[5], codebookStep, 4096, 8192)
		pair45 := searchPulsePair(dn, rr, &rrv, fixed4[:], ipos[4], ipos[5], codebookStep, pair23.ps, fxp.LMult(pair23.alp, 16384), pulsePairWeights{
			firstSelf:  1024,
			firstFixed: 2048,
			secondTail: 8192,
			pair:       2048,
		})

		fixed6 := [...]int16{i0, i1, pair23.first, pair23.second, pair45.first, pair45.second}
		fillPulseTailCorrelation(rr, &rrv, fixed6[:], ipos[7], codebookStep, 2048, 4096)
		pair67 := searchPulsePair(dn, rr, &rrv, fixed6[:], ipos[6], ipos[7], codebookStep, pair45.ps, fxp.LMult(pair45.alp, 16384), pulsePairWeights{
			firstSelf:  512,
			firstFixed: 1024,
			secondTail: 8192,
			pair:       1024,
		})

		fixed8 := [...]int16{i0, i1, pair23.first, pair23.second, pair45.first, pair45.second, pair67.first, pair67.second}
		fillPulseTailCorrelation(rr, &rrv, fixed8[:], ipos[9], codebookStep, 2048, 4096)
		pair89 := searchPulsePair(dn, rr, &rrv, fixed8[:], ipos[8], ipos[9], codebookStep, pair67.ps, fxp.LMult(pair67.alp, 16384), pulsePairWeights{
			firstSelf:  256,
			firstFixed: 512,
			secondTail: 4096,
			pair:       512,
		})

		if betterCodebookScore(psk, alpk, pair89.sq, pair89.alp) {
			psk = pair89.sq
			alpk = pair89.alp
			codvec = [pulseCount10]int16{
				i0, i1,
				pair23.first, pair23.second,
				pair45.first, pair45.second,
				pair67.first, pair67.second,
				pair89.first, pair89.second,
			}
		}

		rotatePulseTracks(ipos, pulseCount10)
	}
	return codvec
}

func resetCodebookOutput(code []int16, y []int16) {
	clearCodeVector(code)
	clear(y[:subframeSamples])
}

func synthesizeCodebookTarget(codvec []int16, signs []int16, h []int16, y []int16) {
	for i := range subframeSamples {
		sum := int32(0)
		for k, pos := range codvec {
			hIndex := i - int(pos)
			if hIndex >= 0 {
				sum = fxp.Add32(sum, fxp.LMult(h[hIndex], signs[k]))
			}
		}
		y[i] = fxp.Round(sum)
	}
}

func synthesizeMR122CodebookTarget(codvec []int16, signs []int16, h []int16, y []int16) {
	for i := range subframeSamples {
		sum := int32(0)
		for k, pos := range codvec {
			hIndex := i - int(pos)
			if hIndex >= 0 {
				sum = fxp.Add32(sum, (int32(h[hIndex])*int32(signs[k]))>>7)
			}
		}
		y[i] = int16((sum + 0x80) >> 8)
	}
}

func writeCodebookPulse(code []int16, dnSign []int16, pos int16) (int16, bool) {
	if dnSign[pos] > 0 {
		code[pos] = 8191
		return fxp.Max16, true
	}
	code[pos] = -8192
	return fxp.Min16, false
}

func buildCode2i40(
	subframeNumber int16,
	codvec [pulseCount2]int16,
	dnSign []int16,
	code []int16,
	h []int16,
	y []int16,
) code2i40Result {
	resetCodebookOutput(code, y)

	var signs [pulseCount2]int16
	index := int16(0)
	rsign := int16(0)
	trackBase := int(subframeNumber) * codebookTracks
	for k := range pulseCount2 {
		pos := codvec[k]
		posIndex := int16((int32(pos) * 6554) >> 15)
		track := pos - 5*posIndex
		first := trackTable2i40[trackBase+int(track)]

		if k == 0 {
			track = 0
			if first != 0 {
				posIndex = fxp.Add16(posIndex, 64)
			}
		} else {
			track = 1
			posIndex = fxp.Shl16(posIndex, 3)
		}

		sign, positive := writeCodebookPulse(code, dnSign, pos)
		signs[k] = sign
		if positive {
			rsign = fxp.Add16(rsign, fxp.Shl16(1, track))
		}
		index = fxp.Add16(index, posIndex)
	}

	synthesizeCodebookTarget(codvec[:], signs[:], h, y)

	return code2i40Result{index: index, sign: rsign}
}

func buildCode2i40_11(
	codvec [pulseCount2]int16,
	dnSign []int16,
	code []int16,
	h []int16,
	y []int16,
) code2i40Result {
	resetCodebookOutput(code, y)

	var signs [pulseCount2]int16
	index := int16(0)
	rsign := int16(0)
	for k := range pulseCount2 {
		pos := codvec[k]
		posIndex := int16((int32(pos) * 6554) >> 15)
		track := pos - 5*posIndex

		switch track {
		case 0:
			track = 1
			posIndex <<= 6
		case 1:
			if k == 0 {
				track = 0
				posIndex <<= 1
			} else {
				track = 1
				posIndex = (posIndex << 6) + 16
			}
		case 2:
			track = 1
			posIndex = (posIndex << 6) + 32
		case 3:
			track = 0
			posIndex = (posIndex << 1) + 1
		case 4:
			track = 1
			posIndex = (posIndex << 6) + 48
		}

		sign, positive := writeCodebookPulse(code, dnSign, pos)
		signs[k] = sign
		if positive {
			rsign += 1 << track
		}
		index += posIndex
	}

	synthesizeCodebookTarget(codvec[:], signs[:], h, y)

	return code2i40Result{index: index, sign: rsign}
}

func buildCode3i40(
	codvec [3]int16,
	dnSign []int16,
	code []int16,
	h []int16,
	y []int16,
) code3i40Result {
	resetCodebookOutput(code, y)

	var signs [3]int16
	index := int16(0)
	rsign := int16(0)
	for k := range 3 {
		pos := codvec[k]
		posIndex := int16((int32(pos) * 6554) >> 15)
		track := pos - 5*posIndex

		switch track {
		case 1:
			posIndex <<= 4
		case 2:
			track = 2
			posIndex <<= 8
		case 3:
			track = 1
			posIndex = (posIndex << 4) + 8
		case 4:
			track = 2
			posIndex = (posIndex << 8) + 128
		}

		sign, positive := writeCodebookPulse(code, dnSign, pos)
		signs[k] = sign
		if positive {
			rsign += 1 << track
		}
		index += posIndex
	}

	synthesizeCodebookTarget(codvec[:], signs[:], h, y)

	return code3i40Result{index: index, sign: rsign}
}

func buildCode4i40(
	codvec [4]int16,
	dnSign []int16,
	code []int16,
	h []int16,
	y []int16,
) code4i40Result {
	resetCodebookOutput(code, y)

	var signs [4]int16
	index := int16(0)
	rsign := int16(0)
	for k := range 4 {
		pos := codvec[k]
		posIndex := int16((int32(pos) * 6554) >> 15)
		track := pos - 5*posIndex
		posIndex = gray[posIndex]

		switch track {
		case 1:
			posIndex <<= 3
		case 2:
			posIndex <<= 6
		case 3:
			posIndex <<= 10
		case 4:
			track = 3
			posIndex = (posIndex << 10) + 512
		}

		sign, positive := writeCodebookPulse(code, dnSign, pos)
		signs[k] = sign
		if positive {
			rsign += 1 << track
		}
		index += posIndex
	}

	synthesizeCodebookTarget(codvec[:], signs[:], h, y)

	return code4i40Result{index: index, sign: rsign}
}

func buildCode8i40(
	codvec [pulseCount8]int16,
	dnSign []int16,
	code []int16,
	h []int16,
	y []int16,
) code8i40Result {
	resetCodebookOutput(code, y)

	var signs [pulseCount8]int16
	var signIndex [mr102Tracks]int16
	var posIndex [pulseCount8]int16
	for i := range mr102Tracks {
		signIndex[i] = -1
		posIndex[i] = -1
	}
	for k := range pulseCount8 {
		pos := codvec[k]
		track := pos & 3
		position := pos >> 2
		pulseSign := int16(0)
		if dnSign[pos] > 0 {
			code[pos] = fxp.Add16(code[pos], 8191)
			signs[k] = fxp.Max16
		} else {
			code[pos] = fxp.Sub16(code[pos], 8191)
			signs[k] = fxp.Min16
			pulseSign = 1
		}

		if posIndex[track] < 0 {
			posIndex[track] = position
			signIndex[track] = pulseSign
			continue
		}

		secondSlot := track + mr102Tracks
		if ((pulseSign ^ signIndex[track]) & 1) == 0 {
			if posIndex[track] <= position {
				posIndex[secondSlot] = position
			} else {
				posIndex[secondSlot] = posIndex[track]
				posIndex[track] = position
				signIndex[track] = pulseSign
			}
			continue
		}

		if posIndex[track] <= position {
			posIndex[secondSlot] = posIndex[track]
			posIndex[track] = position
			signIndex[track] = pulseSign
		} else {
			posIndex[secondSlot] = position
		}
	}

	synthesizeCodebookTarget(codvec[:], signs[:], h, y)

	return code8i40Result{params: compressCode8i40(signIndex, posIndex)}
}

func buildCode10i40(
	codvec [pulseCount10]int16,
	dnSign []int16,
	code []int16,
	h []int16,
	y []int16,
) code10i40Result {
	resetCodebookOutput(code, y)

	var signs [pulseCount10]int16
	var params [pulseCount10]int16
	for i := range codebookTracks {
		params[i] = -1
	}
	for k := range pulseCount10 {
		pos := codvec[k]
		position := int16((int32(pos) * 6554) >> 15)
		track := pos - 5*position
		index := position
		if dnSign[pos] > 0 {
			code[pos] = fxp.Add16(code[pos], 4096)
			signs[k] = 8192
		} else {
			code[pos] = fxp.Sub16(code[pos], 4096)
			signs[k] = -8192
			index += 8
		}

		if params[track] < 0 {
			params[track] = index
			continue
		}

		if ((index ^ params[track]) & 8) == 0 {
			if params[track] <= index {
				params[track+codebookTracks] = index
			} else {
				params[track+codebookTracks] = params[track]
				params[track] = index
			}
			continue
		}

		if (params[track] & 7) <= (index & 7) {
			params[track+codebookTracks] = params[track]
			params[track] = index
		} else {
			params[track+codebookTracks] = index
		}
	}

	synthesizeMR122CodebookTarget(codvec[:], signs[:], h, y)

	for i := range params {
		params[i] = quantizePulsePosition(params[i], i)
	}
	return code10i40Result{params: params}
}

func quantizePulsePosition(index int16, pulse int) int16 {
	if pulse < codebookTracks {
		return (index & 8) | gray[index&7]
	}
	return gray[index&7]
}

func compressCode8i40(signIndex [mr102Tracks]int16, posIndex [pulseCount8]int16) [7]int16 {
	var params [7]int16
	copy(params[:mr102Tracks], signIndex[:])
	params[4] = compress10(posIndex[0], posIndex[4], posIndex[1])
	params[5] = compress10(posIndex[2], posIndex[6], posIndex[5])

	ib := posIndex[7] >> 1
	ia := posIndex[3] >> 1
	if ib&1 == 1 {
		ia = 4 - ia
	}
	ib *= 5
	ib += ia
	ib <<= 5
	ib += 12
	ic := int16((int32(ib) * 1311) >> 15)
	params[6] = (ic << 2) + (posIndex[3] & 1) + ((posIndex[7] & 1) << 1)
	return params
}

func compress10(posA, posB, posC int16) int16 {
	ia := posA >> 1
	ib := (posB >> 1) * 5
	ic := (posC >> 1) * 25
	index := (ia + ib + ic) << 3
	index += (posA & 1) + ((posB & 1) << 1) + ((posC & 1) << 2)
	return index
}
