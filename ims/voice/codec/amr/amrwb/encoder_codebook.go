/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * These encoder fixed-codebook primitives are ported from amrwbenc/src/cor_h_x.c
 * and c2t64fx.c.
 */

package amrwb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const (
	acelp2TrackCount     = 2
	acelp2TrackPositions = 32
	acelp4TrackPositions = 16
)

func correlateImpulseTarget(h []int16, x []int16) ([subframeSamples]int16, error) {
	var dn [subframeSamples]int16
	if len(h) < subframeSamples || len(x) < subframeSamples {
		return dn, errors.New("correlate impulse response and target: buffers are too short")
	}
	var y32 [subframeSamples]int32
	total := int32(1)
	for track := range codeTrackCount {
		var trackMax int32
		for i := track; i < subframeSamples; i += codeTrackCount {
			acc := int32(1)
			for j := i; j < subframeSamples; j++ {
				acc = fxp.LMac(acc, x[j], h[j-i])
			}
			y32[i] = acc
			abs := fxp.Abs32(acc)

			trackMax = max(trackMax, abs)

		}
		trackMax = fxp.Shr32(trackMax, 2)
		total = fxp.Add32(total, trackMax)
		total = fxp.Add32(total, fxp.Shr32(trackMax, 1))
	}

	shift := normalizeAMRWB(total) - 4
	for i := range subframeSamples {
		dn[i] = fxp.Round(fxp.Shl32(y32[i], shift))
	}
	return dn, nil
}

type acelp2t64Result struct {
	index    int16
	code     [subframeSamples]int16
	filtered [subframeSamples]int16
}

func acelp2t64(dn []int16, cn []int16, h []int16) (acelp2t64Result, error) {
	var out acelp2t64Result
	if len(dn) < subframeSamples || len(cn) < subframeSamples || len(h) < subframeSamples {
		return out, errors.New("search 2-track algebraic codebook: buffers are too short")
	}

	cnEnergy, exp := dotProduct12(cn, cn, subframeSamples)
	cnEnergy, exp = oneOverSqrtNorm(cnEnergy, exp)
	kCN := fxp.Round(fxp.Shl32(cnEnergy, exp+5))

	dnEnergy, exp := dotProduct12(dn, dn, subframeSamples)
	dnEnergy, exp = oneOverSqrtNorm(dnEnergy, exp)
	kDN := fxp.Round(fxp.Shl32(dnEnergy, exp+8))
	kDN = fxp.MultRound(8192, kDN)

	var sign [subframeSamples]int16
	var dnAbs [subframeSamples]int16
	for i := range subframeSamples {
		mixed := fxp.LMult(kCN, cn[i])
		mixed = fxp.LMac(mixed, kDN, dn[i])
		dn2 := fxp.ExtractH(fxp.Shl32(mixed, 8))
		dnAbs[i] = dn[i]
		if dn2 >= 0 {
			sign[i] = fxp.Max16
			continue
		}
		sign[i] = fxp.Min16
		dnAbs[i] = fxp.Neg16(dn[i])
	}

	var selfEnergy [acelp2TrackCount][acelp2TrackPositions]int16
	acc := int32(0x00010000)
	hIndex := 0
	for i := range acelp2TrackPositions {
		acc = fxp.LMac(acc, h[hIndex], h[hIndex])
		hIndex++
		selfEnergy[1][acelp2TrackPositions-1-i] = fxp.ExtractH(acc) >> 1
		acc = fxp.LMac(acc, h[hIndex], h[hIndex])
		hIndex++
		selfEnergy[0][acelp2TrackPositions-1-i] = fxp.ExtractH(acc) >> 1
	}

	var crossEnergy [acelp2TrackPositions * acelp2TrackPositions]int16
	pos := len(crossEnergy) - 1
	pos2 := len(crossEnergy) - 2
	hf := 1
	for k := range acelp2TrackPositions {
		p1 := pos
		p0 := pos2
		acc := int32(0x00008000)
		h1 := 0
		h2 := hf
		for i := k + 1; i < acelp2TrackPositions; i++ {
			acc = fxp.LMac(acc, h[h1], h[h2])
			h1++
			h2++
			crossEnergy[p1] = fxp.ExtractH(acc)
			acc = fxp.LMac(acc, h[h1], h[h2])
			h1++
			h2++
			crossEnergy[p0] = fxp.ExtractH(acc)
			p1 -= acelp2TrackPositions + 1
			p0 -= acelp2TrackPositions + 1
		}
		acc = fxp.LMac(acc, h[h1], h[h2])
		crossEnergy[p1] = fxp.ExtractH(acc)
		pos -= acelp2TrackPositions
		pos2--
		hf += acelp2TrackCount
	}

	cross := 0
	for i := 0; i < subframeSamples; i += acelp2TrackCount {
		for j := 1; j < subframeSamples; j += acelp2TrackCount {
			signValue := sign[j]
			if sign[i] < 0 {
				signValue = fxp.Max16
				if sign[j] > 0 {
					signValue = fxp.Min16
				}
			}
			crossEnergy[cross] = fxp.Mult(crossEnergy[cross], signValue)
			cross++
		}
	}

	psk := int16(-1)
	alpk := int16(1)
	ix := 0
	iy := 1
	p0 := 0
	p1 := 0
	p2 := 0
	for i0 := 0; i0 < subframeSamples; i0 += 2 {
		ps1 := dnAbs[i0]
		alp1 := selfEnergy[0][p0]
		p0++
		pos := -1
		for i1 := 1; i1 < subframeSamples; i1 += 2 {
			ps2 := fxp.Add16(ps1, dnAbs[i1])
			alp2 := fxp.Add16(alp1, fxp.Add16(selfEnergy[1][p1], crossEnergy[p2]))
			p1++
			p2++
			sq := fxp.Mult(ps2, ps2)
			score := fxp.LMsu(fxp.LMult(alpk, sq), psk, alp2)
			if score > 0 {
				psk = sq
				alpk = alp2
				pos = i1
			}
		}
		p1 -= acelp2TrackPositions
		if pos >= 0 {
			ix = i0
			iy = pos
		}
	}

	i0 := ix >> 1
	i1 := iy >> 1
	if sign[ix] > 0 {
		out.code[ix] = codePulseAmplitude
	} else {
		out.code[ix] = -codePulseAmplitude
		i0 += acelp2TrackPositions
	}
	if sign[iy] > 0 {
		out.code[iy] = codePulseAmplitude
	} else {
		out.code[iy] = -codePulseAmplitude
		i1 += acelp2TrackPositions
	}
	for i := range subframeSamples {
		sum := filteredPulseSample(h, ix, sign[ix], i)
		sum = fxp.Add16(sum, filteredPulseSample(h, iy, sign[iy], i))
		out.filtered[i] = fxp.ShrRound16(sum, 3)
	}
	out.index = int16((i0 << 6) + i1)
	return out, nil
}

func (e *Encoder) searchMode660Codebook(sf *encoderSubframePitch) error {
	var h [subframeSamples]int16
	copy(h[:], sf.codeImpulse[:])
	preemphasis(h[:], e.tiltCode)
	pitchLag := sf.t0
	if sf.t0Frac > 2 {
		pitchLag++
	}
	sharpenPitch(h[:], pitchLag, pitSharp)

	dn, err := correlateImpulseTarget(h[:], sf.target2[:])
	if err != nil {
		return fmt.Errorf("search 6.60 codebook: %w", err)
	}
	searched, err := acelp2t64(dn[:], sf.codeTarget[:], h[:])
	if err != nil {
		return fmt.Errorf("search 6.60 codebook: %w", err)
	}
	sf.codeIndex = searched.index
	sf.code = searched.code
	sf.codeFiltered = searched.filtered
	preemphasis(sf.code[:], e.tiltCode)
	sharpenPitch(sf.code[:], pitchLag, pitSharp)
	copy(sf.codeImpulse[:], h[:])
	return nil
}

func (e *Encoder) searchMode885Codebook(sf *encoderSubframePitch) error {
	var h [subframeSamples]int16
	copy(h[:], sf.codeImpulse[:])
	preemphasis(h[:], e.tiltCode)
	pitchLag := sf.t0
	if sf.t0Frac > 2 {
		pitchLag++
	}
	sharpenPitch(h[:], pitchLag, pitSharp)

	dn, err := correlateImpulseTarget(h[:], sf.target2[:])
	if err != nil {
		return fmt.Errorf("search 8.85 codebook: %w", err)
	}
	searched, err := acelp4t64_20(dn[:], sf.codeTarget[:], h[:])
	if err != nil {
		return fmt.Errorf("search 8.85 codebook: %w", err)
	}
	copy(sf.codeIndices[:], searched.indices[:searched.indexCount])
	sf.code = searched.code
	if searched.hasFiltered {
		sf.codeFiltered = searched.filtered
	} else {
		scaleCodebookFallback(sf.codeFiltered[:])
	}
	preemphasis(sf.code[:], e.tiltCode)
	sharpenPitch(sf.code[:], pitchLag, pitSharp)
	copy(sf.codeImpulse[:], h[:])
	return nil
}

func (e *Encoder) searchMode1265Codebook(sf *encoderSubframePitch) error {
	return e.searchHigherModeCodebook(sf, 36, int16(frameBits[Mode1265]))
}

func (e *Encoder) searchMode1425Codebook(sf *encoderSubframePitch) error {
	return e.searchHigherModeCodebook(sf, 44, int16(frameBits[Mode1425]))
}

func (e *Encoder) searchMode1585Codebook(sf *encoderSubframePitch) error {
	return e.searchHigherModeCodebook(sf, 52, int16(frameBits[Mode1585]))
}

func (e *Encoder) searchMode1825Codebook(sf *encoderSubframePitch) error {
	return e.searchHigherModeCodebook(sf, 64, int16(frameBits[Mode1825]))
}

func (e *Encoder) searchMode1985Codebook(sf *encoderSubframePitch) error {
	return e.searchHigherModeCodebook(sf, 72, int16(frameBits[Mode1985]))
}

func (e *Encoder) searchMode2305Codebook(sf *encoderSubframePitch) error {
	return e.searchHigherModeCodebook(sf, 88, int16(frameBits[Mode2305]))
}

func (e *Encoder) searchMode2385Codebook(sf *encoderSubframePitch) error {
	return e.searchHigherModeCodebook(sf, 88, int16(frameBits[Mode2385]))
}

func (e *Encoder) searchHigherModeCodebook(
	sf *encoderSubframePitch,
	nbits int16,
	serialBits int16,
) error {
	var h [subframeSamples]int16
	copy(h[:], sf.codeImpulse[:])
	preemphasis(h[:], e.tiltCode)
	pitchLag := sf.t0
	if sf.t0Frac > 2 {
		pitchLag++
	}
	sharpenPitch(h[:], pitchLag, pitSharp)

	dn, err := correlateImpulseTarget(h[:], sf.target2[:])
	if err != nil {
		return fmt.Errorf("search %d-bit algebraic codebook: %w", nbits, err)
	}
	searched, err := acelp4t64Indexed(
		dn[:],
		sf.codeTarget[:],
		h[:],
		nbits,
		serialBits,
	)
	if err != nil {
		return fmt.Errorf("search %d-bit algebraic codebook: %w", nbits, err)
	}
	copy(sf.codeIndices[:], searched.indices[:searched.indexCount])
	sf.code = searched.code
	if searched.hasFiltered {
		sf.codeFiltered = searched.filtered
	} else {
		scaleCodebookFallback(sf.codeFiltered[:])
	}
	preemphasis(sf.code[:], e.tiltCode)
	sharpenPitch(sf.code[:], pitchLag, pitSharp)
	copy(sf.codeImpulse[:], h[:])
	return nil
}

type acelp4t64Result struct {
	indices     [8]int16
	indexCount  int
	code        [subframeSamples]int16
	filtered    [subframeSamples]int16
	hasFiltered bool
}

func scaleCodebookFallback(filtered []int16) {
	for i := range filtered {
		filtered[i] = fxp.ShrRound16(filtered[i], 3)
	}
}

func acelp4t64_20(dn []int16, cn []int16, h []int16) (acelp4t64Result, error) {
	return acelp4t64Indexed(dn, cn, h, 20, int16(frameBits[Mode885]))
}

func acelp4t64_36(dn []int16, cn []int16, h []int16) (acelp4t64Result, error) {
	return acelp4t64Indexed(dn, cn, h, 36, int16(frameBits[Mode1265]))
}

func acelp4t64Indexed(
	dn []int16,
	cn []int16,
	h []int16,
	nbits int16,
	serialBits int16,
) (acelp4t64Result, error) {
	var out acelp4t64Result
	if len(dn) < subframeSamples || len(cn) < subframeSamples || len(h) < subframeSamples {
		return out, errors.New("search 4-track algebraic codebook: buffers are too short")
	}

	cfg, ok := acelp4t64SearchConfig(nbits, serialBits)
	if !ok {
		return out, fmt.Errorf("search 4-track algebraic codebook: unsupported %d-bit configuration", nbits)
	}
	out.indexCount = 4
	if nbits >= 64 {
		out.indexCount = 8
	}

	sign, dnAbs, dnRank := codebookSearchSigns(dn, cn, cfg.alpha)
	posMax := codebookCandidateRanks(dnRank[:])
	hScaled, hShift := scaledImpulseResponse(h, cfg.pulses)
	rrixix := impulseSelfCorrelations(hScaled[:])
	rrixiy := impulseCrossCorrelations(hScaled[:], sign[:])

	bestScore := int16(-1)
	bestEnergy := int16(1)
	bestUpdated := false
	var bestVec [subframeSamples]int16
	var bestCode [24]int16
	var ind [24]int16
	var vec [subframeSamples]int16
	for i := range cfg.pulses {
		bestCode[i] = int16(i)
	}
	for iter := range cfg.iterations {
		var ipos [24]int16
		for i := range cfg.pulses {
			ipos[i] = acelp4t64TrackOrder[iter*codeTrackCount+i]
		}

		pos, ps, energy := initialCodebookStage(
			nbits,
			ipos[:],
			posMax[:],
			dnAbs[:],
			sign[:],
			hScaled[:],
			rrixix,
			rrixiy,
			&vec,
		)
		switch nbits {
		case 44:
			ipos[8], ipos[9] = 0, 1
		case 72:
			ipos[16], ipos[17] = 0, 1
		}
		copy(ind[:], ipos[:])
		if pos > 0 {
			for i := range pos {
				ind[i] = posMax[ipos[i]]
			}
		}

		for j, stage := pos, 0; j < cfg.pulses; j, stage = j+2, stage+1 {
			trackX := int(ipos[j])
			trackY := int(ipos[j+1])
			corX, corY := correlateFixedVector(hScaled[:], vec[:], trackX, sign[:], rrixix)
			pair := searchPulsePair(
				cfg.nbpos[stage],
				trackX,
				trackY,
				ps,
				energy,
				dnAbs[:],
				dnRank[:],
				corX[:],
				corY[:],
				rrixiy[:],
			)
			ps, energy = pair.ps, pair.energy
			ind[j], ind[j+1] = pair.x, pair.y
			addSignedImpulse(vec[:], hScaled[:], int(pair.x), sign[pair.x])
			addSignedImpulse(vec[:], hScaled[:], int(pair.y), sign[pair.y])
		}

		score := fxp.Mult(ps, ps)
		diff := fxp.Sub32(fxp.LMult(bestEnergy, score), fxp.LMult(bestScore, energy))
		if diff > 0 {
			bestScore = score
			bestEnergy = energy
			bestUpdated = true
			copy(bestCode[:], ind[:cfg.pulses])
			copy(bestVec[:], vec[:])
		}
	}

	var packed [codeTrackCount * 6]int16
	for i := range packed {
		packed[i] = -1
	}
	if bestUpdated {
		out.hasFiltered = true
		for i := range subframeSamples {
			out.filtered[i] = fxp.ShrRound16(bestVec[i], 3)
		}
	}
	amplitude := int16(codePulseAmplitude >> hShift)
	for k := range cfg.pulses {
		pos := bestCode[k]
		index := pos >> 2
		track := pos & 3
		if sign[pos] > 0 {
			out.code[pos] += amplitude
		} else {
			out.code[pos] -= amplitude
			index += codeTrackPositions
		}
		offset := int(track) * 6
		for packed[offset] >= 0 {
			offset++
		}
		packed[offset] = index
	}

	for track, offset := 0, 0; track < codeTrackCount; track, offset = track+1, offset+6 {
		var positions [6]int
		for i := range positions {
			positions[i] = int(packed[offset+i])
		}
		switch nbits {
		case 20:
			out.indices[track] = int16(quant1Pulse(positions[0], 4))
		case 36:
			out.indices[track] = int16(quant2Pulse(positions[0], positions[1], 4))
		case 44:
			if track < 2 {
				out.indices[track] = int16(quant3Pulse(
					positions[0],
					positions[1],
					positions[2],
					4,
				))
			} else {
				out.indices[track] = int16(quant2Pulse(positions[0], positions[1], 4))
			}
		case 52:
			out.indices[track] = int16(quant3Pulse(
				positions[0],
				positions[1],
				positions[2],
				4,
			))
		case 64:
			index := quant4Pulse(positions[:4], 4)
			out.indices[track] = int16((index >> 14) & 3)
			out.indices[track+codeTrackCount] = int16(index & 0x3fff)
		case 72:
			if track < 2 {
				index := quant5Pulse(positions[:5], 4)
				out.indices[track] = int16((index >> 10) & 0x03ff)
				out.indices[track+codeTrackCount] = int16(index & 0x03ff)
			} else {
				index := quant4Pulse(positions[:4], 4)
				out.indices[track] = int16((index >> 14) & 3)
				out.indices[track+codeTrackCount] = int16(index & 0x3fff)
			}
		case 88:
			index := quant6Pulse(positions[:], 4)
			out.indices[track] = int16((index >> 11) & 0x07ff)
			out.indices[track+codeTrackCount] = int16(index & 0x07ff)
		}
	}
	return out, nil
}

func filterCodeword(h []int16, code []int16) ([subframeSamples]int16, error) {
	var y [subframeSamples]int16
	if len(h) < subframeSamples || len(code) < subframeSamples {
		return y, errors.New("filter algebraic codeword: buffers are too short")
	}
	for i := range subframeSamples {
		var sum int16
		for pos, pulse := range code[:subframeSamples] {
			if pulse == 0 {
				continue
			}
			sign := int16(1)
			if pulse < 0 {
				sign = -1
			}
			sum = fxp.Add16(sum, filteredPulseSample(h, pos, sign, i))
		}
		y[i] = fxp.ShrRound16(sum, 3)
	}
	return y, nil
}

type acelp4t64Config struct {
	alpha      int16
	pulses     int
	iterations int
	nbpos      [10]int16
}

var acelp4t64TrackOrder = [...]int16{
	0, 1, 2, 3,
	1, 2, 3, 0,
	2, 3, 0, 1,
	3, 0, 1, 2,
	0, 1, 2, 3,
	1, 2, 3, 0,
	2, 3, 0, 1,
	3, 0, 1, 2,
	0, 1, 2, 3,
}

func acelp4t64SearchConfig(nbits int16, serialBits int16) (acelp4t64Config, bool) {
	switch nbits {
	case 20:
		return acelp4t64Config{alpha: 8192, pulses: 4, iterations: 4, nbpos: [10]int16{4, 8}}, true
	case 36:
		return acelp4t64Config{alpha: 4096, pulses: 8, iterations: 4, nbpos: [10]int16{4, 8, 8}}, true
	case 44:
		return acelp4t64Config{alpha: 4096, pulses: 10, iterations: 4, nbpos: [10]int16{4, 6, 8, 8}}, true
	case 52:
		return acelp4t64Config{alpha: 4096, pulses: 12, iterations: 4, nbpos: [10]int16{4, 6, 8, 8}}, true
	case 64:
		return acelp4t64Config{alpha: 3277, pulses: 16, iterations: 3, nbpos: [10]int16{4, 4, 6, 6, 8, 8}}, true
	case 72:
		return acelp4t64Config{alpha: 3072, pulses: 18, iterations: 3, nbpos: [10]int16{2, 3, 4, 5, 6, 7, 8}}, true
	case 88:
		iterations := 2
		if serialBits > 462 {
			iterations = 1
		}
		return acelp4t64Config{
			alpha:      2048,
			pulses:     24,
			iterations: iterations,
			nbpos:      [10]int16{2, 2, 3, 4, 5, 6, 7, 8, 8, 8},
		}, true
	default:
		return acelp4t64Config{}, false
	}
}

func codebookSearchSigns(
	dn []int16,
	cn []int16,
	alpha int16,
) ([subframeSamples]int16, [subframeSamples]int16, [subframeSamples]int16) {
	var sign [subframeSamples]int16
	var dnAbs [subframeSamples]int16
	var dnRank [subframeSamples]int16
	cnEnergy, exp := dotProduct12(cn, cn, subframeSamples)
	cnEnergy, exp = oneOverSqrtNorm(cnEnergy, exp)
	kCN := fxp.Round(fxp.Shl32(cnEnergy, exp+5))

	dnEnergy, exp := dotProduct12(dn, dn, subframeSamples)
	dnEnergy, exp = oneOverSqrtNorm(dnEnergy, exp)
	kDN := fxp.Round(fxp.Shl32(dnEnergy, exp+8))
	kDN = fxp.MultRound(alpha, kDN)
	for i := range subframeSamples {
		mixed := fxp.LMult(kCN, cn[i])
		mixed = fxp.LMac(mixed, kDN, dn[i])
		rank := fxp.ExtractH(fxp.Shl32(mixed, 8))
		dnAbs[i] = dn[i]
		if rank >= 0 {
			sign[i] = fxp.Max16
			dnRank[i] = rank
			continue
		}
		sign[i] = fxp.Min16
		dnAbs[i] = fxp.Neg16(dn[i])
		dnRank[i] = fxp.Neg16(rank)
	}
	return sign, dnAbs, dnRank
}

func codebookCandidateRanks(dnRank []int16) [codeTrackCount]int16 {
	var posMax [codeTrackCount]int16
	for track := range codeTrackCount {
		for rank := range 8 {
			bestScore := int16(-1)
			bestPos := track
			for pos := track; pos < subframeSamples; pos += codeTrackCount {
				if dnRank[pos] > bestScore {
					bestScore = dnRank[pos]
					bestPos = pos
				}
			}
			dnRank[bestPos] = int16(rank - 8)
			if rank == 0 {
				posMax[track] = int16(bestPos)
			}
		}
	}
	return posMax
}

func scaledImpulseResponse(h []int16, pulseCount int) ([subframeSamples]int16, int16) {
	var out [subframeSamples]int16
	var energy int32
	for i := range subframeSamples {
		energy = fxp.LMac(energy, h[i], h[i])
	}
	shift := int16(0)
	if pulseCount >= 12 && fxp.ExtractH(energy) > 1024 {
		shift = 1
	}
	if fxp.ExtractH(energy) > 0x6000 {
		shift = 2
	}
	for i := range subframeSamples {
		out[i] = fxp.Shr16(h[i], shift)
	}
	return out, shift
}

func impulseSelfCorrelations(h []int16) [codeTrackCount][acelp4TrackPositions]int16 {
	var out [codeTrackCount][acelp4TrackPositions]int16
	for track := range codeTrackCount {
		for slot := range acelp4TrackPositions {
			pos := track + slot*codeTrackCount
			acc := int32(0x8000)
			for i := range subframeSamples - pos {
				acc = fxp.LMac(acc, h[i], h[i])
			}
			out[track][slot] = fxp.ExtractH(acc)
		}
	}
	return out
}

func impulseCrossCorrelations(
	h []int16,
	sign []int16,
) [codeTrackCount][acelp4TrackPositions * acelp4TrackPositions]int16 {
	var out [codeTrackCount][acelp4TrackPositions * acelp4TrackPositions]int16
	for trackX := range codeTrackCount {
		trackY := (trackX + 1) & 3
		for xSlot := range acelp4TrackPositions {
			x := trackX + xSlot*codeTrackCount
			for ySlot := range acelp4TrackPositions {
				y := trackY + ySlot*codeTrackCount
				start := x
				start = max(start, y)

				acc := int32(0x8000)
				for i := start; i < subframeSamples; i++ {
					acc = fxp.LMac(acc, h[i-x], h[i-y])
				}
				corr := fxp.ExtractH(acc)
				if sign[x] < 0 {
					corr = fxp.Mult(corr, invertedCodebookSign(sign[y]))
				} else {
					corr = fxp.Mult(corr, sign[y])
				}
				out[trackX][xSlot*acelp4TrackPositions+ySlot] = corr
			}
		}
	}
	return out
}

func invertedCodebookSign(sign int16) int16 {
	if sign < 0 {
		return fxp.Max16
	}
	return fxp.Min16
}

func initialCodebookStage(
	nbits int16,
	ipos []int16,
	posMax []int16,
	dn []int16,
	sign []int16,
	h []int16,
	rrixix [codeTrackCount][acelp4TrackPositions]int16,
	rrixiy [codeTrackCount][acelp4TrackPositions * acelp4TrackPositions]int16,
	vec *[subframeSamples]int16,
) (int, int16, int16) {
	clear(vec[:])
	if nbits == 20 {
		return 0, 0, 0
	}
	if nbits == 36 || nbits == 44 {
		ix, iy := posMax[ipos[0]], posMax[ipos[1]]
		ps := fxp.Add16(dn[ix], dn[iy])
		i := ix >> 2
		j := iy >> 2
		acc := fxp.LMult(rrixix[ipos[0]][i], 4096)
		acc = fxp.LMac(acc, rrixix[ipos[1]][j], 4096)
		crossIndex := (i << 4) + j
		acc = fxp.LMac(acc, rrixiy[ipos[0]][crossIndex], 8192)
		addSignedImpulse(vec[:], h, int(ix), sign[ix])
		addSignedImpulse(vec[:], h, int(iy), sign[iy])
		return 2, ps, fxp.Round(acc)
	}
	ix, iy := posMax[ipos[0]], posMax[ipos[1]]
	iz, iw := posMax[ipos[2]], posMax[ipos[3]]
	ps := fxp.Add16(fxp.Add16(dn[ix], dn[iy]), fxp.Add16(dn[iz], dn[iw]))
	addSignedImpulse(vec[:], h, int(ix), sign[ix])
	addSignedImpulse(vec[:], h, int(iy), sign[iy])
	addSignedImpulse(vec[:], h, int(iz), sign[iz])
	addSignedImpulse(vec[:], h, int(iw), sign[iw])
	return 4, ps, vectorEnergy(vec[:])
}

func vectorEnergy(vec []int16) int16 {
	var acc int32
	for i := range subframeSamples {
		acc = fxp.LMac(acc, vec[i], vec[i])
	}
	return fxp.Round(fxp.Shr32(acc, 3))
}

func correlateFixedVector(
	h []int16,
	vec []int16,
	track int,
	sign []int16,
	self [codeTrackCount][acelp4TrackPositions]int16,
) ([acelp4TrackPositions]int16, [acelp4TrackPositions]int16) {
	var corX [acelp4TrackPositions]int16
	var corY [acelp4TrackPositions]int16
	trackY := (track + 1) & 3
	for slot := range acelp4TrackPositions {
		posX := track + slot*codeTrackCount
		posY := trackY + slot*codeTrackCount
		corX[slot] = fixedVectorCorrelation(h, vec, posX, sign[posX], self[track][slot])
		corY[slot] = fixedVectorCorrelation(h, vec, posY, sign[posY], self[trackY][slot])
	}
	return corX, corY
}

func fixedVectorCorrelation(h []int16, vec []int16, pos int, sign int16, self int16) int16 {
	var acc int32
	for i := pos; i < subframeSamples; i++ {
		acc = fxp.LMac(acc, h[i-pos], vec[i])
	}
	corr := fxp.Round(fxp.Shl32(acc, 1))
	return fxp.Add16(fxp.Mult(corr, sign), self)
}

type pulsePairSearch struct {
	x      int16
	y      int16
	ps     int16
	energy int16
}

func searchPulsePair(
	nbPosIX int16,
	trackX int,
	trackY int,
	ps int16,
	energy int16,
	dn []int16,
	dnRank []int16,
	corX []int16,
	corY []int16,
	cross [][acelp4TrackPositions * acelp4TrackPositions]int16,
) pulsePairSearch {
	threshold := nbPosIX - 8
	baseEnergy := (int32(energy) << 16) + 0x8000
	bestScore := int16(-1)
	bestEnergy := int16(1)
	bestX := int16(trackX)
	bestY := int16(trackY)
	for xSlot, x := 0, trackX; x < subframeSamples; xSlot, x = xSlot+1, x+codeTrackCount {
		if dnRank[x] >= threshold {
			continue
		}
		ps1 := fxp.Add16(ps, dn[x])
		energy1 := fxp.LMac(baseEnergy, corX[xSlot], 4096)
		for ySlot, y := 0, trackY; y < subframeSamples; ySlot, y = ySlot+1, y+codeTrackCount {
			ps2 := fxp.Add16(ps1, dn[y])
			energy2 := fxp.LMac(energy1, corY[ySlot], 4096)
			energy2 = fxp.LMac(energy2, cross[trackX][xSlot*acelp4TrackPositions+ySlot], 8192)
			energy16 := fxp.ExtractH(energy2)
			score := fxp.Mult(ps2, ps2)
			diff := fxp.Sub32(fxp.LMult(bestEnergy, score), fxp.LMult(bestScore, energy16))
			if diff > 0 {
				bestScore = score
				bestEnergy = energy16
				bestX = int16(x)
				bestY = int16(y)
			}
		}
	}
	return pulsePairSearch{
		x:      bestX,
		y:      bestY,
		ps:     fxp.Add16(ps, fxp.Add16(dn[bestX], dn[bestY])),
		energy: bestEnergy,
	}
}

func addSignedImpulse(vec []int16, h []int16, pos int, sign int16) {
	for i := pos; i < subframeSamples; i++ {
		value := h[i-pos]
		if sign < 0 {
			value = fxp.Neg16(value)
		}
		vec[i] = fxp.Add16(vec[i], value)
	}
}

func quant1Pulse(pos int, n int) int32 {
	mask := (1 << n) - 1
	index := int32(pos & mask)
	if pos&acelp4TrackPositions != 0 {
		index += int32(1 << n)
	}
	return index
}

func quant2Pulse(pos1 int, pos2 int, n int) int32 {
	mask := (1 << n) - 1
	signBit := 1 << (2 * n)
	sameSign := ((pos2 ^ pos1) & acelp4TrackPositions) == 0
	if sameSign {
		first := pos1
		second := pos2
		if first > second {
			first, second = second, first
		}
		index := int32(((first & mask) << n) + (second & mask))
		if pos1&acelp4TrackPositions != 0 {
			index += int32(signBit)
		}
		return index
	}

	first := pos2
	second := pos1
	if (pos1 & mask) > (pos2 & mask) {
		first = pos1
		second = pos2
	}
	index := int32(((first & mask) << n) + (second & mask))
	if first&acelp4TrackPositions != 0 {
		index += int32(signBit)
	}
	return index
}

func quant3Pulse(pos1 int, pos2 int, pos3 int, n int) int32 {
	nbPos := 1 << (n - 1)
	switch {
	case ((pos1 ^ pos2) & nbPos) == 0:
		index := quant2Pulse(pos1, pos2, n-1)
		index += int32(pos1&nbPos) << n
		index += quant1Pulse(pos3, n) << (2 * n)
		return index
	case ((pos1 ^ pos3) & nbPos) == 0:
		index := quant2Pulse(pos1, pos3, n-1)
		index += int32(pos1&nbPos) << n
		index += quant1Pulse(pos2, n) << (2 * n)
		return index
	default:
		index := quant2Pulse(pos2, pos3, n-1)
		index += int32(pos2&nbPos) << n
		index += quant1Pulse(pos1, n) << (2 * n)
		return index
	}
}

func quant4PulseN1(pos1 int, pos2 int, pos3 int, pos4 int, n int) int32 {
	nbPos := 1 << (n - 1)
	switch {
	case ((pos1 ^ pos2) & nbPos) == 0:
		index := quant2Pulse(pos1, pos2, n-1)
		index += int32(pos1&nbPos) << n
		index += quant2Pulse(pos3, pos4, n) << (2 * n)
		return index
	case ((pos1 ^ pos3) & nbPos) == 0:
		index := quant2Pulse(pos1, pos3, n-1)
		index += int32(pos1&nbPos) << n
		index += quant2Pulse(pos2, pos4, n) << (2 * n)
		return index
	default:
		index := quant2Pulse(pos2, pos3, n-1)
		index += int32(pos2&nbPos) << n
		index += quant2Pulse(pos1, pos4, n) << (2 * n)
		return index
	}
}

func quant4Pulse(pos []int, n int) int32 {
	n1 := n - 1
	nbPos := 1 << n1
	var posA [4]int
	var posB [4]int
	countA := 0
	countB := 0
	for i := range 4 {
		if pos[i]&nbPos == 0 {
			posA[countA] = pos[i]
			countA++
		} else {
			posB[countB] = pos[i]
			countB++
		}
	}

	var index int32
	switch countA {
	case 0:
		index = 1 << ((4 * n) - 3)
		index += quant4PulseN1(posB[0], posB[1], posB[2], posB[3], n1)
	case 1:
		index = quant1Pulse(posA[0], n1) << ((3 * n1) + 1)
		index += quant3Pulse(posB[0], posB[1], posB[2], n1)
	case 2:
		index = quant2Pulse(posA[0], posA[1], n1) << ((2 * n1) + 1)
		index += quant2Pulse(posB[0], posB[1], n1)
	case 3:
		index = quant3Pulse(posA[0], posA[1], posA[2], n1) << n
		index += quant1Pulse(posB[0], n1)
	case 4:
		index = quant4PulseN1(posA[0], posA[1], posA[2], posA[3], n1)
	}
	index += int32(countA&3) << ((4 * n) - 2)
	return index
}

func quant5Pulse(pos []int, n int) int32 {
	n1 := n - 1
	nbPos := 1 << n1
	var posA [5]int
	var posB [5]int
	countA := 0
	countB := 0
	for i := range 5 {
		if pos[i]&nbPos == 0 {
			posA[countA] = pos[i]
			countA++
		} else {
			posB[countB] = pos[i]
			countB++
		}
	}

	switch countA {
	case 0:
		return (1 << ((5 * n) - 1)) +
			(quant3Pulse(posB[0], posB[1], posB[2], n1) << ((2 * n) + 1)) +
			quant2Pulse(posB[3], posB[4], n)
	case 1:
		return (1 << ((5 * n) - 1)) +
			(quant3Pulse(posB[0], posB[1], posB[2], n1) << ((2 * n) + 1)) +
			quant2Pulse(posB[3], posA[0], n)
	case 2:
		return (1 << ((5 * n) - 1)) +
			(quant3Pulse(posB[0], posB[1], posB[2], n1) << ((2 * n) + 1)) +
			quant2Pulse(posA[0], posA[1], n)
	case 3:
		return (quant3Pulse(posA[0], posA[1], posA[2], n1) << ((2 * n) + 1)) +
			quant2Pulse(posB[0], posB[1], n)
	case 4:
		return (quant3Pulse(posA[0], posA[1], posA[2], n1) << ((2 * n) + 1)) +
			quant2Pulse(posA[3], posB[0], n)
	case 5:
		return (quant3Pulse(posA[0], posA[1], posA[2], n1) << ((2 * n) + 1)) +
			quant2Pulse(posA[3], posA[4], n)
	default:
		return 0
	}
}

func quant6Pulse(pos []int, n int) int32 {
	n1 := n - 1
	nbPos := 1 << n1
	var posA [6]int
	var posB [6]int
	countA := 0
	countB := 0
	for i := range 6 {
		if pos[i]&nbPos == 0 {
			posA[countA] = pos[i]
			countA++
		} else {
			posB[countB] = pos[i]
			countB++
		}
	}

	group := countA
	var index int32
	switch countA {
	case 0:
		index = 1 << ((6 * n) - 5)
		index += quant5Pulse(posB[:], n1) << n
		index += quant1Pulse(posB[5], n1)
	case 1:
		index = 1 << ((6 * n) - 5)
		index += quant5Pulse(posB[:], n1) << n
		index += quant1Pulse(posA[0], n1)
	case 2:
		index = 1 << ((6 * n) - 5)
		index += quant4Pulse(posB[:], n1) << ((2 * n1) + 1)
		index += quant2Pulse(posA[0], posA[1], n1)
	case 3:
		index = quant3Pulse(posA[0], posA[1], posA[2], n1) << ((3 * n1) + 1)
		index += quant3Pulse(posB[0], posB[1], posB[2], n1)
	case 4:
		group = 2
		index = quant4Pulse(posA[:], n1) << ((2 * n1) + 1)
		index += quant2Pulse(posB[0], posB[1], n1)
	case 5:
		group = 1
		index = quant5Pulse(posA[:], n1) << n
		index += quant1Pulse(posB[0], n1)
	case 6:
		group = 0
		index = quant5Pulse(posA[:], n1) << n
		index += quant1Pulse(posA[5], n1)
	}
	index += int32(group&3) << ((6 * n) - 4)
	return index
}

func filteredPulseSample(h []int16, pos int, sign int16, sample int) int16 {
	if sample < pos {
		return 0
	}
	value := h[sample-pos]
	if sign < 0 {
		return fxp.Neg16(value)
	}
	return value
}
