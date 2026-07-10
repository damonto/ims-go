/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This frame synthesis flow follows amr_wb/dec/src/synthesis_amr_wb.cpp.
 */

package amrwb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const subframeSamples16k = 80

func (s *decoderCoreState) synthesize(
	aq []int16,
	exc []int16,
	qNew int16,
	synth16k []int16,
	corrGain int16,
	hfISF []int16,
	mode Mode,
	dtxState dtxStateType,
	badFrame bool,
) (int, error) {
	if len(aq) < lpcCoeffCount || len(exc) < subframeSamples || len(synth16k) < subframeSamples16k {
		return 0, errors.New("synthesize AMR-WB subframe: buffers are too short")
	}
	if mode <= Mode660 && dtxState == dtxStateSpeech && len(hfISF) < lpcOrder {
		return 0, errors.New("synthesize AMR-WB subframe: high-band ISF buffer is too short")
	}

	var low12k8 [subframeSamples]int16
	filtered, err := synthesisFilter32(aq, exc[:subframeSamples], qNew, s.memSynHi, s.memSynLo)
	if err != nil {
		return 0, fmt.Errorf("synthesize AMR-WB subframe: %w", err)
	}
	s.memSynHi = filtered.memoryHigh
	s.memSynLo = filtered.memoryLow

	deemphasized := deemphasis32(filtered.high, filtered.low, deemphasisFactor, s.memDeemph)
	low12k8 = deemphasized.signal
	s.memDeemph = deemphasized.memory
	s.memSigOut = highpass50HzAt12k8(low12k8[:], s.memSigOut)
	oversampled := oversample12k8To16k(low12k8, s.memOversmp)
	copy(synth16k[:subframeSamples16k], oversampled.signal[:])
	s.memOversmp = oversampled.memory

	hf, seed := generateHFNoise(s.seed2)
	s.seed2 = seed
	hf, err = scaleHFNoiseToExcitation(hf, exc, qNew)
	if err != nil {
		return 0, fmt.Errorf("synthesize AMR-WB subframe: %w", err)
	}

	tilt := hfGainFromTilt(low12k8, s.memHP400, s.vadHist)
	s.memHP400 = tilt.memory
	if mode == Mode2385 && !badFrame {
		if err := applyHFCorrectionGain(hf[:], corrGain); err != nil {
			return 0, fmt.Errorf("synthesize AMR-WB subframe: %w", err)
		}
	} else {
		applyHFGain(hf[:], tilt.gain)
	}

	if mode <= Mode660 && dtxState == dtxStateSpeech {
		hfISP, err := isfExtrapolation(hfISF)
		if err != nil {
			return 0, fmt.Errorf("synthesize AMR-WB subframe: %w", err)
		}
		hfAz, err := ispToAzOrder(hfISP[:], lpcOrder16k, false)
		if err != nil {
			return 0, fmt.Errorf("synthesize AMR-WB subframe: %w", err)
		}
		weighted, err := weightLPCOrder(hfAz[:], 29491, lpcOrder16k)
		if err != nil {
			return 0, fmt.Errorf("synthesize AMR-WB subframe: %w", err)
		}
		filtered, err := wbSynthesisFilter(weighted[:], hf[:], s.memSynHF[:])
		if err != nil {
			return 0, fmt.Errorf("synthesize AMR-WB subframe: %w", err)
		}
		hf = filtered.signal
		copy(s.memSynHF[:], filtered.memory[:])
	} else {
		weighted, err := weightLPC(aq, 19661)
		if err != nil {
			return 0, fmt.Errorf("synthesize AMR-WB subframe: %w", err)
		}
		filtered, err := wbSynthesisFilter(weighted[:], hf[:], s.memSynHF[lpcOrder16k-lpcOrder:])
		if err != nil {
			return 0, fmt.Errorf("synthesize AMR-WB subframe: %w", err)
		}
		hf = filtered.signal
		copy(s.memSynHF[lpcOrder16k-lpcOrder:], filtered.memory[:lpcOrder])
	}

	filteredHF := bandPass6k7k(hf, s.memHF)
	hf = filteredHF.signal
	s.memHF = filteredHF.memory
	if mode == Mode2385 {
		filteredHF = lowPass7k(hf, s.memHF3)
		hf = filteredHF.signal
		s.memHF3 = filteredHF.memory
	}
	for i := range subframeSamples16k {
		synth16k[i] = fxp.Add16(synth16k[i], hf[i])
	}
	return subframeSamples16k, nil
}
