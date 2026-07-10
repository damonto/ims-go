/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * This encoder LPC analysis flow follows amrwbenc/src/voAMRWBEnc.c.
 */

package amrwb

import (
	"errors"
	"fmt"
)

type encoderLPCState struct {
	levinson encoderLevinsonState
	ispOld   [lpcOrder]int16
}

type encoderLPCAnalysis struct {
	rc     [lpcOrder]int16
	ispNew [lpcOrder]int16
	a      [4 * lpcCoeffCount]int16
}

func (s *encoderLPCState) reset() {
	s.levinson.reset()
	copy(s.ispOld[:], initialISP[:])
}

func (s *encoderLPCState) analyze(oldSpeech []int16, speech12k8 []int16) (encoderLPCAnalysis, error) {
	var out encoderLPCAnalysis
	if len(oldSpeech) < encoderOldSpeechSamples || len(speech12k8) < frameSamples12k8+lpcLookahead12k8 {
		return out, errors.New("analyze LPC: buffers are too short")
	}

	var window [lpcWindowSamples]int16
	const lpcHistorySamples = encoderOldSpeechSamples - lpcLookahead12k8
	copy(window[:lpcHistorySamples], oldSpeech[:lpcHistorySamples])
	copy(window[lpcHistorySamples:], speech12k8[:frameSamples12k8+lpcLookahead12k8])

	corr, err := encoderAutocorrelation(window[:], encoderLPCWindow[:])
	if err != nil {
		return out, fmt.Errorf("analyze LPC: %w", err)
	}
	rh, rl := encoderLagWindow(corr.rh, corr.rl)
	levinson, err := s.levinson.levinson(rh[:], rl[:])
	if err != nil {
		return out, fmt.Errorf("analyze LPC: %w", err)
	}
	out.rc = levinson.rc
	out.ispNew, err = encoderAzToISP(levinson.a[:], s.ispOld[:])
	if err != nil {
		return out, fmt.Errorf("analyze LPC: %w", err)
	}
	out.a, err = interpolateISP(s.ispOld[:], out.ispNew[:])
	if err != nil {
		return out, fmt.Errorf("analyze LPC: %w", err)
	}
	copy(s.ispOld[:], out.ispNew[:])
	return out, nil
}

func updateEncoderOldSpeech(oldSpeech []int16, speech12k8 []int16) error {
	if len(oldSpeech) < encoderOldSpeechSamples || len(speech12k8) < frameSamples12k8+lpcLookahead12k8 {
		return errors.New("old speech buffers are too short")
	}
	copy(oldSpeech[:encoderOldSpeechSamples], speech12k8[frameSamples12k8-encoderOldSpeechSamples+lpcLookahead12k8:frameSamples12k8+lpcLookahead12k8])
	return nil
}
