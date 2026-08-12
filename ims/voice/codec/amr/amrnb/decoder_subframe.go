package amrnb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

type decodedSubframe struct {
	samples  []int16
	t0       int16
	t0Frac   int16
	gainPit  int16
	gainCode int16
}

type decodeGoodSubframeInput struct {
	mode             Mode
	subframe         int
	params           []int16
	dst              []int16
	badFrame         bool
	potentialDegrade bool
	lsfForCBGain     []int16
}

func (s *decoderCoreState) decodeGoodSubframe(in decodeGoodSubframeInput) (int, decodedSubframe, error) {
	if in.subframe < 0 || in.subframe > 3 {
		return 0, decodedSubframe{}, fmt.Errorf("AMR-NB subframe %d outside 0..3", in.subframe)
	}
	if len(in.params) == 0 {
		return 0, decodedSubframe{}, errors.New("AMR-NB subframe has no pitch parameter")
	}

	consumed := 0
	pitchIndex := in.params[consumed]
	consumed++

	t0, t0Frac, err := s.decodeSubframePitch(in.mode, in.subframe, pitchIndex, in.badFrame)
	if err != nil {
		return 0, decodedSubframe{}, err
	}

	fixed, err := s.decodeSubframeFixed(in.mode, in.subframe, in.params[consumed:], in.badFrame)
	if err != nil {
		return 0, decodedSubframe{}, err
	}
	consumed += fixed.consumed

	addPitchContribution(s.code[:], t0, fixed.pitchSharpness)

	evenSubfr := int16(0)
	if in.subframe%2 == 0 {
		evenSubfr = 1
	}
	gain, err := s.decodeSubframeGain(decodeSubframeGainInput{
		mode:     in.mode,
		even:     evenSubfr,
		gainPit:  fixed.pitchGain,
		params:   in.params[consumed:],
		badFrame: in.badFrame,
		code:     s.code[:],
	})
	if err != nil {
		return 0, decodedSubframe{}, err
	}
	consumed += gain.consumed
	gainPit, gainCode := gain.pitch, gain.code

	gainPit, gainCode = s.updateSubframeGains(in.badFrame, gainPit, gainCode)
	gainPit = s.limitBackgroundPitchGain(in.mode, gainPit, in.badFrame)
	gainCodeMix := gainCode
	if in.lsfForCBGain != nil {
		gainCodeMix = s.mixSubframeCodeGain(in.mode, gainCode, in.lsfForCBGain, in.badFrame, in.potentialDegrade)
	}
	s.updateSharp(in.mode, evenSubfr, gainPit)
	if !in.badFrame {
		s.pushLTPGain(gainPit)
	}
	samples := s.synthesizeCurrentSubframe(in.subframe, s.code[:], gainPit, gainCode, gainCodeMix, in.mode, in.dst)
	s.oldT0 = t0

	return consumed, decodedSubframe{
		samples:  samples,
		t0:       t0,
		t0Frac:   t0Frac,
		gainPit:  gainPit,
		gainCode: gainCode,
	}, nil
}

func (s *decoderCoreState) decodeSubframePitch(mode Mode, subframe int, index int16, badFrame bool) (t0, t0Frac int16, err error) {
	pitFlag := int16(subframe * subframeSamples)
	if subframe == 2 && mode != Mode475 && mode != Mode515 {
		pitFlag = 0
	}

	if mode == Mode1220 {
		t0, t0Frac = decodeLag6(index, pitchMinMR122, pitchMax, pitFlag, s.oldT0)
		if badFrame || (pitFlag != 0 && index >= 61) {
			s.t0LagBuff = t0
			t0 = s.oldT0
			t0Frac = 0
		}
		err = s.predictPitch(t0, t0Frac, false)
		return t0, t0Frac, err
	}

	deltaLow := int16(5)
	deltaRange := int16(9)
	if mode == Mode795 {
		deltaLow = 10
		deltaRange = 19
	}
	t0Min := s.oldT0 - deltaLow

	t0Min = max(t0Min, pitchMin)

	t0Max := t0Min + deltaRange
	if t0Max > pitchMax {
		t0Max = pitchMax
		t0Min = t0Max - deltaRange
	}
	flag4 := mode == Mode475 || mode == Mode515 || mode == Mode590 || mode == Mode670
	t0, t0Frac = decodeLag3(index, t0Min, t0Max, pitFlag, s.oldT0, flag4)
	s.t0LagBuff = t0
	if badFrame {
		if s.oldT0 < pitchMax {
			s.oldT0++
		}
		t0 = s.oldT0
		t0Frac = 0
		if s.inBackgroundNoise &&
			s.voicedHangover > 4 &&
			(mode == Mode475 || mode == Mode515 || mode == Mode590) {
			t0 = s.t0LagBuff
		}
	}
	err = s.predictPitch(t0, t0Frac, true)
	return t0, t0Frac, err
}

type decodedFixedCodebook struct {
	pitchSharpness int16
	pitchGain      int16
	consumed       int
}

func (s *decoderCoreState) decodeSubframeFixed(mode Mode, subframe int, params []int16, badFrame bool) (decodedFixedCodebook, error) {
	switch mode {
	case Mode475, Mode515:
		if len(params) < 2 {
			return decodedFixedCodebook{}, fmt.Errorf("AMR-NB fixed codebook needs 2 params for mode %d", mode)
		}
		s.decodeFixed2I40At9Bits(int16(subframe), params[1], params[0])
		return decodedFixedCodebook{pitchSharpness: fxp.Shl16(s.sharp, 1), consumed: 2}, nil
	case Mode590:
		if len(params) < 2 {
			return decodedFixedCodebook{}, fmt.Errorf("AMR-NB fixed codebook needs 2 params for mode %d", mode)
		}
		s.decodeFixed2I40At11Bits(params[1], params[0])
		return decodedFixedCodebook{pitchSharpness: fxp.Shl16(s.sharp, 1), consumed: 2}, nil
	case Mode670:
		if len(params) < 2 {
			return decodedFixedCodebook{}, fmt.Errorf("AMR-NB fixed codebook needs 2 params for mode %d", mode)
		}
		s.decodeFixed3I40At14Bits(params[1], params[0])
		return decodedFixedCodebook{pitchSharpness: fxp.Shl16(s.sharp, 1), consumed: 2}, nil
	case Mode740, Mode795:
		if len(params) < 2 {
			return decodedFixedCodebook{}, fmt.Errorf("AMR-NB fixed codebook needs 2 params for mode %d", mode)
		}
		s.decodeFixed4I40At17Bits(params[1], params[0])
		return decodedFixedCodebook{pitchSharpness: fxp.Shl16(s.sharp, 1), consumed: 2}, nil
	case Mode1020:
		if len(params) < 7 {
			return decodedFixedCodebook{}, errors.New("AMR-NB MR102 fixed codebook needs 7 params")
		}
		s.decodeFixed8I40At31Bits(params[:7])
		return decodedFixedCodebook{pitchSharpness: fxp.Shl16(s.sharp, 1), consumed: 7}, nil
	case Mode1220:
		if len(params) < 11 {
			return decodedFixedCodebook{}, errors.New("AMR-NB MR122 fixed codebook needs 11 params")
		}
		var gainPit int16
		if badFrame {
			gainPit = s.ecGainPitch.conceal(s.state)
		} else {
			gainPit = dGainPitch(mode, params[0])
		}
		s.decodeFixed10I40At35Bits(params[1:11])
		return decodedFixedCodebook{pitchSharpness: fxp.Shl16(gainPit, 1), pitchGain: gainPit, consumed: 11}, nil
	default:
		return decodedFixedCodebook{}, fmt.Errorf("AMR-NB fixed codebook mode %d is not supported", mode)
	}
}

type decodeSubframeGainInput struct {
	mode     Mode
	even     int16
	gainPit  int16
	params   []int16
	badFrame bool
	code     []int16
}

type decodedSubframeGain struct {
	pitch    int16
	code     int16
	consumed int
}

func (s *decoderCoreState) decodeSubframeGain(in decodeSubframeGainInput) (decodedSubframeGain, error) {
	switch {
	case in.mode == Mode475:
		consumed := 0
		if in.even != 0 {
			if len(in.params) < 1 {
				return decodedSubframeGain{}, errors.New("AMR-NB MR475 gain needs index on even subframe")
			}
			s.gainIndexMR475 = in.params[0]
			consumed = 1
		}
		if in.badFrame {
			return decodedSubframeGain{pitch: s.ecGainPitch.conceal(s.state), code: s.ecGainCode.conceal(&s.predState, s.state), consumed: consumed}, nil
		}
		gp, gc := decGain(&s.predState, in.mode, s.gainIndexMR475, in.code, in.even)
		return decodedSubframeGain{pitch: gp, code: gc, consumed: consumed}, nil
	case in.mode <= Mode740 || in.mode == Mode1020:
		if len(in.params) < 1 {
			return decodedSubframeGain{}, fmt.Errorf("AMR-NB gain needs 1 param for mode %d", in.mode)
		}
		if in.badFrame {
			return decodedSubframeGain{pitch: s.ecGainPitch.conceal(s.state), code: s.ecGainCode.conceal(&s.predState, s.state), consumed: 1}, nil
		}
		gp, gc := decGain(&s.predState, in.mode, in.params[0], in.code, in.even)
		return decodedSubframeGain{pitch: gp, code: gc, consumed: 1}, nil
	case in.mode == Mode795:
		if len(in.params) < 2 {
			return decodedSubframeGain{}, errors.New("AMR-NB MR795 gain needs 2 params")
		}
		if in.badFrame {
			return decodedSubframeGain{pitch: s.ecGainPitch.conceal(s.state), code: s.ecGainCode.conceal(&s.predState, s.state), consumed: 2}, nil
		}
		gp := dGainPitch(in.mode, in.params[0])
		gc := dGainCode(&s.predState, in.mode, in.params[1], in.code)
		return decodedSubframeGain{pitch: gp, code: gc, consumed: 2}, nil
	case in.mode == Mode1220:
		if len(in.params) < 1 {
			return decodedSubframeGain{}, errors.New("AMR-NB MR122 code gain needs 1 param")
		}
		if in.badFrame {
			return decodedSubframeGain{pitch: in.gainPit, code: s.ecGainCode.conceal(&s.predState, s.state), consumed: 1}, nil
		}
		gc := dGainCode(&s.predState, in.mode, in.params[0], in.code)
		return decodedSubframeGain{pitch: in.gainPit, code: gc, consumed: 1}, nil
	default:
		return decodedSubframeGain{}, fmt.Errorf("AMR-NB gain mode %d is not supported", in.mode)
	}
}

func (s *decoderCoreState) updateSubframeGains(badFrame bool, gainPit, gainCode int16) (int16, int16) {
	gainPit = s.ecGainPitch.update(badFrame, s.prevBF, gainPit)
	gainCode = s.ecGainCode.update(badFrame, s.prevBF, gainCode)
	return gainPit, gainCode
}

func (s *decoderCoreState) mixSubframeCodeGain(mode Mode, gainCode int16, lsf []int16, badFrame, potentialDegrade bool) int16 {
	return s.cbGainAvg.average(cbGainAverageInput{
		mode:              mode,
		gainCode:          gainCode,
		lsf:               lsf,
		lsfAverage:        s.lspAvg.meanSave[:],
		badFrame:          badFrame,
		previousBadFrame:  s.prevBF,
		potentialDegrade:  potentialDegrade,
		previousDegrade:   s.prevPDF,
		inBackgroundNoise: s.inBackgroundNoise,
		voicedHangover:    s.voicedHangover,
	})
}

func (s *decoderCoreState) limitBackgroundPitchGain(mode Mode, gainPit int16, badFrame bool) int16 {
	if !s.prevBF && !badFrame {
		return gainPit
	}
	if !s.inBackgroundNoise || (mode != Mode475 && mode != Mode515 && mode != Mode590) {
		return gainPit
	}
	if gainPit > 12288 {
		gainPit = ((gainPit - 12288) >> 1) + 12288
	}
	if gainPit > 14745 {
		gainPit = 14745
	}
	return gainPit
}

func (s *decoderCoreState) updateSharp(mode Mode, evenSubfr int16, gainPit int16) {
	if mode == Mode475 && evenSubfr != 0 {
		return
	}
	s.sharp = gainPit

	s.sharp = min(s.sharp, sharpMax)
}

func (s *decoderCoreState) pushLTPGain(gainPit int16) {
	copy(s.ltpGainHistory[:ltpGainHistoryLen-1], s.ltpGainHistory[1:])
	s.ltpGainHistory[ltpGainHistoryLen-1] = gainPit
}
