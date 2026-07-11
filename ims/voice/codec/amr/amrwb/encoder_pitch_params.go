package amrwb

type encodedPitchLag struct {
	index   int16
	width   int
	state   pitchLagState
	pitFlag int16
}

func initialPitchLagState(tOp int16) pitchLagState {
	return pitchSearchRange(tOp)
}

type subframePitchLagInput struct {
	mode     Mode
	subframe int
	openLoop int16
	lag      int16
	fraction int16
	state    pitchLagState
}

func encodeSubframePitchLag(in subframePitchLagInput) encodedPitchLag {
	pitFlag, state := subframePitchSearchState(in.mode, in.subframe, in.openLoop, in.state)

	nbits := nBits1265
	width := 9
	if in.mode <= Mode885 {
		nbits = nBits885
		width = 8
	}
	if pitFlag != 0 {
		if in.mode <= Mode885 {
			width = 5
		} else {
			width = 6
		}
	}

	index, next := encodePitchLag(in.lag, in.fraction, nbits, pitFlag, state)
	return encodedPitchLag{
		index:   index,
		width:   width,
		state:   next,
		pitFlag: pitFlag,
	}
}

func subframePitchSearchState(mode Mode, subframe int, tOp2 int16, state pitchLagState) (int16, pitchLagState) {
	pitFlag := int16(subframeSamples * subframe)
	if subframe == 2 && mode > Mode660 {
		return 0, pitchSearchRange(tOp2)
	}
	return pitFlag, state
}
