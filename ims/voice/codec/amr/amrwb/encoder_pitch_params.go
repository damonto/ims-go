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

func encodeSubframePitchLag(mode Mode, subframe int, tOp2 int16, t0 int16, t0Frac int16, state pitchLagState) encodedPitchLag {
	pitFlag, state := subframePitchSearchState(mode, subframe, tOp2, state)

	nbits := nBits1265
	width := 9
	if mode <= Mode885 {
		nbits = nBits885
		width = 8
	}
	if pitFlag != 0 {
		if mode <= Mode885 {
			width = 5
		} else {
			width = 6
		}
	}

	index, next := encodePitchLag(t0, t0Frac, nbits, pitFlag, state)
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
