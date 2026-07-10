/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This code is ported from amr_nb/dec/src/d_plsf.cpp,
 * d_plsf_3.cpp, q_plsf_3_tbl.cpp, and common/src/reorder.cpp.
 */

package amrnb

const lsfGap int16 = 205

var pastRQInit = [...]int16{
	-258, -318, -439, -634, -656, -773, -711, -502, -268, -193,
	-2, 125, 122, -39, -9, 105, 129, 283, 372, 575,
	-277, -324, -197, -487, -445, -362, -292, -27, 177, 543,
	342, 517, 516, 130, 27, -104, -120, -140, -74, -56,
	-564, -943, -1520, -965, -814, -526, -322, -2, 159, 657,
	-312, -284, -386, -597, -493, -526, -418, -229, 105, 449,
	-557, -870, -1075, -919, -950, -752, -709, -316, 62, 486,
	-314, -191, -203, -330, -160, -103, -51, 131, 338, 515,
}

type dPLSFState struct {
	pastRQ   [lpcOrder]int16
	pastLSFQ [lpcOrder]int16
}

func newDPLSFState() dPLSFState {
	var state dPLSFState
	state.reset()
	return state
}

func (s *dPLSFState) reset() {
	clear(s.pastRQ[:])
	copy(s.pastLSFQ[:], meanLSF5[:])
}

func (s *dPLSFState) initFromPastRQ(index int16) {
	index = min(max(index, 0), 7)

	offset := int(index) * lpcOrder
	copy(s.pastRQ[:], pastRQInit[offset:offset+lpcOrder])
}

func reorderLSF(lsf []int16, minDistance int16) {
	lsfMin := minDistance
	for i := range lpcOrder {
		lsf[i] = max(lsf[i], lsfMin)
		lsfMin = lsf[i] + minDistance
	}
}
