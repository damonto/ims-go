package amrwb

import "testing"

func TestDecodeISF46GoodFrame(t *testing.T) {
	var past [lpcOrder]int16
	var old [lpcOrder]int16
	var buf [meanISFBufferSize * lpcOrder]int16
	copy(old[:], initialISF[:])
	copy(buf[:lpcOrder], initialISF[:])

	decoder := isfDecodeState{pastResidual: past[:], history: buf[:]}
	isf, err := decoder.decode46([]int16{0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.Fatalf("decode46() error = %v", err)
	}

	if isf[0] != 1646 {
		t.Fatalf("isf[0] = %d, want 1646", isf[0])
	}
	if isf[1] != 2816 {
		t.Fatalf("isf[1] = %d, want 2816", isf[1])
	}
	if past[0] != 908 {
		t.Fatalf("past[0] = %d, want residual 908", past[0])
	}
	if buf[0] != isf[0] {
		t.Fatalf("buf[0] = %d, want newest isf %d", buf[0], isf[0])
	}
}

func TestDecodeISF36GoodFrame(t *testing.T) {
	var past [lpcOrder]int16
	var old [lpcOrder]int16
	var buf [meanISFBufferSize * lpcOrder]int16
	copy(old[:], initialISF[:])

	decoder := isfDecodeState{pastResidual: past[:]}
	isf, err := decoder.decode36([]int16{0, 0, 0, 0, 0})
	if err != nil {
		t.Fatalf("decode36() error = %v", err)
	}

	if isf[0] != 1265 {
		t.Fatalf("isf[0] = %d, want 1265", isf[0])
	}
	if past[0] != 527 {
		t.Fatalf("past[0] = %d, want residual 527", past[0])
	}
	if buf[0] != 0 {
		t.Fatalf("buf[0] = %d, want unchanged buffer", buf[0])
	}
}

func TestDecodeISFBadFrameMovesTowardReference(t *testing.T) {
	var past [lpcOrder]int16
	var old [lpcOrder]int16
	var buf [meanISFBufferSize * lpcOrder]int16
	for i := range meanISFBufferSize {
		copy(buf[i*lpcOrder:(i+1)*lpcOrder], initialISF[:])
	}
	copy(old[:], initialISF[:])
	past[0] = 300

	decoder := isfDecodeState{pastResidual: past[:], history: buf[:]}
	isf, err := decoder.conceal(old[:])
	if err != nil {
		t.Fatalf("conceal() error = %v", err)
	}

	if isf[0] >= initialISF[0] {
		t.Fatalf("isf[0] = %d, want shift below old value %d", isf[0], initialISF[0])
	}
	if past[0] == 300 {
		t.Fatal("past residual did not update on bad frame")
	}
}

func TestISFDecodeRejectsInvalidBuffersWithoutWrites(t *testing.T) {
	tests := []struct {
		name         string
		pastSize     int
		historySize  int
		previousSize int
		withHistory  bool
		run          func(state isfDecodeState, previous []int16) ([lpcOrder]int16, error)
	}{
		{
			name:         "short indices",
			pastSize:     lpcOrder,
			previousSize: lpcOrder,
			run: func(state isfDecodeState, _ []int16) ([lpcOrder]int16, error) {
				return state.decode46(make([]int16, 6))
			},
		},
		{
			name:         "negative index",
			pastSize:     lpcOrder,
			previousSize: lpcOrder,
			run: func(state isfDecodeState, _ []int16) ([lpcOrder]int16, error) {
				indices := [7]int16{-1}
				return state.decode46(indices[:])
			},
		},
		{
			name:         "index above codebook",
			pastSize:     lpcOrder,
			previousSize: lpcOrder,
			run: func(state isfDecodeState, _ []int16) ([lpcOrder]int16, error) {
				indices := [5]int16{int16(len(dico1Isf) / 9)}
				return state.decode36(indices[:])
			},
		},
		{
			name:         "short residual history",
			pastSize:     lpcOrder - 1,
			previousSize: lpcOrder,
			run: func(state isfDecodeState, _ []int16) ([lpcOrder]int16, error) {
				return state.decode46(make([]int16, 7))
			},
		},
		{
			name:         "short ISF history",
			pastSize:     lpcOrder,
			historySize:  meanISFBufferSize*lpcOrder - 1,
			previousSize: lpcOrder,
			withHistory:  true,
			run: func(state isfDecodeState, _ []int16) ([lpcOrder]int16, error) {
				return state.decode46(make([]int16, 7))
			},
		},
		{
			name:         "short previous ISF",
			pastSize:     lpcOrder,
			historySize:  meanISFBufferSize * lpcOrder,
			previousSize: lpcOrder - 1,
			withHistory:  true,
			run: func(state isfDecodeState, previous []int16) ([lpcOrder]int16, error) {
				return state.conceal(previous)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var past [lpcOrder]int16
			var history [meanISFBufferSize * lpcOrder]int16
			var previous [lpcOrder]int16
			past[0], history[0], previous[0] = 22, 33, 44
			state := isfDecodeState{pastResidual: past[:tt.pastSize]}
			if tt.withHistory {
				state.history = history[:tt.historySize]
			}
			pastBefore := past
			historyBefore := history

			got, err := tt.run(state, previous[:tt.previousSize])
			if err == nil {
				t.Fatal("ISF decode error = nil")
			}
			if got != ([lpcOrder]int16{}) || past != pastBefore || history != historyBefore {
				t.Fatal("ISF decode changed state after input validation error")
			}
		})
	}
}
