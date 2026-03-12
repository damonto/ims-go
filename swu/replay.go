package swu

import "math"

const espReplayWindowSize = 64

type replayWindow struct {
	initialized bool
	highest     uint32
	bitmap      uint64
}

func (w *replayWindow) Reset() {
	w.initialized = false
	w.highest = 0
	w.bitmap = 0
}

func (w *replayWindow) Accept(sequence uint32) bool {
	if sequence == 0 {
		return false
	}
	if !w.initialized {
		w.initialized = true
		w.highest = sequence
		w.bitmap = 1
		return true
	}
	if sequence > w.highest {
		shift := sequence - w.highest
		if shift >= espReplayWindowSize {
			w.bitmap = 1
		} else {
			w.bitmap = (w.bitmap << shift) | 1
		}
		w.highest = sequence
		return true
	}
	delta := w.highest - sequence
	if delta >= espReplayWindowSize {
		return false
	}
	bit := uint64(1) << delta
	if w.bitmap&bit != 0 {
		return false
	}
	w.bitmap |= bit
	return true
}

func nextESPSequence(sequence *uint32) (uint32, bool) {
	if *sequence == math.MaxUint32 {
		return 0, false
	}
	*sequence++
	return *sequence, true
}
