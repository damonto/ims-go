package esp

import "math"

const espReplayWindowSize = 64

type ReplayWindow struct {
	initialized bool
	highest     uint32
	bitmap      uint64
}

func (w *ReplayWindow) Reset() {
	w.initialized = false
	w.highest = 0
	w.bitmap = 0
}

func (w *ReplayWindow) Accept(sequence uint32) bool {
	if !w.WouldAccept(sequence) {
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
	w.bitmap |= uint64(1) << delta
	return true
}

func (w ReplayWindow) WouldAccept(sequence uint32) bool {
	if sequence == 0 {
		return false
	}
	if !w.initialized {
		return true
	}
	if sequence > w.highest {
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
	return true
}

func NextSequence(sequence *uint32) (uint32, bool) {
	if *sequence == math.MaxUint32 {
		return 0, false
	}
	*sequence++
	return *sequence, true
}
