// Package vad provides band-level calculations for AMR voice activity detection.
package vad

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

// LevelBand describes one VAD filter-bank band in the interleaved work buffer.
//
// A LevelBand is table-driven codec data, not a general-purpose zero-value
// helper. Calculate expects the configured indexes to be valid for data.
type LevelBand struct {
	TailStart int
	TailEnd   int
	Step      int
	Offset    int
	Scale     int16
}

// Calculate returns the band level and the next delayed sub-frame level.
func (b LevelBand) Calculate(data []int16, subLevel int16) (int16, int16) {
	var tail int32
	for i := b.TailStart; i < b.TailEnd; i++ {
		tail = fxp.LMac(tail, 1, fxp.Abs16(data[b.Step*i+b.Offset]))
	}

	level := fxp.Add32(tail, fxp.Shl32(int32(subLevel), fxp.Sub16(16, b.Scale)))
	nextSubLevel := fxp.ExtractH(fxp.Shl32(tail, b.Scale))
	for i := range b.TailStart {
		level = fxp.LMac(level, 1, fxp.Abs16(data[b.Step*i+b.Offset]))
	}
	return fxp.ExtractH(fxp.Shl32(level, b.Scale)), nextSubLevel
}
