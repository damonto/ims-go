package amrwb

import (
	"encoding/binary"
	"os"
	"testing"
)

func TestEncoderCodebookFallbackPreservesGainInput(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		mode       Mode
		frame      int
		paramIndex int
		want       int16
	}{
		{
			name: "T02 23.85 frame 2 subframe 1 gain",
			// Only the three frames used by this regression are shipped.
			// The full reference vector corpus remains optional.
			path:       "fixtures/codebook_gain.pcm",
			mode:       Mode2385,
			frame:      2,
			paramIndex: 30,
			want:       21,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.path)
			if err != nil {
				t.Fatalf("read PCM vector: %v", err)
			}
			pcm := make([]int16, len(data)/2)
			for i := range pcm {
				pcm[i] = int16(binary.LittleEndian.Uint16(data[i*2:]))
			}

			enc, err := NewEncoder(Config{Mode: tt.mode})
			if err != nil {
				t.Fatalf("NewEncoder() error = %v", err)
			}
			for frame := 0; frame <= tt.frame; frame++ {
				start := frame * FrameSamples
				if _, err := enc.Encode(nil, pcm[start:start+FrameSamples]); err != nil {
					t.Fatalf("Encode(frame %d) error = %v", frame, err)
				}
			}
			if got := enc.params[tt.paramIndex]; got != tt.want {
				t.Fatalf("params[%d] = %d, want %d", tt.paramIndex, got, tt.want)
			}
		})
	}
}
