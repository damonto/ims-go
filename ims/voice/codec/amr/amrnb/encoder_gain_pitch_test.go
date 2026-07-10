package amrnb

import "testing"

const fixedMax16ForTest int16 = 32767

func TestQuantizePitchGain(t *testing.T) {
	tests := []struct {
		name                 string
		mode                 Mode
		limit                int16
		gain                 int16
		wantIndex            int16
		wantGain             int16
		wantCandidates       [3]int16
		wantCandidateIndices [3]int16
	}{
		{
			name:      "MR122 masks two LSBs",
			mode:      Mode1220,
			limit:     fixedMax16ForTest,
			gain:      17000,
			wantIndex: 12,
			wantGain:  17200,
		},
		{
			name:      "honors limit",
			mode:      Mode590,
			limit:     15565,
			gain:      19000,
			wantIndex: 10,
			wantGain:  15565,
		},
		{
			name:                 "MR795 candidates",
			mode:                 Mode795,
			limit:                fixedMax16ForTest,
			gain:                 15000,
			wantIndex:            9,
			wantGain:             14746,
			wantCandidates:       [3]int16{13926, 14746, 15565},
			wantCandidateIndices: [3]int16{8, 9, 10},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := quantizePitchGain(tt.mode, tt.limit, tt.gain)

			if got.index != tt.wantIndex {
				t.Fatalf("index = %d, want %d", got.index, tt.wantIndex)
			}
			if got.gain != tt.wantGain {
				t.Fatalf("gain = %d, want %d", got.gain, tt.wantGain)
			}
			if got.candidates != tt.wantCandidates || got.candidateIndices != tt.wantCandidateIndices {
				t.Fatalf(
					"candidates = %v/%v, want %v/%v",
					got.candidates,
					got.candidateIndices,
					tt.wantCandidates,
					tt.wantCandidateIndices,
				)
			}
		})
	}
}
