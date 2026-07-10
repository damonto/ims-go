package vad

import "testing"

func TestLevelBandCalculate(t *testing.T) {
	tests := []struct {
		name         string
		band         LevelBand
		data         []int16
		subLevel     int16
		want         int16
		wantSubLevel int16
	}{
		{
			name: "updates delayed tail",
			band: LevelBand{
				TailStart: 1,
				TailEnd:   3,
				Step:      2,
				Offset:    0,
				Scale:     16,
			},
			data:         []int16{-10, 0, -30, 0, 50},
			subLevel:     5,
			want:         185,
			wantSubLevel: 160,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subLevel := tt.subLevel

			got, nextSubLevel := tt.band.Calculate(tt.data, subLevel)

			if got != tt.want {
				t.Fatalf("Calculate() = %d, want %d", got, tt.want)
			}
			if nextSubLevel != tt.wantSubLevel {
				t.Fatalf("nextSubLevel = %d, want %d", nextSubLevel, tt.wantSubLevel)
			}
		})
	}
}
