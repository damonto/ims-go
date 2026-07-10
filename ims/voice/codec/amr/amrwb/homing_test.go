package amrwb

import "testing"

func TestHomingFrameTest(t *testing.T) {
	tests := []struct {
		name string
		mode Mode
	}{
		{name: "6.60", mode: Mode660},
		{name: "12.65", mode: Mode1265},
		{name: "23.85", mode: Mode2385},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serial := homingSerial(tt.mode, frameBits[tt.mode])

			if !homingFrameTest(serial, tt.mode) {
				t.Fatalf("homingFrameTest(%d) = false, want true", tt.mode)
			}

			serial[0] ^= 1
			if homingFrameTest(serial, tt.mode) {
				t.Fatalf("homingFrameTest(%d) accepted corrupted frame", tt.mode)
			}
		})
	}
}

func TestHomingFrameTestFirst(t *testing.T) {
	serial := homingSerial(Mode885, homingFirstSubframeBits[Mode885])

	if !homingFrameTestFirst(serial, Mode885) {
		t.Fatal("homingFrameTestFirst() = false, want true")
	}

	serial[0] ^= 1
	if homingFrameTestFirst(serial, Mode885) {
		t.Fatal("homingFrameTestFirst() accepted corrupted first subframe")
	}
}

func TestMask14BitOutput(t *testing.T) {
	pcm := []int16{0, 1, 2, 3, 4, -1, -2, -3, -4}

	mask14BitOutput(pcm)

	want := []int16{0, 0, 0, 0, 4, -4, -4, -4, -4}
	for i := range want {
		if pcm[i] != want[i] {
			t.Fatalf("pcm[%d] = %d, want %d", i, pcm[i], want[i])
		}
	}
}
