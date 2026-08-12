package amrwb

import "testing"

func TestCorrelateImpulseTargetProducesTrackCorrelations(t *testing.T) {
	h := make([]int16, subframeSamples)
	x := make([]int16, subframeSamples)
	h[0] = 4096
	for i := range x {
		x[i] = int16((i%9 - 4) * 100)
	}
	dn, err := correlateImpulseTarget(h, x)
	if err != nil {
		t.Fatalf("correlateImpulseTarget() error = %v", err)
	}
	if allZeroSamples(dn[:]) {
		t.Fatal("correlation is all zero")
	}
}

func TestAcelp2t64CodewordRoundTrip(t *testing.T) {
	dn := make([]int16, subframeSamples)
	cn := make([]int16, subframeSamples)
	h := make([]int16, subframeSamples)
	for i := range dn {
		dn[i] = int16((i%17 - 8) * 64)
		cn[i] = int16((7 - i%15) * 48)
	}
	h[0] = 4096
	h[1] = 2048
	h[2] = -1024

	got, err := acelp2t64(dn, cn, h)

	if err != nil {
		t.Fatalf("acelp2t64() error = %v", err)
	}
	if got.index < 0 || got.index >= 1<<12 {
		t.Fatalf("index = %d outside 12 bits", got.index)
	}
	wantCode, err := decodeAcelp2PIn64(got.index)
	if err != nil {
		t.Fatalf("decodeAcelp2PIn64() error = %v", err)
	}
	for i := range got.code {
		if got.code[i] != wantCode[i] {
			t.Fatalf("code[%d] = %d, want %d from decoded index", i, got.code[i], wantCode[i])
		}
	}
	if allZeroSamples(got.filtered[:]) {
		t.Fatal("filtered codeword is all zero")
	}
}

func TestACELP4T64At20BitsCodewordRoundTrip(t *testing.T) {
	dn := make([]int16, subframeSamples)
	cn := make([]int16, subframeSamples)
	h := make([]int16, subframeSamples)
	for i := range dn {
		dn[i] = int16((i%19 - 9) * 48)
		cn[i] = int16((8 - i%17) * 40)
	}
	h[0] = 4096
	h[1] = 1536
	h[2] = -768
	h[3] = 384

	got, err := acelp4T64At20Bits(dn, cn, h)

	if err != nil {
		t.Fatalf("acelp4T64At20Bits() error = %v", err)
	}
	for i, index := range got.indices[:got.indexCount] {
		if index < 0 || index >= 1<<5 {
			t.Fatalf("indices[%d] = %d outside 5 bits", i, index)
		}
	}
	wantCode, err := decodeAcelp4PIn64(got.indices[:got.indexCount], 20)
	if err != nil {
		t.Fatalf("decodeAcelp4PIn64() error = %v", err)
	}
	for i := range got.code {
		if got.code[i] != wantCode[i] {
			t.Fatalf("code[%d] = %d, want %d from decoded indices", i, got.code[i], wantCode[i])
		}
	}
	if allZeroSamples(got.filtered[:]) {
		t.Fatal("filtered codeword is all zero")
	}
}

func TestACELP4T64At36BitsCodewordRoundTrip(t *testing.T) {
	dn := make([]int16, subframeSamples)
	cn := make([]int16, subframeSamples)
	h := make([]int16, subframeSamples)
	for i := range dn {
		dn[i] = int16((i%23 - 11) * 44)
		cn[i] = int16((10 - i%21) * 36)
	}
	h[0] = 4096
	h[1] = 1536
	h[2] = -768
	h[3] = 384

	got, err := acelp4T64At36Bits(dn, cn, h)

	if err != nil {
		t.Fatalf("acelp4T64At36Bits() error = %v", err)
	}
	for i, index := range got.indices[:got.indexCount] {
		if index < 0 || index >= 1<<9 {
			t.Fatalf("indices[%d] = %d outside 9 bits", i, index)
		}
	}
	wantCode, err := decodeAcelp4PIn64(got.indices[:got.indexCount], 36)
	if err != nil {
		t.Fatalf("decodeAcelp4PIn64() error = %v", err)
	}
	for i := range got.code {
		if got.code[i] != wantCode[i] {
			t.Fatalf("code[%d] = %d, want %d from decoded indices", i, got.code[i], wantCode[i])
		}
	}
	if allZeroSamples(got.filtered[:]) {
		t.Fatal("filtered codeword is all zero")
	}
}

func TestAcelp4t64HigherModeCodewordRoundTrip(t *testing.T) {
	for _, nbits := range []int16{44, 52, 64, 72, 88} {
		dn := make([]int16, subframeSamples)
		cn := make([]int16, subframeSamples)
		h := make([]int16, subframeSamples)
		for i := range dn {
			dn[i] = int16((i%29 - 14) * 40)
			cn[i] = int16((13 - i%27) * 32)
		}
		h[0] = 4096
		h[1] = 1536
		h[2] = -768
		h[3] = 384

		got, err := acelp4t64Indexed(dn, cn, h, nbits, int16(frameBits[Mode2385]))

		if err != nil {
			t.Fatalf("acelp4t64Indexed(%d) error = %v", nbits, err)
		}
		wantCode, err := decodeAcelp4PIn64(got.indices[:got.indexCount], nbits)
		if err != nil {
			t.Fatalf("decodeAcelp4PIn64(%d) error = %v", nbits, err)
		}
		for i := range got.code {
			if got.code[i] != wantCode[i] {
				t.Fatalf("nbits %d code[%d] = %d, want %d from decoded indices",
					nbits, i, got.code[i], wantCode[i])
			}
		}
		if allZeroSamples(got.filtered[:]) {
			t.Fatalf("nbits %d filtered codeword is all zero", nbits)
		}
	}
}

func TestFilterCodewordUsesPulseSigns(t *testing.T) {
	h := make([]int16, subframeSamples)
	h[0] = 4096
	code := make([]int16, subframeSamples)
	code[0] = 512
	code[1] = -512
	y, err := filterCodeword(h, code)
	if err != nil {
		t.Fatalf("filterCodeword() error = %v", err)
	}
	if y[0] != 512 {
		t.Fatalf("y[0] = %d, want 512", y[0])
	}
	if y[1] != -512 {
		t.Fatalf("y[1] = %d, want -512", y[1])
	}
}

func TestQuant1PulseRoundTrip(t *testing.T) {
	for _, pos := range []int{0, 7, 15, 16, 23, 31} {
		index := quant1Pulse(pos, 4)
		decoded := decode1pN1(index, 4, 0)
		if decoded[0] != int16(pos) {
			t.Fatalf("decode1pN1(quant1Pulse(%d)) = %d", pos, decoded[0])
		}
	}
}

func TestQuant2PulseRoundTripCodevector(t *testing.T) {
	tests := [][2]int{
		{0, 4},
		{4, 0},
		{0, 20},
		{20, 0},
		{19, 31},
		{31, 19},
	}
	for _, tt := range tests {
		index := quant2Pulse(tt[0], tt[1], 4)
		decoded := decode2p2N1(index, 4, 0)

		var wantPos pulsePositions
		wantPos[0], wantPos[1] = int16(tt[0]), int16(tt[1])
		want := addPulses([subframeSamples]int16{}, wantPos, 2, 0)
		got := addPulses([subframeSamples]int16{}, decoded, 2, 0)
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("positions %v decoded to %v: code[%d] = %d, want %d",
					tt, decoded, i, got[i], want[i])
			}
		}
	}
}

func TestQuant3PulseRoundTripCodevector(t *testing.T) {
	tests := [][]int{
		{0, 4, 20},
		{20, 0, 4},
		{3, 11, 31},
		{27, 19, 7},
	}
	for _, tt := range tests {
		index := quant3Pulse(tt[0], tt[1], tt[2], 4)
		decoded := decode3p3N1(index, 4, 0)
		assertTrackCodevector(t, tt, decoded, 3)
	}
}

func TestQuant4PulseRoundTripCodevector(t *testing.T) {
	tests := [][]int{
		{0, 4, 8, 12},
		{16, 20, 24, 28},
		{0, 20, 8, 28},
		{31, 3, 23, 11},
	}
	for _, tt := range tests {
		index := quant4Pulse(tt, 4)
		decoded := decode4p4N(index, 4, 0)
		assertTrackCodevector(t, tt, decoded, 4)
	}
}

func TestQuant5PulseRoundTripCodevector(t *testing.T) {
	tests := [][]int{
		{0, 4, 8, 12, 31},
		{16, 20, 24, 28, 31},
		{0, 20, 8, 28, 15},
		{31, 3, 22, 11, 7},
	}
	for _, tt := range tests {
		index := quant5Pulse(tt, 4)
		decoded := decode5p5N(index, 4, 0)
		assertTrackCodevector(t, tt, decoded, 5)
	}
}

func TestQuant6PulseRoundTripCodevector(t *testing.T) {
	tests := [][]int{
		{0, 4, 8, 12, 31, 27},
		{16, 20, 24, 28, 31, 27},
		{0, 20, 8, 28, 15, 23},
		{31, 3, 22, 11, 7, 18},
	}
	for _, tt := range tests {
		index := quant6Pulse(tt, 4)
		decoded := decode6p6N2(index, 4, 0)
		assertTrackCodevector(t, tt, decoded, 6)
	}
}

func assertTrackCodevector(t *testing.T, wantPos []int, gotPos pulsePositions, count int16) {
	t.Helper()
	var want [subframeSamples]int16
	for _, pos := range wantPos {
		positions := pulsePositions{int16(pos)}
		want = addPulses(want, positions, 1, 0)
	}
	got := addPulses([subframeSamples]int16{}, gotPos, count, 0)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("positions %v decoded to %v: code[%d] = %d, want %d",
				wantPos, gotPos, i, got[i], want[i])
		}
	}
}
