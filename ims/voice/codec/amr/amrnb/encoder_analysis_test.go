package amrnb

import "testing"

func TestEncoderAnalyzeFrameMode590(t *testing.T) {
	encoder, err := NewEncoder(Config{Mode: Mode590})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	pcm := make([]int16, FrameSamples)
	for i := range pcm {
		pcm[i] = int16((i%31)*96 - 1200)
	}

	got, err := encoder.analyzeFrame(pcm)

	if err != nil {
		t.Fatalf("analyzeFrame() error = %v", err)
	}
	if got.written != 19 {
		t.Fatalf("written params = %d, want 19", got.written)
	}
	if got.az[3*lpcCoeffCount] != 4096 || got.azQ[3*lpcCoeffCount] != 4096 {
		t.Fatalf("final LPC headers = %d/%d, want 4096", got.az[3*lpcCoeffCount], got.azQ[3*lpcCoeffCount])
	}
	if allZero(got.wsp[:]) {
		t.Fatal("weighted speech is all zero")
	}
	for _, lag := range got.tOp {
		if lag < pitchMin || lag > pitchMax {
			t.Fatalf("T_op lag = %d, want %d..%d", lag, pitchMin, pitchMax)
		}
	}
	nonZeroTargets := 0
	for i := range got.sub {
		if allZero(got.sub[i].xn[:]) {
			continue
		}
		nonZeroTargets++
	}
	if nonZeroTargets == 0 {
		t.Fatal("all target vectors are zero")
	}
	for i := range got.sub {
		if !got.sub[i].hasPitch {
			t.Fatalf("subframe %d pitch analysis was not computed", i)
		}
		if got.sub[i].pitch.t0 < pitchMin || got.sub[i].pitch.t0 > pitchMax {
			t.Fatalf("subframe %d pitch lag = %d, want %d..%d", i, got.sub[i].pitch.t0, pitchMin, pitchMax)
		}
		if !got.sub[i].hasFixed {
			t.Fatalf("subframe %d fixed codebook search was not computed", i)
		}
		decoded := decode2i40_11bits(got.sub[i].fixed.sign, got.sub[i].fixed.index)
		if allZero(decoded[:]) {
			t.Fatalf("subframe %d decoded fixed codebook is all zero", i)
		}
	}
	if encoder.oldSpeech[0] == 0 && encoder.oldSpeech[FrameSamples-1] == 0 {
		t.Fatal("speech history was not advanced")
	}
	if encoder.oldWsp[0] == 0 && encoder.oldWsp[pitchMax-1] == 0 {
		t.Fatal("weighted speech history was not advanced")
	}
	if encoder.pitch.prevT0 == 0 {
		t.Fatal("pitch state was not advanced")
	}
}

func TestEncoderAnalyzeFrameMode122(t *testing.T) {
	encoder, err := NewEncoder(Config{Mode: Mode1220})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	pcm := make([]int16, FrameSamples)
	for i := range pcm {
		pcm[i] = int16((i%37)*74 - 900)
	}

	got, err := encoder.analyzeFrame(pcm)

	if err != nil {
		t.Fatalf("analyzeFrame(MR122) error = %v", err)
	}
	if got.written != 57 {
		t.Fatalf("written params = %d, want 57", got.written)
	}
	if got.az[lpcCoeffCount] != 4096 || got.azQ[lpcCoeffCount] != 4096 {
		t.Fatalf("mid LPC headers = %d/%d, want 4096", got.az[lpcCoeffCount], got.azQ[lpcCoeffCount])
	}
	if got.az[3*lpcCoeffCount] != 4096 || got.azQ[3*lpcCoeffCount] != 4096 {
		t.Fatalf("final LPC headers = %d/%d, want 4096", got.az[3*lpcCoeffCount], got.azQ[3*lpcCoeffCount])
	}
	if allZero(got.wsp[:]) {
		t.Fatal("weighted speech is all zero")
	}
	for _, lag := range got.tOp {
		if lag < pitchMinMR122 || lag > pitchMax {
			t.Fatalf("MR122 T_op lag = %d, want %d..%d", lag, pitchMinMR122, pitchMax)
		}
	}
	for i := range got.sub {
		if allZero(got.sub[i].h1[:]) {
			t.Fatalf("subframe %d impulse response is all zero", i)
		}
		if !got.sub[i].hasPitch {
			t.Fatalf("subframe %d pitch analysis was not computed", i)
		}
		if got.sub[i].pitch.t0 < pitchMinMR122 || got.sub[i].pitch.t0 > pitchMax {
			t.Fatalf("subframe %d MR122 pitch lag = %d, want %d..%d", i, got.sub[i].pitch.t0, pitchMinMR122, pitchMax)
		}
		if !got.sub[i].pitch.hasGainPitIndex {
			t.Fatalf("subframe %d MR122 pitch gain was not quantized", i)
		}
		if !got.sub[i].hasFixed {
			t.Fatalf("subframe %d fixed codebook search was not computed", i)
		}
		if got.sub[i].fixed.paramCount != 10 {
			t.Fatalf("subframe %d fixed param count = %d, want 10", i, got.sub[i].fixed.paramCount)
		}
		decoded := decode10i40_35bits(got.sub[i].fixed.params[:got.sub[i].fixed.paramCount])
		if allZero(decoded[:]) {
			t.Fatalf("subframe %d decoded fixed codebook is all zero", i)
		}
		if allZero(got.sub[i].fixed.y2[:]) {
			t.Fatalf("subframe %d filtered fixed codebook is all zero", i)
		}
		if got.sub[i].fixed.gainCode.index < 0 || got.sub[i].fixed.gainCode.index > 31 {
			t.Fatalf("subframe %d code gain index = %d, want 0..31", i, got.sub[i].fixed.gainCode.index)
		}
	}
}

func TestEncoderAnalyzeFrameMode515IncludesFixedCodebook(t *testing.T) {
	encoder, err := NewEncoder(Config{Mode: Mode515})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	pcm := make([]int16, FrameSamples)
	for i := range pcm {
		pcm[i] = int16((i%41)*68 - 1100)
	}

	got, err := encoder.analyzeFrame(pcm)

	if err != nil {
		t.Fatalf("analyzeFrame(MR515) error = %v", err)
	}
	for i := range got.sub {
		sub := got.sub[i]
		if !sub.hasPitch {
			t.Fatalf("subframe %d pitch analysis was not computed", i)
		}
		if !sub.hasFixed {
			t.Fatalf("subframe %d fixed codebook search was not computed", i)
		}
		decoded := decode2i40_9bits(int16(i), sub.fixed.sign, sub.fixed.index)
		if allZero(decoded[:]) {
			t.Fatalf("subframe %d decoded fixed codebook is all zero", i)
		}
		if allZero(sub.fixed.y2[:]) {
			t.Fatalf("subframe %d filtered fixed codebook is all zero", i)
		}
	}
}

func TestEncoderAnalyzeFrameMode475RebuildsPairState(t *testing.T) {
	encoder, err := NewEncoder(Config{Mode: Mode475})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	pcm := make([]int16, FrameSamples)
	for i := range pcm {
		pcm[i] = int16((i%39)*84 - 1250)
	}

	got, err := encoder.analyzeFrame(pcm)

	if err != nil {
		t.Fatalf("analyzeFrame(MR475) error = %v", err)
	}
	if got.written != 17 {
		t.Fatalf("written params = %d, want 17", got.written)
	}
	for i := range got.sub {
		sub := got.sub[i]
		if !sub.hasPitch {
			t.Fatalf("subframe %d pitch analysis was not computed", i)
		}
		if !sub.hasFixed {
			t.Fatalf("subframe %d fixed codebook search was not computed", i)
		}
		decoded := decode2i40_9bits(int16(i), sub.fixed.sign, sub.fixed.index)
		if allZero(decoded[:]) {
			t.Fatalf("subframe %d decoded fixed codebook is all zero", i)
		}
		if sub.fixed.gainCode.index < 0 || sub.fixed.gainCode.index > 255 {
			t.Fatalf("subframe %d MR475 gain index = %d, want 0..255", i, sub.fixed.gainCode.index)
		}
		if i%2 == 1 && sub.fixed.gainCode.index != got.sub[i-1].fixed.gainCode.index {
			t.Fatalf(
				"subframe pair %d/%d gain indexes = %d/%d, want shared index",
				i-1,
				i,
				got.sub[i-1].fixed.gainCode.index,
				sub.fixed.gainCode.index,
			)
		}
	}
	if allZero(encoder.memSyn[:]) {
		t.Fatal("MR475 synthesis memory was not updated")
	}
	if allZero(encoder.memErr[:]) {
		t.Fatal("MR475 error memory was not updated")
	}
	if allZero(encoder.memW0[:]) {
		t.Fatal("MR475 weighting memory was not updated")
	}
	if encoder.sharp == sharpMin {
		t.Fatal("MR475 sharp was not updated")
	}
}

func TestEncoderAnalyzeFrameMode670IncludesFixedCodebook(t *testing.T) {
	encoder, err := NewEncoder(Config{Mode: Mode670})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	pcm := make([]int16, FrameSamples)
	for i := range pcm {
		pcm[i] = int16((i%43)*72 - 1300)
	}

	got, err := encoder.analyzeFrame(pcm)

	if err != nil {
		t.Fatalf("analyzeFrame(MR670) error = %v", err)
	}
	for i := range got.sub {
		sub := got.sub[i]
		if !sub.hasPitch {
			t.Fatalf("subframe %d pitch analysis was not computed", i)
		}
		if !sub.hasFixed {
			t.Fatalf("subframe %d fixed codebook search was not computed", i)
		}
		decoded := decode3i40_14bits(sub.fixed.sign, sub.fixed.index)
		if allZero(decoded[:]) {
			t.Fatalf("subframe %d decoded fixed codebook is all zero", i)
		}
		if allZero(sub.fixed.y2[:]) {
			t.Fatalf("subframe %d filtered fixed codebook is all zero", i)
		}
	}
}

func TestEncoderAnalyzeFrameMode795IncludesFixedCodebook(t *testing.T) {
	encoder, err := NewEncoder(Config{Mode: Mode795})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	pcm := make([]int16, FrameSamples)
	for i := range pcm {
		pcm[i] = int16((i%47)*76 - 1400)
	}

	got, err := encoder.analyzeFrame(pcm)

	if err != nil {
		t.Fatalf("analyzeFrame(MR795) error = %v", err)
	}
	if got.written != 23 {
		t.Fatalf("written params = %d, want 23", got.written)
	}
	for i := range got.sub {
		sub := got.sub[i]
		if !sub.hasPitch {
			t.Fatalf("subframe %d pitch analysis was not computed", i)
		}
		if !sub.hasFixed {
			t.Fatalf("subframe %d fixed codebook search was not computed", i)
		}
		decoded := decode4i40_17bits(sub.fixed.sign, sub.fixed.index)
		if allZero(decoded[:]) {
			t.Fatalf("subframe %d decoded fixed codebook is all zero", i)
		}
		if allZero(sub.fixed.y2[:]) {
			t.Fatalf("subframe %d filtered fixed codebook is all zero", i)
		}
		if !sub.fixed.gainCode.hasPitchIndex {
			t.Fatalf("subframe %d MR795 gain pitch index was not computed", i)
		}
		if sub.fixed.gainCode.index < 0 || sub.fixed.gainCode.index > 31 {
			t.Fatalf("subframe %d code gain index = %d, want 0..31", i, sub.fixed.gainCode.index)
		}
	}
}

func TestEncoderAnalyzeFrameMode1020IncludesFixedCodebook(t *testing.T) {
	encoder, err := NewEncoder(Config{Mode: Mode1020})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	pcm := make([]int16, FrameSamples)
	for i := range pcm {
		pcm[i] = int16((i%53)*82 - 1500)
	}

	got, err := encoder.analyzeFrame(pcm)

	if err != nil {
		t.Fatalf("analyzeFrame(MR102) error = %v", err)
	}
	for i, lag := range got.tOp {
		if lag < pitchMin || lag > pitchMax {
			t.Fatalf("MR102 T_op[%d] = %d, want %d..%d", i, lag, pitchMin, pitchMax)
		}
	}
	for i := range got.sub {
		sub := got.sub[i]
		if !sub.hasPitch {
			t.Fatalf("subframe %d pitch analysis was not computed", i)
		}
		if !sub.hasFixed {
			t.Fatalf("subframe %d fixed codebook search was not computed", i)
		}
		if sub.fixed.paramCount != 7 {
			t.Fatalf("subframe %d fixed param count = %d, want 7", i, sub.fixed.paramCount)
		}
		decoded := decode8i40_31bits(sub.fixed.params[:sub.fixed.paramCount])
		if allZero(decoded[:]) {
			t.Fatalf("subframe %d decoded fixed codebook is all zero", i)
		}
		if allZero(sub.fixed.y2[:]) {
			t.Fatalf("subframe %d filtered fixed codebook is all zero", i)
		}
	}
}

func TestEncoderAnalyzeFrameRejectsBadPCMSize(t *testing.T) {
	encoder, err := NewEncoder(Config{Mode: Mode590})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}

	if _, err := encoder.analyzeFrame(make([]int16, FrameSamples-1)); err == nil {
		t.Fatal("analyzeFrame() error = nil, want bad length error")
	}
}

func allZero(samples []int16) bool {
	for _, sample := range samples {
		if sample != 0 {
			return false
		}
	}
	return true
}
