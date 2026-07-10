package amrwb

import "testing"

func TestEncoderHomingFrame(t *testing.T) {
	pcm := make([]int16, FrameSamples)
	for i := range pcm {
		pcm[i] = encoderHomingFrameSample
	}

	if !encoderHomingFrame(pcm) {
		t.Fatal("encoderHomingFrame() = false, want true")
	}
	pcm[FrameSamples-1] = 0
	if encoderHomingFrame(pcm) {
		t.Fatal("encoderHomingFrame(modified) = true, want false")
	}
	if encoderHomingFrame(pcm[:FrameSamples-1]) {
		t.Fatal("encoderHomingFrame(short) = true, want false")
	}
}

func TestMaskEncoderInputClearsTwoLowBits(t *testing.T) {
	pcm := []int16{7, -1, 0x1237}

	maskEncoderInput(pcm)

	want := []int16{4, -4, 0x1234}
	for i := range want {
		if pcm[i] != want[i] {
			t.Fatalf("pcm[%d] = %d, want %d", i, pcm[i], want[i])
		}
	}
}

func TestDecimate16kTo12k8ChunkingMatchesFullInput(t *testing.T) {
	var full encoderPreprocessState
	var chunked encoderPreprocessState
	input := make([]int16, 2*FrameSamples)
	for i := range input {
		input[i] = int16((i%97)*113 - 4800)
	}

	want := full.decimate16kTo12k8(nil, input)
	first := chunked.decimate16kTo12k8(nil, input[:FrameSamples])
	got := append([]int16{}, first...)
	second := chunked.decimate16kTo12k8(nil, input[FrameSamples:])
	got = append(got, second...)

	if len(want) != 2*frameSamples12k8 {
		t.Fatalf("full output length = %d, want %d", len(want), 2*frameSamples12k8)
	}
	if !samplesEqual(got, want) {
		t.Fatal("chunked decimator output differs from full input output")
	}
}

func TestEncoderPreprocessFrame(t *testing.T) {
	var state encoderPreprocessState
	state.reset()
	pcm := make([]int16, FrameSamples)
	for i := range pcm {
		pcm[i] = int16((i%53)*77 - 1800)
	}

	got := state.processFrame(nil, pcm)

	if len(got) != frameSamples12k8+lpcLookahead12k8 {
		t.Fatalf("output length = %d, want %d", len(got), frameSamples12k8+lpcLookahead12k8)
	}
	if allZeroSamples(got) {
		t.Fatal("preprocessed frame is all zero")
	}
	if allZeroSamples(state.decimMem[:]) {
		t.Fatal("decimator memory was not updated")
	}
	if allZeroSamples(state.hp50Mem[:]) {
		t.Fatal("high-pass memory was not updated")
	}
	if state.memPreemp == 0 {
		t.Fatal("preemphasis memory was not updated")
	}
	if state.qOld < 0 || state.qOld > qMax {
		t.Fatalf("qOld = %d, want 0..%d", state.qOld, qMax)
	}
}

func TestEncoderPrepareFrameStores12k8Speech(t *testing.T) {
	enc, err := NewEncoder(Config{Mode: Mode2385})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	pcm := make([]int16, FrameSamples)
	for i := range pcm {
		pcm[i] = int16((i%71)*59 - 2100)
	}

	homing, err := enc.prepareFrame(pcm)

	if err != nil {
		t.Fatalf("prepareFrame() error = %v", err)
	}
	if homing {
		t.Fatal("prepareFrame() homing = true, want false")
	}
	if allZeroSamples(enc.speech12k8[:]) {
		t.Fatal("prepared 12.8 kHz speech buffer is all zero")
	}

	for i := range pcm {
		pcm[i] = encoderHomingFrameSample
	}
	homing, err = enc.prepareFrame(pcm)
	if err != nil {
		t.Fatalf("prepareFrame(homing) error = %v", err)
	}
	if !homing {
		t.Fatal("prepareFrame(homing) = false, want true")
	}
}

func TestEncoderResetClearsPreprocessState(t *testing.T) {
	enc, err := NewEncoder(Config{Mode: Mode2385})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	for i := range enc.preprocess.decimMem {
		enc.preprocess.decimMem[i] = int16(i + 1)
	}
	for i := range enc.preprocess.hp50Mem {
		enc.preprocess.hp50Mem[i] = int16(i + 1)
	}
	enc.preprocess.memPreemp = 99
	enc.preprocess.qOld = 3
	enc.preprocess.qMax[0] = 4
	enc.preprocess.qMax[1] = 5
	for i := range enc.speech12k8 {
		enc.speech12k8[i] = int16(i + 1)
	}
	for i := range enc.oldSpeech {
		enc.oldSpeech[i] = int16(i + 1)
	}
	for i := range enc.oldExc {
		enc.oldExc[i] = int16(i + 1)
	}
	for i := range enc.memSyn {
		enc.memSyn[i] = int16(i + 1)
	}
	for i := range enc.memDecim2 {
		enc.memDecim2[i] = int16(i + 1)
	}
	enc.memWsp = 17
	enc.memW0 = 19

	enc.Reset()

	if !allZeroSamples(enc.preprocess.decimMem[:]) {
		t.Fatal("decimator memory was not reset")
	}
	if !allZeroSamples(enc.preprocess.hp50Mem[:]) {
		t.Fatal("high-pass memory was not reset")
	}
	if enc.preprocess.memPreemp != 0 {
		t.Fatalf("memPreemp = %d, want 0", enc.preprocess.memPreemp)
	}
	if enc.preprocess.qOld != 15 || enc.preprocess.qMax != [2]int16{15, 15} {
		t.Fatalf(
			"Q state = old %d max %v, want old 15 max [15 15]",
			enc.preprocess.qOld,
			enc.preprocess.qMax,
		)
	}
	if !allZeroSamples(enc.speech12k8[:]) {
		t.Fatal("12.8 kHz speech buffer was not reset")
	}
	if !allZeroSamples(enc.oldSpeech[:]) {
		t.Fatal("old speech was not reset")
	}
	if !allZeroSamples(enc.oldExc[:]) {
		t.Fatal("old excitation was not reset")
	}
	if !allZeroSamples(enc.memSyn[:]) {
		t.Fatal("synthesis memory was not reset")
	}
	if !allZeroSamples(enc.memDecim2[:]) {
		t.Fatal("weighted-speech decimator memory was not reset")
	}
	if enc.memWsp != 0 || enc.memW0 != 0 {
		t.Fatalf("scalar memories = %d/%d, want zero", enc.memWsp, enc.memW0)
	}
}

func TestEncoderPreemphasisAndScaleUpdatesQHistory(t *testing.T) {
	var state encoderPreprocessState
	state.reset()
	signal := make([]int16, frameSamples12k8+lpcLookahead12k8)
	for i := range signal {
		signal[i] = int16((i%17)*300 - 2400)
	}
	lastFrameSample := signal[frameSamples12k8-1]

	qNew := state.preemphasisAndScale(signal)

	if qNew < 0 || qNew > qMax {
		t.Fatalf("qNew = %d, want 0..%d", qNew, qMax)
	}
	if state.memPreemp != lastFrameSample {
		t.Fatalf("memPreemp = %d, want %d", state.memPreemp, lastFrameSample)
	}
	if allZeroSamples(signal) {
		t.Fatal("preemphasized signal is all zero")
	}
}

func TestEncoderScaleHistory(t *testing.T) {
	enc, err := NewEncoder(Config{Mode: Mode2385})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	enc.oldSpeech[0] = 1024
	enc.oldExc[0] = -1024
	enc.memSyn[0] = 512
	enc.memDecim2[0] = -512
	enc.memWsp = 256
	enc.memW0 = -256

	enc.scaleHistory(1)

	if enc.oldSpeech[0] != 2048 || enc.oldExc[0] != -2048 ||
		enc.memSyn[0] != 1024 || enc.memDecim2[0] != -1024 ||
		enc.memWsp != 512 || enc.memW0 != -512 {
		t.Fatalf(
			"scaled history = %d/%d/%d/%d/%d/%d, want doubled values",
			enc.oldSpeech[0],
			enc.oldExc[0],
			enc.memSyn[0],
			enc.memDecim2[0],
			enc.memWsp,
			enc.memW0,
		)
	}
}

func samplesEqual(a []int16, b []int16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func allZeroSamples(samples []int16) bool {
	for _, sample := range samples {
		if sample != 0 {
			return false
		}
	}
	return true
}
