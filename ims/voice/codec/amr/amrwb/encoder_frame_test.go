package amrwb

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

func TestEncodeFrameSpeechRejectsBadPCMCount(t *testing.T) {
	enc, err := NewEncoder(Config{Mode: Mode1265})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}

	if _, err := enc.encodeFrameSpeech(nil, make([]int16, FrameSamples-1)); err == nil {
		t.Fatal("encodeFrameSpeech(short PCM) error = nil")
	}
}

func TestEncodeFrameSpeechProducesDecodablePayloads(t *testing.T) {
	for mode := Mode660; mode <= Mode2385; mode++ {
		t.Run(fmt.Sprintf("mode_%d", mode), func(t *testing.T) {
			enc, err := NewEncoder(Config{Mode: mode})
			if err != nil {
				t.Fatalf("NewEncoder() error = %v", err)
			}
			dec := NewDecoder()
			for frameIndex := range 2 {
				t.Run(fmt.Sprintf("frame_%d", frameIndex), func(t *testing.T) {
					pcm := encoderPipelinePCM(frameIndex)

					speech, err := enc.encodeFrameSpeech(nil, pcm)

					if err != nil {
						t.Fatalf("encodeFrameSpeech() error = %v", err)
					}
					wantBytes, err := FrameBytes(mode)
					if err != nil {
						t.Fatalf("FrameBytes() error = %v", err)
					}
					if len(speech) != wantBytes {
						t.Fatalf("speech bytes = %d, want %d", len(speech), wantBytes)
					}
					payload := Speech{Mode: mode}
					if err := payload.UnmarshalBinary(speech); err != nil {
						t.Fatalf("Speech.UnmarshalBinary() error = %v", err)
					}
					serial := payload.Serial
					decoded := Params{Mode: mode}
					if err := decoded.UnmarshalBinary(serial); err != nil {
						t.Fatalf("Params.UnmarshalBinary() error = %v", err)
					}
					params := decoded.Values
					if !slices.Equal(params, enc.params) {
						t.Fatal("params did not round trip through speech bytes")
					}
					out, err := dec.Decode(nil, Frame{Mode: mode, Quality: true, Data: speech})
					if err != nil {
						t.Fatalf("Decode(generated speech) error = %v", err)
					}
					if len(out) != FrameSamples {
						t.Fatalf("decoded samples = %d, want %d", len(out), FrameSamples)
					}
				})
			}
		})
	}
}

func TestEncodeProducesDecodablePayloads(t *testing.T) {
	for mode := Mode660; mode <= Mode2385; mode++ {
		t.Run(fmt.Sprintf("mode_%d", mode), func(t *testing.T) {
			enc, err := NewEncoder(Config{Mode: mode})
			if err != nil {
				t.Fatalf("NewEncoder() error = %v", err)
			}
			dec := NewDecoder()
			pcm := encoderPipelinePCM(int(mode))

			frame, err := enc.Encode(nil, pcm)

			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			wantBytes, err := FrameBytes(mode)
			if err != nil {
				t.Fatalf("FrameBytes() error = %v", err)
			}
			if frame.Mode != mode || !frame.Quality {
				t.Fatalf("frame metadata = %d/%v, want %d/true", frame.Mode, frame.Quality, mode)
			}
			if len(frame.Data) != wantBytes {
				t.Fatalf("speech bytes = %d, want %d", len(frame.Data), wantBytes)
			}
			out, err := dec.Decode(nil, frame)
			if err != nil {
				t.Fatalf("Decode(generated speech) error = %v", err)
			}
			if len(out) != FrameSamples {
				t.Fatalf("decoded samples = %d, want %d", len(out), FrameSamples)
			}
		})
	}
}

func TestEncodeDTXSequenceProducesSIDAndNoData(t *testing.T) {
	enc, err := NewEncoder(Config{Mode: Mode1265, DTX: true})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	dec := NewDecoder()
	silence := make([]int16, FrameSamples)
	var modes []Mode
	var sizes []int
	for range 13 {
		frame, err := enc.Encode(nil, silence)
		if err != nil {
			t.Fatalf("Encode(DTX silence) error = %v", err)
		}
		modes = append(modes, frame.Mode)
		sizes = append(sizes, len(frame.Data))
		if _, err := dec.Decode(nil, frame); err != nil {
			t.Fatalf("Decode(DTX mode %d) error = %v", frame.Mode, err)
		}
	}

	if modes[7] != ModeSID || sizes[7] != 5 {
		t.Fatalf("first DTX frame = mode %d size %d, want SID_FIRST", modes[7], sizes[7])
	}
	for _, index := range []int{8, 9} {
		if modes[index] != ModeNoData || sizes[index] != 0 {
			t.Fatalf("DTX frame %d = mode %d size %d, want no-data", index, modes[index], sizes[index])
		}
	}
	if modes[10] != ModeSID || sizes[10] != 5 {
		t.Fatalf("DTX frame 10 = mode %d size %d, want SID_UPDATE", modes[10], sizes[10])
	}
}

func TestEncodeDTXKeepsActiveSpeechMode(t *testing.T) {
	enc, err := NewEncoder(Config{Mode: Mode1265, DTX: true})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}

	frame, err := enc.Encode(nil, encoderPipelinePCM(0))

	if err != nil {
		t.Fatalf("Encode(active DTX) error = %v", err)
	}
	if frame.Mode != Mode1265 || len(frame.Data) != 32 {
		t.Fatalf("active DTX frame = mode %d size %d, want Mode1265/32", frame.Mode, len(frame.Data))
	}
}

func TestSIDParamsQuantizeNoiseISF(t *testing.T) {
	enc, err := NewEncoder(Config{Mode: Mode1265, DTX: true})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	pcm := encoderPipelinePCM(3)

	params, err := enc.sidParams(pcm)

	if err != nil {
		t.Fatalf("sidParams() error = %v", err)
	}
	if len(params) != 7 {
		t.Fatalf("SID params = %d, want 7", len(params))
	}
	limits := []int16{63, 63, 63, 31, 31}
	anySpectralIndex := false
	for i, limit := range limits {
		if params[i] < 0 || params[i] > limit {
			t.Fatalf("SID params[%d] = %d outside 0..%d", i, params[i], limit)
		}
		anySpectralIndex = anySpectralIndex || params[i] != 0
	}
	if !anySpectralIndex {
		t.Fatal("SID spectral indices are all zero")
	}
	if params[5] < 0 || params[5] > 63 || params[6] < 0 || params[6] > 1 {
		t.Fatalf("SID energy/dither = %d/%d, want energy 0..63 and dither bit", params[5], params[6])
	}
}

func TestQuantizeISFNoiseImprovesOverZeroIndices(t *testing.T) {
	var isf [lpcOrder]int16
	copy(isf[:], initialISF[:])
	isf[0] = fxp.Add16(isf[0], 300)
	isf[4] = fxp.Add16(isf[4], 700)
	isf[9] = fxp.Add16(isf[9], 900)
	isf[13] = fxp.Add16(isf[13], 500)
	indices, err := quantizeISFNoise(isf[:])
	if err != nil {
		t.Fatalf("quantizeISFNoise() error = %v", err)
	}

	quantized, err := decodeISFNoise(indices[:])
	if err != nil {
		t.Fatalf("decodeISFNoise(quantized) error = %v", err)
	}
	zero, err := decodeISFNoise(make([]int16, 5))
	if err != nil {
		t.Fatalf("decodeISFNoise(zero) error = %v", err)
	}
	if isfDistance(isf[:], quantized[:]) >= isfDistance(isf[:], zero[:]) {
		t.Fatalf("quantized distance %d is not better than zero-index distance %d",
			isfDistance(isf[:], quantized[:]), isfDistance(isf[:], zero[:]))
	}
}

func TestQuantizeISFNoiseRejectsShortBuffersWithoutWrites(t *testing.T) {
	tests := []struct {
		name    string
		isfSize int
	}{
		{name: "empty ISF", isfSize: 0},
		{name: "short ISF", isfSize: lpcOrder - 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indices, err := quantizeISFNoise(make([]int16, tt.isfSize))
			if err == nil {
				t.Fatal("quantizeISFNoise() error = nil")
			}
			if indices != ([5]int16{}) {
				t.Fatalf("indices = %v, want zero value", indices)
			}
		})
	}
}

func TestDecodeISFNoiseRejectsInvalidIndices(t *testing.T) {
	tests := []struct {
		name    string
		indices []int16
	}{
		{name: "short indices", indices: make([]int16, 4)},
		{name: "negative index", indices: []int16{-1, 0, 0, 0, 0}},
		{name: "first codebook overflow", indices: []int16{64, 0, 0, 0, 0}},
		{name: "fourth codebook overflow", indices: []int16{0, 0, 0, 32, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isf, err := decodeISFNoise(tt.indices)
			if err == nil {
				t.Fatal("decodeISFNoise() error = nil")
			}
			if isf != ([lpcOrder]int16{}) {
				t.Fatalf("isf = %v, want zero value", isf)
			}
		})
	}
}

func TestEncoderDTXHistoryAveragesISFAndEnergy(t *testing.T) {
	var state encoderDTXState
	state.reset()
	speech := make([]int16, frameSamples12k8)
	for i := range speech {
		speech[i] = int16((i%31 + 1) * 8)
	}
	var isf [lpcOrder]int16
	copy(isf[:], initialISF[:])
	for i := range isf {
		isf[i] = fxp.Add16(isf[i], int16(i*9))
	}

	state.buffer(isf[:], speech, Mode1265)

	average := state.averageISF()
	if average == ([lpcOrder]int16{}) {
		t.Fatal("averageISF() returned all zeros")
	}
	if state.logEnergyIndex() < 0 || state.logEnergyIndex() > 63 {
		t.Fatalf("logEnergyIndex() = %d outside 0..63", state.logEnergyIndex())
	}
}

func TestEncoderDTXAverageReplacesSpectralOutlier(t *testing.T) {
	var state encoderDTXState
	state.reset()
	var base [lpcOrder]int16
	copy(base[:], initialISF[:])
	var outlier [lpcOrder]int16
	copy(outlier[:], initialISF[:])
	for frame := range encoderDTXHistorySize {
		isf := base[:]
		if frame == 3 {
			for i := range lpcOrder {
				outlier[i] = fxp.Add16(initialISF[i], 2200)
			}
			isf = outlier[:]
		}
		state.bufferLogEnergy(isf, 0)
	}

	average := state.averageISF()

	if delta := fxp.Abs16(fxp.Sub16(average[0], initialISF[0])); delta > 8 {
		t.Fatalf("average[0] delta = %d, want outlier replacement near initial ISF", delta)
	}
	var populated bool
	for _, sum := range state.sumD {
		populated = populated || sum != 0
	}
	if !populated {
		t.Fatal("sumD was not populated")
	}
}

func TestEncoderDTXDitheringFollowsEnergyVariation(t *testing.T) {
	var state encoderDTXState
	state.reset()
	for i := range state.logEnergyHist {
		state.logEnergyHist[i] = 100
	}
	if got := state.ditheringControl(); got != 0 {
		t.Fatalf("stationary dithering = %d, want 0", got)
	}
	for i := range state.logEnergyHist {
		if i%2 == 0 {
			state.logEnergyHist[i] = -200
		} else {
			state.logEnergyHist[i] = 500
		}
	}
	if got := state.ditheringControl(); got != 1 {
		t.Fatalf("varying dithering = %d, want 1", got)
	}
}

func TestEncoderDTXDitheringFollowsSpectralVariation(t *testing.T) {
	var state encoderDTXState
	state.reset()
	for frame := range encoderDTXHistorySize {
		for i := range lpcOrder {
			state.isfHist[frame*lpcOrder+i] = fxp.Add16(initialISF[i], int16(frame*i*300))
		}
	}
	// Computing the average also refreshes the spectral-distance state used below.
	_ = state.averageISF()

	if got := state.ditheringControl(); got != 1 {
		t.Fatalf("spectral dithering = %d, want 1", got)
	}
}

func TestEncodeHomingFrameEncodesThenResets(t *testing.T) {
	enc, err := NewEncoder(Config{Mode: Mode2385})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	if _, err := enc.Encode(nil, encoderPipelinePCM(0)); err != nil {
		t.Fatalf("Encode(warmup) error = %v", err)
	}
	if allZeroSamples(enc.oldExc[:]) {
		t.Fatal("warmup did not update encoder history")
	}
	pcm := make([]int16, FrameSamples)
	for i := range pcm {
		pcm[i] = encoderHomingFrameSample
	}
	wantEnc := *enc
	want, err := wantEnc.encodeFrameSpeech(nil, pcm)
	if err != nil {
		t.Fatalf("Encode(want homing) error = %v", err)
	}

	frame, err := enc.Encode(nil, pcm)

	if err != nil {
		t.Fatalf("Encode(homing) error = %v", err)
	}
	if !bytes.Equal(frame.Data, want) {
		t.Fatal("Encode(homing) did not encode the homing input before reset")
	}
	if !allZeroSamples(enc.oldExc[:]) || len(enc.serial) != 0 || len(enc.params) != 0 {
		t.Fatalf("encoder was not reset after homing: oldExcZero=%v serial=%d params=%d",
			allZeroSamples(enc.oldExc[:]), len(enc.serial), len(enc.params))
	}
}

func isfDistance(a []int16, b []int16) int64 {
	var distance int64
	for i := range lpcOrder {
		diff := int64(a[i]) - int64(b[i])
		distance += diff * diff
	}
	return distance
}

func TestEncodeFrameSerialUpdatesEncoderHistory(t *testing.T) {
	enc, err := NewEncoder(Config{Mode: Mode885})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	pcm := encoderPipelinePCM(0)

	serial, err := enc.encodeFrameSerial(pcm)

	if err != nil {
		t.Fatalf("encodeFrameSerial() error = %v", err)
	}
	if len(serial) != frameBits[Mode885] {
		t.Fatalf("serial bits = %d, want %d", len(serial), frameBits[Mode885])
	}
	if len(enc.params) != mustParameterCount(t, Mode885) {
		t.Fatalf("parameter count = %d, want %d", len(enc.params), mustParameterCount(t, Mode885))
	}
	if allZeroSamples(enc.oldSpeech[:]) {
		t.Fatal("old speech history was not updated")
	}
	if allZeroSamples(enc.oldExc[:]) {
		t.Fatal("excitation history was not updated")
	}
}

func encoderPipelinePCM(frameIndex int) []int16 {
	pcm := make([]int16, FrameSamples)
	for i := range pcm {
		ramp := (i*37 + frameIndex*53) % 257
		pcm[i] = int16((ramp - 128) * 64)
	}
	pcm[(frameIndex*73+19)%FrameSamples] += 2048
	return pcm
}
