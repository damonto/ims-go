package amrwb

import "testing"

func TestAnalyzePitchSubframesWritesPitchParameters(t *testing.T) {
	enc := newPreparedEncoder(t, Mode1265)
	params := make([]int16, mustParameterCount(t, Mode1265))
	analysis, err := enc.analyzeSpeech(params)
	if err != nil {
		t.Fatalf("analyzeSpeech() error = %v", err)
	}

	got, err := enc.analyzePitchSubframes(analysis, params)

	if err != nil {
		t.Fatalf("analyzePitchSubframes() error = %v", err)
	}
	for subframe := range 4 {
		sf := got.subframes[subframe]
		if sf.t0 < pitchMin || sf.t0 > pitchMax {
			t.Fatalf("subframe %d t0 = %d outside pitch range", subframe, sf.t0)
		}
		if sf.t0Frac < 0 || sf.t0Frac > 3 {
			t.Fatalf("subframe %d frac = %d, want 0..3", subframe, sf.t0Frac)
		}
		if sf.param != pitchParameterIndex(Mode1265, subframe) {
			t.Fatalf("subframe %d param = %d, want %d", subframe, sf.param, pitchParameterIndex(Mode1265, subframe))
		}
		width := 9
		if sf.pitFlag != 0 {
			width = 6
		}
		if params[sf.param] < 0 || params[sf.param] >= 1<<width {
			t.Fatalf("subframe %d pitch index = %d outside %d bits", subframe, params[sf.param], width)
		}
		selectIndex := pitchSelectParameterIndex(Mode1265, subframe)
		if selectIndex < 0 {
			t.Fatalf("subframe %d select index = %d", subframe, selectIndex)
		}
		if params[selectIndex] < 0 || params[selectIndex] > 1 {
			t.Fatalf("subframe %d select = %d, want 0 or 1", subframe, params[selectIndex])
		}
		if sf.selectLP < 0 || sf.selectLP > 1 {
			t.Fatalf("subframe %d selectLP = %d, want 0 or 1", subframe, sf.selectLP)
		}
	}
}

func TestAnalyzeSubframePitchRejectsShortParamsWithoutWrites(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{name: "pitch parameter", size: pitchParameterIndex(Mode1265, 0)},
		{name: "selector parameter", size: pitchSelectParameterIndex(Mode1265, 0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := NewEncoder(Config{Mode: Mode1265})
			if err != nil {
				t.Fatalf("NewEncoder() error = %v", err)
			}
			analysis := encoderAnalysis{}
			var excitation [pitchMax + interpolationLen + frameSamples12k8 + 1]int16
			ctx := encoderSubframeContext{
				analysis:   &analysis,
				excitation: excitation[:],
				subframe:   0,
			}
			sf := encoderSubframePitch{}
			sf.target[0] = 123
			params := make([]int16, tt.size)
			excitationBefore := excitation
			sfBefore := sf
			pitchClipBefore := enc.pitchClip

			if _, err := enc.analyzeSubframePitch(ctx, &sf, initialPitchLagState(40), params); err == nil {
				t.Fatal("analyzeSubframePitch() error = nil")
			}
			if excitation != excitationBefore || sf != sfBefore || enc.pitchClip != pitchClipBefore {
				t.Fatal("analyzeSubframePitch() changed state after parameter validation error")
			}
			for i, value := range params {
				if value != 0 {
					t.Fatalf("params[%d] = %d, want unchanged zero", i, value)
				}
			}
		})
	}
}

func TestQuantizeSubframeGainRejectsShortParamsWithoutChangingState(t *testing.T) {
	enc, err := NewEncoder(Config{Mode: Mode1265})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	sf := encoderSubframePitch{param: pitchParameterIndex(Mode1265, 0)}
	gainIndex := gainParameterIndex(Mode1265, sf.param)
	params := make([]int16, gainIndex)
	gainBefore := enc.gainQuant
	pitchClipBefore := enc.pitchClip
	sfBefore := sf

	if _, err := enc.quantizeSubframeGain(&sf, false, params); err == nil {
		t.Fatal("quantizeSubframeGain() error = nil")
	}
	if enc.gainQuant != gainBefore || enc.pitchClip != pitchClipBefore || sf != sfBefore {
		t.Fatal("quantizeSubframeGain() changed state after parameter validation error")
	}
}

func TestSearchSubframeCodebookRejectsShortParamsWithoutChangingSubframe(t *testing.T) {
	tests := []struct {
		name  string
		mode  Mode
		count int
	}{
		{name: "6.60 mode", mode: Mode660, count: 1},
		{name: "8.85 mode", mode: Mode885, count: 4},
		{name: "12.65 mode", mode: Mode1265, count: 4},
		{name: "18.25 mode", mode: Mode1825, count: 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := NewEncoder(Config{Mode: tt.mode})
			if err != nil {
				t.Fatalf("NewEncoder() error = %v", err)
			}
			sf := encoderSubframePitch{param: pitchParameterIndex(tt.mode, 0)}
			sf.code[0] = 123
			codeIndex := sf.param + 2
			if tt.mode <= Mode885 {
				codeIndex = sf.param + 1
			}
			params := make([]int16, codeIndex+tt.count-1)
			sfBefore := sf

			if err := enc.searchSubframeCodebook(&sf, params); err == nil {
				t.Fatal("searchSubframeCodebook() error = nil")
			}
			if sf != sfBefore {
				t.Fatal("searchSubframeCodebook() changed subframe after parameter validation error")
			}
		})
	}
}

func TestAnalyzePitchSubframesBuildsTargetsAndExcitation(t *testing.T) {
	enc := newPreparedEncoder(t, Mode885)
	params := make([]int16, mustParameterCount(t, Mode885))
	analysis, err := enc.analyzeSpeech(params)
	if err != nil {
		t.Fatalf("analyzeSpeech() error = %v", err)
	}

	got, err := enc.analyzePitchSubframes(analysis, params)

	if err != nil {
		t.Fatalf("analyzePitchSubframes() error = %v", err)
	}
	for subframe := range got.subframes {
		if allZeroSamples(got.subframes[subframe].target[:]) {
			t.Fatalf("subframe %d target is all zero", subframe)
		}
		if allZeroSamples(got.subframes[subframe].impulse[:]) {
			t.Fatalf("subframe %d impulse response is all zero", subframe)
		}
	}
}

func TestAnalyzePitchSubframesWritesMode660CodebookParameters(t *testing.T) {
	enc := newPreparedEncoder(t, Mode660)
	params := make([]int16, mustParameterCount(t, Mode660))
	analysis, err := enc.analyzeSpeech(params)
	if err != nil {
		t.Fatalf("analyzeSpeech() error = %v", err)
	}

	got, err := enc.analyzePitchSubframes(analysis, params)

	if err != nil {
		t.Fatalf("analyzePitchSubframes() error = %v", err)
	}
	for subframe := range 4 {
		pitchIndex := pitchParameterIndex(Mode660, subframe)
		codeIndex := pitchIndex + 1
		if params[codeIndex] < 0 || params[codeIndex] >= 1<<12 {
			t.Fatalf("subframe %d code index = %d outside 12 bits", subframe, params[codeIndex])
		}
		wantCode, err := decodeAcelp2PIn64(params[codeIndex])
		if err != nil {
			t.Fatalf("subframe %d decodeAcelp2PIn64() error = %v", subframe, err)
		}
		if allZeroSamples(wantCode[:]) || allZeroSamples(got.subframes[subframe].code[:]) {
			t.Fatalf("subframe %d codebook produced an all-zero codeword", subframe)
		}
	}
	if _, err := (Params{Mode: Mode660, Values: params}).Pack(nil); err != nil {
		t.Fatalf("Params.Pack() error = %v", err)
	}
}

func TestAnalyzePitchSubframesWritesMode885CodebookParameters(t *testing.T) {
	enc := newPreparedEncoder(t, Mode885)
	params := make([]int16, mustParameterCount(t, Mode885))
	analysis, err := enc.analyzeSpeech(params)
	if err != nil {
		t.Fatalf("analyzeSpeech() error = %v", err)
	}

	got, err := enc.analyzePitchSubframes(analysis, params)

	if err != nil {
		t.Fatalf("analyzePitchSubframes() error = %v", err)
	}
	for subframe := range 4 {
		pitchIndex := pitchParameterIndex(Mode885, subframe)
		codeIndex := pitchIndex + 1
		for i := range 4 {
			if params[codeIndex+i] < 0 || params[codeIndex+i] >= 1<<5 {
				t.Fatalf("subframe %d code index %d = %d outside 5 bits",
					subframe, i, params[codeIndex+i])
			}
		}
		wantCode, err := decodeAcelp4PIn64(params[codeIndex:codeIndex+4], 20)
		if err != nil {
			t.Fatalf("subframe %d decodeAcelp4PIn64() error = %v", subframe, err)
		}
		if allZeroSamples(wantCode[:]) || allZeroSamples(got.subframes[subframe].code[:]) {
			t.Fatalf("subframe %d codebook produced an all-zero codeword", subframe)
		}
	}
	if _, err := (Params{Mode: Mode885, Values: params}).Pack(nil); err != nil {
		t.Fatalf("Params.Pack() error = %v", err)
	}
}

func TestAnalyzePitchSubframesWritesMode1265CodebookParameters(t *testing.T) {
	enc := newPreparedEncoder(t, Mode1265)
	params := make([]int16, mustParameterCount(t, Mode1265))
	analysis, err := enc.analyzeSpeech(params)
	if err != nil {
		t.Fatalf("analyzeSpeech() error = %v", err)
	}

	got, err := enc.analyzePitchSubframes(analysis, params)

	if err != nil {
		t.Fatalf("analyzePitchSubframes() error = %v", err)
	}
	for subframe := range 4 {
		pitchIndex := pitchParameterIndex(Mode1265, subframe)
		codeIndex := pitchIndex + 2
		for i := range 4 {
			if params[codeIndex+i] < 0 || params[codeIndex+i] >= 1<<9 {
				t.Fatalf("subframe %d code index %d = %d outside 9 bits",
					subframe, i, params[codeIndex+i])
			}
		}
		wantCode, err := decodeAcelp4PIn64(params[codeIndex:codeIndex+4], 36)
		if err != nil {
			t.Fatalf("subframe %d decodeAcelp4PIn64() error = %v", subframe, err)
		}
		if allZeroSamples(wantCode[:]) || allZeroSamples(got.subframes[subframe].code[:]) {
			t.Fatalf("subframe %d codebook produced an all-zero codeword", subframe)
		}
	}
	if _, err := (Params{Mode: Mode1265, Values: params}).Pack(nil); err != nil {
		t.Fatalf("Params.Pack() error = %v", err)
	}
}

func TestAnalyzePitchSubframesWritesHigherModeCodebookParameters(t *testing.T) {
	tests := []struct {
		mode   Mode
		nbits  int16
		widths [4]int
	}{
		{mode: Mode1425, nbits: 44, widths: [4]int{13, 13, 9, 9}},
		{mode: Mode1585, nbits: 52, widths: [4]int{13, 13, 13, 13}},
	}
	for _, tt := range tests {
		enc := newPreparedEncoder(t, tt.mode)
		params := make([]int16, mustParameterCount(t, tt.mode))
		analysis, err := enc.analyzeSpeech(params)
		if err != nil {
			t.Fatalf("mode %d analyzeSpeech() error = %v", tt.mode, err)
		}

		got, err := enc.analyzePitchSubframes(analysis, params)

		if err != nil {
			t.Fatalf("mode %d analyzePitchSubframes() error = %v", tt.mode, err)
		}
		for subframe := range 4 {
			pitchIndex := pitchParameterIndex(tt.mode, subframe)
			codeIndex := pitchIndex + 2
			for i, width := range tt.widths {
				if params[codeIndex+i] < 0 || params[codeIndex+i] >= 1<<width {
					t.Fatalf("mode %d subframe %d code index %d = %d outside %d bits",
						tt.mode, subframe, i, params[codeIndex+i], width)
				}
			}
			wantCode, err := decodeAcelp4PIn64(params[codeIndex:codeIndex+4], tt.nbits)
			if err != nil {
				t.Fatalf("mode %d subframe %d decodeAcelp4PIn64() error = %v", tt.mode, subframe, err)
			}
			if allZeroSamples(wantCode[:]) || allZeroSamples(got.subframes[subframe].code[:]) {
				t.Fatalf("mode %d subframe %d codebook produced an all-zero codeword",
					tt.mode, subframe)
			}
			if tt.mode == Mode2385 {
				hfIndex := highBandCorrectionParameterIndex(tt.mode, gainParameterIndex(tt.mode, pitchIndex))
				if hfIndex < 0 || hfIndex >= len(params) {
					t.Fatalf("mode %d subframe %d HF slot = %d", tt.mode, subframe, hfIndex)
				}
				if params[hfIndex] < 0 || params[hfIndex] >= 16 {
					t.Fatalf("mode %d subframe %d HF index = %d outside 4 bits",
						tt.mode, subframe, params[hfIndex])
				}
				if got.subframes[subframe].hfGainIndex != params[hfIndex] {
					t.Fatalf("mode %d subframe %d stored HF index = %d, want %d",
						tt.mode, subframe, got.subframes[subframe].hfGainIndex, params[hfIndex])
				}
			}
		}
		if _, err := (Params{Mode: tt.mode, Values: params}).Pack(nil); err != nil {
			t.Fatalf("mode %d Params.Pack() error = %v", tt.mode, err)
		}
	}
}

func TestAnalyzePitchSubframesWritesHighestModeCodebookParameters(t *testing.T) {
	tests := []struct {
		mode   Mode
		nbits  int16
		widths [8]int
	}{
		{mode: Mode1825, nbits: 64, widths: [8]int{2, 2, 2, 2, 14, 14, 14, 14}},
		{mode: Mode1985, nbits: 72, widths: [8]int{10, 10, 2, 2, 10, 10, 14, 14}},
		{mode: Mode2305, nbits: 88, widths: [8]int{11, 11, 11, 11, 11, 11, 11, 11}},
		{mode: Mode2385, nbits: 88, widths: [8]int{11, 11, 11, 11, 11, 11, 11, 11}},
	}
	for _, tt := range tests {
		enc := newPreparedEncoder(t, tt.mode)
		params := make([]int16, mustParameterCount(t, tt.mode))
		analysis, err := enc.analyzeSpeech(params)
		if err != nil {
			t.Fatalf("mode %d analyzeSpeech() error = %v", tt.mode, err)
		}

		got, err := enc.analyzePitchSubframes(analysis, params)

		if err != nil {
			t.Fatalf("mode %d analyzePitchSubframes() error = %v", tt.mode, err)
		}
		for subframe := range 4 {
			pitchIndex := pitchParameterIndex(tt.mode, subframe)
			codeIndex := pitchIndex + 2
			for i, width := range tt.widths {
				if params[codeIndex+i] < 0 || params[codeIndex+i] >= 1<<width {
					t.Fatalf("mode %d subframe %d code index %d = %d outside %d bits",
						tt.mode, subframe, i, params[codeIndex+i], width)
				}
			}
			wantCode, err := decodeAcelp4PIn64(params[codeIndex:codeIndex+8], tt.nbits)
			if err != nil {
				t.Fatalf("mode %d subframe %d decodeAcelp4PIn64() error = %v", tt.mode, subframe, err)
			}
			if allZeroSamples(wantCode[:]) || allZeroSamples(got.subframes[subframe].code[:]) {
				t.Fatalf("mode %d subframe %d codebook produced an all-zero codeword",
					tt.mode, subframe)
			}
		}
		if _, err := (Params{Mode: tt.mode, Values: params}).Pack(nil); err != nil {
			t.Fatalf("mode %d Params.Pack() error = %v", tt.mode, err)
		}
	}
}

func TestAnalyzePitchSubframesWritesGainParameters(t *testing.T) {
	for mode := Mode660; mode <= Mode2385; mode++ {
		enc := newPreparedEncoder(t, mode)
		params := make([]int16, mustParameterCount(t, mode))
		analysis, err := enc.analyzeSpeech(params)
		if err != nil {
			t.Fatalf("mode %d analyzeSpeech() error = %v", mode, err)
		}

		got, err := enc.analyzePitchSubframes(analysis, params)

		if err != nil {
			t.Fatalf("mode %d analyzePitchSubframes() error = %v", mode, err)
		}
		decGain := resetGainDecoder()
		for subframe := range 4 {
			pitchIndex := pitchParameterIndex(mode, subframe)
			gainIndex := gainParameterIndex(mode, pitchIndex)
			if gainIndex < 0 || gainIndex >= len(params) {
				t.Fatalf("mode %d subframe %d gain index slot = %d", mode, subframe, gainIndex)
			}
			width := int16(7)
			if mode <= Mode885 {
				width = 6
			}
			if params[gainIndex] < 0 || params[gainIndex] >= 1<<width {
				t.Fatalf("mode %d subframe %d gain index = %d outside %d bits",
					mode, subframe, params[gainIndex], width)
			}
			sf := got.subframes[subframe]
			if sf.gainIndex != params[gainIndex] {
				t.Fatalf("mode %d subframe %d stored gain index = %d, want %d",
					mode, subframe, sf.gainIndex, params[gainIndex])
			}
			decoded, err := decodeGain(decGain, gainDecodeInput{
				index: params[gainIndex],
				nbits: width,
				code:  sf.code[:],
			})
			if err != nil {
				t.Fatalf("mode %d subframe %d decodeGain() error = %v", mode, subframe, err)
			}
			decGain = decoded.memory
			if decoded.gains.pitch == 0 || decoded.gains.code == 0 {
				t.Fatalf("mode %d subframe %d decoded gain = pitch %d code %d, want non-zero",
					mode, subframe, decoded.gains.pitch, decoded.gains.code)
			}
		}
		if _, err := (Params{Mode: mode, Values: params}).Pack(nil); err != nil {
			t.Fatalf("mode %d Params.Pack() error = %v", mode, err)
		}
	}
}
