package evs

import (
	"errors"
	"sync"
	"testing"
)

func TestCodecRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		sampleRate int
		bandwidth  Bandwidth
		bitrate    int
	}{
		{"narrowband", SampleRateNB, BandwidthNB, 13200},
		{"wideband", SampleRateWB, BandwidthWB, 13200},
		{"super-wideband", SampleRateSWB, BandwidthSWB, 13200},
		{"fullband", SampleRateFB, BandwidthFB, 13200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			codec, err := NewCodec(ctx, Config{
				SampleRate: tt.sampleRate,
				Encoder: EncoderConfig{
					Bitrate:   tt.bitrate,
					Bandwidth: tt.bandwidth,
				},
			})
			if err != nil {
				t.Fatalf("NewCodec() error = %v", err)
			}
			defer func() {
				if err := codec.Close(ctx); err != nil {
					t.Errorf("Codec.Close() error = %v", err)
				}
			}()
			encoderDelay, err := codec.EncoderDelay(ctx)
			if err != nil || encoderDelay <= 0 {
				t.Fatalf("EncoderDelay() = %d, %v, want positive delay", encoderDelay, err)
			}
			decoderDelay, err := codec.DecoderDelay(ctx)
			if err != nil || decoderDelay <= 0 {
				t.Fatalf("DecoderDelay() = %d, %v, want positive delay", decoderDelay, err)
			}

			frame, err := codec.Encode(ctx, nil, make([]int16, codec.FrameSamples()))
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			if frame.Format != Native || frame.FrameType != 4 || frame.Bits != 264 {
				t.Fatalf("Encode() frame = %+v, want native FT=4 bits=264", frame)
			}
			pcm, err := codec.Decode(ctx, nil, frame)
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if len(pcm) != codec.FrameSamples() {
				t.Fatalf("Decode() samples = %d, want %d", len(pcm), codec.FrameSamples())
			}
		})
	}
}

func TestCodecModeSwitchAndPLC(t *testing.T) {
	ctx := t.Context()
	engine, err := NewEngine(ctx)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	defer func() {
		if err := engine.Close(ctx); err != nil {
			t.Errorf("Engine.Close() error = %v", err)
		}
	}()
	codec, err := engine.NewCodec(ctx, Config{
		SampleRate: SampleRateWB,
		Encoder:    EncoderConfig{Bitrate: 13200, Bandwidth: BandwidthWB},
	})
	if err != nil {
		t.Fatalf("NewCodec() error = %v", err)
	}
	defer func() {
		if err := codec.Close(ctx); err != nil {
			t.Errorf("Codec.Close() error = %v", err)
		}
	}()

	tests := []struct {
		name   string
		config EncoderConfig
		format Format
		ft     int
		bits   int
	}{
		{"native-mode-1", EncoderConfig{Bitrate: 13200, Bandwidth: BandwidthWB}, Native, 4, 264},
		{"amr-wb-io", EncoderConfig{Bitrate: 12650, Bandwidth: BandwidthWB}, AMRWBIO, 2, 253},
		{"native-mode-2", EncoderConfig{Bitrate: 9600, Bandwidth: BandwidthWB}, Native, 3, 192},
		{"native-rf-on", EncoderConfig{Bitrate: 13200, Bandwidth: BandwidthWB, RF: RFConfig{Offset: 2, Indicator: 1}}, Native, 4, 264},
		{"native-rf-off", EncoderConfig{Bitrate: 13200, Bandwidth: BandwidthWB}, Native, 4, 264},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := codec.Configure(ctx, tt.config); err != nil {
				t.Fatalf("Configure() error = %v", err)
			}
			frame, err := codec.Encode(ctx, nil, make([]int16, codec.FrameSamples()))
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			if frame.Format != tt.format || frame.FrameType != tt.ft || frame.Bits != tt.bits {
				t.Fatalf("Encode() frame = %+v, want format=%s FT=%d bits=%d", frame, tt.format, tt.ft, tt.bits)
			}
			if _, err := codec.Decode(ctx, nil, frame); err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
		})
	}
	if _, err := codec.DecodeLost(ctx, nil, Native); err != nil {
		t.Fatalf("DecodeLost() error = %v", err)
	}
	if err := codec.Reset(ctx); err != nil {
		t.Fatalf("Reset() error = %v", err)
	}
}

func TestCodecDTX(t *testing.T) {
	tests := []struct {
		name       string
		bitrate    int
		wantFormat Format
		wantSID    int
	}{
		{"native", 13200, Native, 12},
		{"amr-wb-io", 12650, AMRWBIO, 9},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			codec, err := NewCodec(ctx, Config{
				SampleRate: SampleRateWB,
				Encoder:    EncoderConfig{Bitrate: tt.bitrate, Bandwidth: BandwidthWB, DTX: true},
			})
			if err != nil {
				t.Fatalf("NewCodec() error = %v", err)
			}
			defer func() {
				if err := codec.Close(ctx); err != nil {
					t.Errorf("Codec.Close() error = %v", err)
				}
			}()

			seenDTX := false
			for range 50 {
				frame, err := codec.Encode(ctx, nil, make([]int16, codec.FrameSamples()))
				if err != nil {
					t.Fatalf("Encode() error = %v", err)
				}
				if _, err := codec.Decode(ctx, nil, frame); err != nil {
					t.Fatalf("Decode() error = %v", err)
				}
				if frame.Format == tt.wantFormat && (frame.FrameType == tt.wantSID || frame.FrameType == 15) {
					seenDTX = true
				}
			}
			if !seenDTX {
				t.Fatalf("Encode() emitted no %s SID/no-data frame", tt.wantFormat)
			}
		})
	}
}

func TestEngineLifecycle(t *testing.T) {
	ctx := t.Context()
	engine, err := NewEngine(ctx)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	config := Config{
		SampleRate: SampleRateWB,
		Encoder:    EncoderConfig{Bitrate: 13200, Bandwidth: BandwidthWB},
	}
	first, err := engine.NewCodec(ctx, config)
	if err != nil {
		t.Fatalf("Engine.NewCodec(first) error = %v", err)
	}
	second, err := engine.NewCodec(ctx, config)
	if err != nil {
		t.Fatalf("Engine.NewCodec(second) error = %v", err)
	}
	if err := first.Close(ctx); err != nil {
		t.Fatalf("first.Close() error = %v", err)
	}
	if err := engine.Close(ctx); err != nil {
		t.Fatalf("Engine.Close() error = %v", err)
	}
	if _, err := second.Encode(ctx, nil, make([]int16, second.FrameSamples())); !errors.Is(err, ErrClosed) {
		t.Fatalf("second.Encode() error = %v, want ErrClosed", err)
	}
	if _, err := engine.NewCodec(ctx, config); !errors.Is(err, ErrEngineClosed) {
		t.Fatalf("Engine.NewCodec() error = %v, want ErrEngineClosed", err)
	}
	if err := engine.Close(ctx); err != nil {
		t.Fatalf("second Engine.Close() error = %v", err)
	}
}

func TestEngineConcurrentCreateAndClose(t *testing.T) {
	tests := []struct {
		name     string
		creators int
	}{
		{name: "single", creators: 1},
		{name: "burst", creators: 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			engine, err := NewEngine(ctx)
			if err != nil {
				t.Fatalf("NewEngine() error = %v", err)
			}
			config := Config{
				SampleRate: SampleRateWB,
				Encoder:    EncoderConfig{Bitrate: 13200, Bandwidth: BandwidthWB},
			}
			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(tt.creators)
			for range tt.creators {
				go func() {
					defer wg.Done()
					<-start
					codec, err := engine.NewCodec(ctx, config)
					if err != nil && !errors.Is(err, ErrEngineClosed) {
						t.Errorf("Engine.NewCodec() error = %v", err)
					}
					if codec != nil {
						if err := codec.Close(ctx); err != nil {
							t.Errorf("Codec.Close() error = %v", err)
						}
					}
				}()
			}
			close(start)
			if err := engine.Close(ctx); err != nil {
				t.Fatalf("Engine.Close() error = %v", err)
			}
			wg.Wait()
		})
	}
}

func TestFrameBits(t *testing.T) {
	tests := []struct {
		name      string
		format    Format
		frameType int
		wantBits  int
		wantBytes int
	}{
		{"native-128k", Native, 11, 2560, 320},
		{"native-sid", Native, 12, 48, 6},
		{"native-no-data", Native, 15, 0, 0},
		{"io-23k85", AMRWBIO, 8, 477, 60},
		{"io-sid-with-auxiliary-bits", AMRWBIO, 9, 35, 5},
		{"io-speech-lost", AMRWBIO, 14, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bits, err := FrameBits(tt.format, tt.frameType)
			if err != nil {
				t.Fatalf("FrameBits() error = %v", err)
			}
			if bits != tt.wantBits {
				t.Errorf("FrameBits() = %d, want %d", bits, tt.wantBits)
			}
			bytes, err := FrameBytes(tt.format, tt.frameType)
			if err != nil {
				t.Fatalf("FrameBytes() error = %v", err)
			}
			if bytes != tt.wantBytes {
				t.Errorf("FrameBytes() = %d, want %d", bytes, tt.wantBytes)
			}
		})
	}
}
