package evs

import (
	"context"
	"testing"
)

func BenchmarkEngine(b *testing.B) {
	ctx := context.Background()
	b.ReportAllocs()
	for range b.N {
		engine, err := NewEngine(ctx)
		if err != nil {
			b.Fatal(err)
		}
		if err := engine.Close(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCodec(b *testing.B) {
	ctx := context.Background()
	engine, err := NewEngine(ctx)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := engine.Close(ctx); err != nil {
			b.Errorf("Engine.Close() error = %v", err)
		}
	})

	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "native-16k-13k2",
			cfg: Config{
				SampleRate: SampleRateWB,
				Encoder:    EncoderConfig{Bitrate: 13200, Bandwidth: BandwidthWB},
			},
		},
		{
			name: "amr-wb-io-16k-12k65",
			cfg: Config{
				SampleRate: SampleRateWB,
				Encoder:    EncoderConfig{Bitrate: 12650, Bandwidth: BandwidthWB},
			},
		},
		{
			name: "native-48k-128k",
			cfg: Config{
				SampleRate: SampleRateFB,
				Encoder:    EncoderConfig{Bitrate: 128000, Bandwidth: BandwidthFB},
			},
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			benchmarkCodec(b, ctx, engine, tt.cfg)
		})
	}
}

func benchmarkCodec(b *testing.B, ctx context.Context, engine *Engine, cfg Config) {
	codec, err := engine.NewCodec(ctx, cfg)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := codec.Close(ctx); err != nil {
			b.Errorf("Codec.Close() error = %v", err)
		}
	})
	pcm := make([]int16, codec.FrameSamples())
	for i := range pcm {
		pcm[i] = int16((i%127 - 63) * 64)
	}
	encoded := make([]byte, 0, 320)
	frame, err := codec.Encode(ctx, encoded[:0], pcm)
	if err != nil {
		b.Fatal(err)
	}
	decoded := make([]int16, 0, codec.FrameSamples())

	b.Run("instantiate", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			instance, err := engine.NewCodec(ctx, cfg)
			if err != nil {
				b.Fatal(err)
			}
			if err := instance.Close(ctx); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("encode", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := codec.Encode(ctx, encoded[:0], pcm); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("decode", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := codec.Decode(ctx, decoded[:0], frame); err != nil {
				b.Fatal(err)
			}
		}
	})
}
