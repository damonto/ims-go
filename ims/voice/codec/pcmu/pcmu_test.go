package pcmu

import (
	"slices"
	"testing"
)

func TestEncodeReferenceVectors(t *testing.T) {
	tests := []struct {
		name string
		pcm  int16
		want byte
	}{
		{name: "negative clipped", pcm: -32768, want: 0x00},
		{name: "negative quantization boundary", pcm: -31612, want: 0x01},
		{name: "negative segment boundary", pcm: -15996, want: 0x10},
		{name: "negative speech", pcm: -1000, want: 0x4e},
		{name: "negative quantum", pcm: -8, want: 0x7e},
		{name: "negative near zero", pcm: -1, want: 0x7f},
		{name: "zero", pcm: 0, want: 0xff},
		{name: "positive near zero", pcm: 1, want: 0xff},
		{name: "positive quantum", pcm: 8, want: 0xfe},
		{name: "positive speech", pcm: 1000, want: 0xce},
		{name: "positive segment boundary", pcm: 15996, want: 0x90},
		{name: "positive clipped", pcm: 32767, want: 0x80},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AppendEncode(nil, []int16{tt.pcm})
			if len(got) != 1 || got[0] != tt.want {
				t.Fatalf("AppendEncode(%d) = %x, want %02x", tt.pcm, got, tt.want)
			}
		})
	}
}

func TestDecodeReferenceVectors(t *testing.T) {
	// These fixed code words come from the ITU-T G.711 mu-law table and
	// were cross-checked against the independent zaf/g711 implementation.
	tests := []struct {
		name    string
		encoded byte
		want    int16
	}{
		{name: "negative maximum", encoded: 0x00, want: -32124},
		{name: "negative segment boundary", encoded: 0x10, want: -15996},
		{name: "negative speech", encoded: 0x4e, want: -988},
		{name: "negative quantum", encoded: 0x7e, want: -8},
		{name: "negative zero", encoded: 0x7f, want: 0},
		{name: "positive maximum", encoded: 0x80, want: 32124},
		{name: "positive segment boundary", encoded: 0x90, want: 15996},
		{name: "positive speech", encoded: 0xce, want: 988},
		{name: "positive quantum", encoded: 0xfe, want: 8},
		{name: "positive zero", encoded: 0xff, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AppendDecode(nil, []byte{tt.encoded})
			if len(got) != 1 || got[0] != tt.want {
				t.Fatalf("AppendDecode(%02x) = %v, want %d", tt.encoded, got, tt.want)
			}
		})
	}
}

func TestEncodeDecode(t *testing.T) {
	tests := []struct {
		name string
		pcm  []int16
	}{
		{name: "empty"},
		{name: "silence", pcm: []int16{0, 0, 0}},
		{name: "speech range", pcm: []int16{-12000, -1000, 0, 1000, 12000}},
		{name: "clipped range", pcm: []int16{-32768, 32767}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := AppendEncode(nil, tt.pcm)
			if len(encoded) != len(tt.pcm) {
				t.Fatalf("AppendEncode() length = %d, want %d", len(encoded), len(tt.pcm))
			}
			decoded := AppendDecode(nil, encoded)
			if len(decoded) != len(tt.pcm) {
				t.Fatalf("AppendDecode() length = %d, want %d", len(decoded), len(tt.pcm))
			}
			for i, sample := range tt.pcm {
				if difference := abs(int(decoded[i]) - int(sample)); difference > 1024 {
					t.Fatalf("round trip sample[%d] = %d, want near %d", i, decoded[i], sample)
				}
			}
		})
	}
}

func TestEncodeDecodeAppend(t *testing.T) {
	tests := []struct {
		name        string
		encodedHead []byte
		decodedHead []int16
	}{
		{name: "empty prefixes"},
		{name: "preserve prefixes", encodedHead: []byte{0x01}, decodedHead: []int16{42}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := AppendEncode(slices.Clone(tt.encodedHead), []int16{0})
			wantEncoded := append(slices.Clone(tt.encodedHead), Silence)
			if !slices.Equal(encoded, wantEncoded) {
				t.Fatalf("AppendEncode() = %v, want %v", encoded, wantEncoded)
			}

			decoded := AppendDecode(slices.Clone(tt.decodedHead), []byte{Silence})
			wantDecoded := append(slices.Clone(tt.decodedHead), 0)
			if !slices.Equal(decoded, wantDecoded) {
				t.Fatalf("AppendDecode() = %v, want %v", decoded, wantDecoded)
			}
		})
	}
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
