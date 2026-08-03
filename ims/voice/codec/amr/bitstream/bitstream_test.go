package bitstream

import (
	"bytes"
	"encoding"
	"io"
	"testing"
)

var (
	_ encoding.BinaryAppender    = Params{}
	_ encoding.BinaryMarshaler   = Params{}
	_ encoding.BinaryUnmarshaler = (*Params)(nil)
	_ io.WriterTo                = Params{}
	_ encoding.BinaryAppender    = Speech{}
	_ encoding.BinaryMarshaler   = Speech{}
	_ encoding.BinaryUnmarshaler = (*Speech)(nil)
	_ io.WriterTo                = Speech{}
)

func TestParamsPack(t *testing.T) {
	tests := []struct {
		name    string
		widths  []int
		params  []int16
		want    []byte
		wantErr bool
	}{
		{
			name:   "packs widths",
			widths: []int{3, 2, 4},
			params: []int16{5, 2, 9},
			want:   []byte{1, 0, 1, 1, 0, 1, 0, 0, 1},
		},
		{
			name:    "rejects count",
			widths:  []int{3, 2},
			params:  []int16{1},
			wantErr: true,
		},
		{
			name:    "rejects overflow",
			widths:  []int{3},
			params:  []int16{8},
			wantErr: true,
		},
		{
			name:    "rejects negative width",
			widths:  []int{3, -1},
			params:  []int16{1, 0},
			wantErr: true,
		},
		{
			name:    "rejects width beyond int16 value range",
			widths:  []int{16},
			params:  []int16{1},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (Params{Widths: tt.widths, Values: tt.params}).Pack(nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Params.Pack() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !equalBytes(got, tt.want) {
				t.Fatalf("Params.Pack() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParamsUnmarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		widths  []int
		bits    []byte
		want    []int16
		wantErr bool
	}{
		{
			name:   "unpacks widths",
			widths: []int{3, 2, 4},
			bits:   []byte{1, 0, 1, 1, 0, 1, 0, 0, 1},
			want:   []int16{5, 2, 9},
		},
		{
			name:    "rejects bit count",
			widths:  []int{3, 2},
			bits:    []byte{1, 0, 1, 1},
			wantErr: true,
		},
		{
			name:    "rejects invalid bit",
			widths:  []int{3},
			bits:    []byte{1, 2, 0},
			wantErr: true,
		},
		{
			name:    "rejects negative width",
			widths:  []int{-1},
			bits:    nil,
			wantErr: true,
		},
		{
			name:    "rejects width beyond int16 value range",
			widths:  []int{16},
			bits:    make([]byte, 16),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := Params{Widths: tt.widths}
			err := params.UnmarshalBinary(tt.bits)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Params.UnmarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !equalInt16s(params.Values, tt.want) {
				t.Fatalf("Params.UnmarshalBinary() = %v, want %v", params.Values, tt.want)
			}
		})
	}
}

func TestParamsBinaryRoundTrip(t *testing.T) {
	want := []int16{5, 2, 9}
	data, err := (Params{Widths: []int{3, 2, 4}, Values: want}).MarshalBinary()
	if err != nil {
		t.Fatalf("Params.MarshalBinary() error = %v", err)
	}
	params := Params{Widths: []int{3, 2, 4}}
	if err := params.UnmarshalBinary(data); err != nil {
		t.Fatalf("Params.UnmarshalBinary() error = %v", err)
	}
	if !equalInt16s(params.Values, want) {
		t.Fatalf("Params.UnmarshalBinary() = %v, want %v", params.Values, want)
	}
}

func TestBinaryErrorsDoNotMutateDestinations(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "parameter pack destination",
			run: func(t *testing.T) {
				backing := []byte{9, 8}
				_, err := (Params{Widths: []int{1, 1}, Values: []int16{1, 2}}).Pack(backing[:0])
				if err == nil {
					t.Fatal("Params.Pack() error = nil")
				}
				if !equalBytes(backing, []byte{9, 8}) {
					t.Fatalf("destination = %v, want unchanged", backing)
				}
			},
		},
		{
			name: "parameter receiver",
			run: func(t *testing.T) {
				params := Params{Widths: []int{1, 1}, Values: []int16{7, 8}}
				if err := params.UnmarshalBinary([]byte{1, 2}); err == nil {
					t.Fatal("Params.UnmarshalBinary() error = nil")
				}
				if !equalInt16s(params.Values, []int16{7, 8}) {
					t.Fatalf("values = %v, want unchanged", params.Values)
				}
			},
		},
		{
			name: "speech pack destination",
			run: func(t *testing.T) {
				backing := []byte{9}
				_, err := (Speech{BitLen: 2, Serial: []byte{1, 2}}).Pack(backing[:0])
				if err == nil {
					t.Fatal("Speech.Pack() error = nil")
				}
				if !equalBytes(backing, []byte{9}) {
					t.Fatalf("destination = %v, want unchanged", backing)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

func TestParamsAppendBinaryPreservesPrefix(t *testing.T) {
	prefix := []byte{9, 8}
	got, err := (Params{
		Widths: []int{3, 2, 4},
		Values: []int16{5, 2, 9},
	}).AppendBinary(prefix)
	if err != nil {
		t.Fatalf("Params.AppendBinary() error = %v", err)
	}
	want := []byte{9, 8, 1, 0, 1, 1, 0, 1, 0, 0, 1}
	if !equalBytes(got, want) {
		t.Fatalf("Params.AppendBinary() = %v, want %v", got, want)
	}
	if !equalBytes(prefix, []byte{9, 8}) {
		t.Fatalf("prefix = %v, want unchanged", prefix)
	}
}

func TestParamsReadParamsFromWriteTo(t *testing.T) {
	tests := []struct {
		name   string
		widths []int
		values []int16
		want   []byte
	}{
		{
			name:   "writes serial bits",
			widths: []int{3, 2, 4},
			values: []int16{5, 2, 9},
			want:   []byte{1, 0, 1, 1, 0, 1, 0, 0, 1},
		},
		{
			name:   "empty vector",
			widths: nil,
			values: nil,
			want:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			n, err := (Params{Widths: tt.widths, Values: tt.values}).WriteTo(&buf)
			if err != nil {
				t.Fatalf("Params.WriteTo() error = %v", err)
			}
			if n != int64(len(tt.want)) {
				t.Fatalf("Params.WriteTo() wrote %d, want %d", n, len(tt.want))
			}
			if !equalBytes(buf.Bytes(), tt.want) {
				t.Fatalf("Params.WriteTo() = %v, want %v", buf.Bytes(), tt.want)
			}

			decoded := Params{Widths: tt.widths}
			n, err = decoded.ReadParamsFrom(bytes.NewReader(buf.Bytes()))
			if err != nil {
				t.Fatalf("Params.ReadParamsFrom() error = %v", err)
			}
			if n != int64(len(tt.want)) {
				t.Fatalf("Params.ReadParamsFrom() read %d, want %d", n, len(tt.want))
			}
			if !equalInt16s(decoded.Values, tt.values) {
				t.Fatalf("Params.ReadParamsFrom() = %v, want %v", decoded.Values, tt.values)
			}
		})
	}
}

func TestParamsReadParamsFromRejectsShortInput(t *testing.T) {
	params := Params{Widths: []int{3, 2, 4}}
	n, err := params.ReadParamsFrom(bytes.NewReader([]byte{1, 0, 1}))
	if err == nil {
		t.Fatal("Params.ReadParamsFrom() error = nil")
	}
	if n != 3 {
		t.Fatalf("Params.ReadParamsFrom() read %d, want 3", n)
	}
}

func TestSpeechRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		bits  []byte
		order []int
	}{
		{
			name: "identity",
			bits: []byte{1, 0, 1, 1, 0, 0, 1, 0, 1},
		},
		{
			name:  "ordered",
			bits:  []byte{1, 0, 1, 1, 0, 0, 1, 0},
			order: []int{7, 6, 5, 4, 3, 2, 1, 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			speech, err := (Speech{Serial: tt.bits, Order: tt.order, BitLen: len(tt.bits)}).Pack(nil)
			if err != nil {
				t.Fatalf("Speech.Pack() error = %v", err)
			}
			got := Speech{Order: tt.order, BitLen: len(tt.bits)}
			if err := got.UnmarshalBinary(speech); err != nil {
				t.Fatalf("Speech.UnmarshalBinary() error = %v", err)
			}
			if !equalBytes(got.Serial, tt.bits) {
				t.Fatalf("Speech.UnmarshalBinary() = %v, want %v", got.Serial, tt.bits)
			}
		})
	}
}

func TestSpeechBinaryRoundTrip(t *testing.T) {
	want := []byte{1, 0, 1, 1, 0, 0, 1, 0}
	order := []int{7, 6, 5, 4, 3, 2, 1, 0}
	data, err := (Speech{Serial: want, Order: order, BitLen: len(want)}).MarshalBinary()
	if err != nil {
		t.Fatalf("Speech.MarshalBinary() error = %v", err)
	}
	speech := Speech{Order: order, BitLen: len(want)}
	if err := speech.UnmarshalBinary(data); err != nil {
		t.Fatalf("Speech.UnmarshalBinary() error = %v", err)
	}
	if !equalBytes(speech.Serial, want) {
		t.Fatalf("Speech.UnmarshalBinary() = %v, want %v", speech.Serial, want)
	}
}

func TestSpeechAppendBinaryPreservesPrefix(t *testing.T) {
	prefix := []byte{9, 8}
	got, err := (Speech{
		Serial: []byte{1, 0, 1, 1, 0, 0, 1, 0},
		Order:  []int{7, 6, 5, 4, 3, 2, 1, 0},
		BitLen: 8,
	}).AppendBinary(prefix)
	if err != nil {
		t.Fatalf("Speech.AppendBinary() error = %v", err)
	}
	want := []byte{9, 8, 0x4d}
	if !equalBytes(got, want) {
		t.Fatalf("Speech.AppendBinary() = %v, want %v", got, want)
	}
	if !equalBytes(prefix, []byte{9, 8}) {
		t.Fatalf("prefix = %v, want unchanged", prefix)
	}
}

func TestSpeechReadSpeechFromWriteTo(t *testing.T) {
	tests := []struct {
		name  string
		bits  []byte
		order []int
	}{
		{
			name: "identity",
			bits: []byte{1, 0, 1, 1, 0, 0, 1, 0, 1},
		},
		{
			name:  "ordered",
			bits:  []byte{1, 0, 1, 1, 0, 0, 1, 0},
			order: []int{7, 6, 5, 4, 3, 2, 1, 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			n, err := (Speech{Serial: tt.bits, Order: tt.order, BitLen: len(tt.bits)}).WriteTo(&buf)
			if err != nil {
				t.Fatalf("Speech.WriteTo() error = %v", err)
			}
			if n != int64(ByteLen(len(tt.bits))) {
				t.Fatalf("Speech.WriteTo() wrote %d, want %d", n, ByteLen(len(tt.bits)))
			}

			decoded := Speech{Order: tt.order, BitLen: len(tt.bits)}
			n, err = decoded.ReadSpeechFrom(bytes.NewReader(buf.Bytes()))
			if err != nil {
				t.Fatalf("Speech.ReadSpeechFrom() error = %v", err)
			}
			if n != int64(buf.Len()) {
				t.Fatalf("Speech.ReadSpeechFrom() read %d, want %d", n, buf.Len())
			}
			if !equalBytes(decoded.Serial, tt.bits) {
				t.Fatalf("Speech.ReadSpeechFrom() = %v, want %v", decoded.Serial, tt.bits)
			}
		})
	}
}

func TestSpeechReadSpeechFromRejectsShortInput(t *testing.T) {
	speech := Speech{BitLen: 9}
	n, err := speech.ReadSpeechFrom(bytes.NewReader([]byte{0x80}))
	if err == nil {
		t.Fatal("Speech.ReadSpeechFrom() error = nil")
	}
	if n != 1 {
		t.Fatalf("Speech.ReadSpeechFrom() read %d, want 1", n)
	}
}

func TestSpeechPackRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		bits  []byte
		order []int
		n     int
	}{
		{
			name: "short serial",
			bits: []byte{1, 0},
			n:    3,
		},
		{
			name: "invalid bit",
			bits: []byte{1, 2, 0},
			n:    3,
		},
		{
			name:  "short order",
			bits:  []byte{1, 0, 0},
			order: []int{0, 1},
			n:     3,
		},
		{
			name:  "order outside",
			bits:  []byte{1, 0, 0},
			order: []int{0, 1, 3},
			n:     3,
		},
		{
			name:  "duplicate order",
			bits:  []byte{1, 0, 0},
			order: []int{0, 1, 1},
			n:     3,
		},
		{
			name:  "empty non-nil order",
			bits:  []byte{1, 0, 0},
			order: []int{},
			n:     3,
		},
		{
			name: "negative bit count",
			bits: nil,
			n:    -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := (Speech{Serial: tt.bits, Order: tt.order, BitLen: tt.n}).Pack(nil); err == nil {
				t.Fatal("Speech.Pack() error = nil")
			}
		})
	}
}

func equalBytes(a []byte, b []byte) bool {
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

func equalInt16s(a []int16, b []int16) bool {
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
