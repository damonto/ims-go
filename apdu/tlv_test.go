package apdu

import (
	"bytes"
	"errors"
	"testing"
)

func TestTLVMarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		item    TLV
		want    []byte
		wantErr error
	}{
		{
			name: "short form length",
			item: TLV{Tag: 0x80, Value: []byte("abc")},
			want: []byte{0x80, 0x03, 'a', 'b', 'c'},
		},
		{
			name: "long form length 0x81",
			item: TLV{Tag: 0x80, Value: make([]byte, 0x82)},
			want: append([]byte{0x80, 0x81, 0x82}, make([]byte, 0x82)...),
		},
		{
			name: "long form length 0x82",
			item: TLV{Tag: 0x80, Value: make([]byte, 0x100)},
			want: append([]byte{0x80, 0x82, 0x01, 0x00}, make([]byte, 0x100)...),
		},
		{
			name:    "reject oversized value",
			item:    TLV{Tag: 0x80, Value: make([]byte, 0x10000)},
			wantErr: errTLVValueTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.item.MarshalBinary()
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("MarshalBinary() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("MarshalBinary() = % X, want % X", got, tt.want)
			}
		})
	}
}

func TestTLVUnmarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    TLV
		wantErr error
	}{
		{
			name: "short form length",
			data: []byte{0x80, 0x03, 'a', 'b', 'c'},
			want: TLV{Tag: 0x80, Value: []byte("abc")},
		},
		{
			name: "long form length 0x81",
			data: append([]byte{0x80, 0x81, 0x82}, make([]byte, 0x82)...),
			want: TLV{Tag: 0x80, Value: make([]byte, 0x82)},
		},
		{
			name: "long form length 0x82",
			data: append([]byte{0x80, 0x82, 0x01, 0x00}, make([]byte, 0x100)...),
			want: TLV{Tag: 0x80, Value: make([]byte, 0x100)},
		},
		{
			name:    "indefinite length unsupported",
			data:    []byte{0x80, 0x80, 0x00},
			wantErr: ErrMalformedResponse,
		},
		{
			name:    "reject trailing bytes",
			data:    []byte{0x80, 0x01, 0xAA, 0x81, 0x00},
			wantErr: ErrMalformedResponse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TLV
			err := got.UnmarshalBinary(tt.data)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("UnmarshalBinary() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.Tag != tt.want.Tag {
				t.Fatalf("UnmarshalBinary().Tag = 0x%02X, want 0x%02X", got.Tag, tt.want.Tag)
			}
			if !bytes.Equal(got.Value, tt.want.Value) {
				t.Fatalf("UnmarshalBinary().Value = % X, want % X", got.Value, tt.want.Value)
			}
		})
	}
}

func TestTLVsRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		items TLVs
	}{
		{
			name: "multiple items",
			items: TLVs{
				{Tag: 0x80, Value: []byte("abc")},
				{Tag: 0x81, Value: []byte{0x01, 0x02}},
			},
		},
		{
			name:  "empty sequence",
			items: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.items.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}

			var got TLVs
			if err := got.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			if len(got) != len(tt.items) {
				t.Fatalf("len(UnmarshalBinary()) = %d, want %d", len(got), len(tt.items))
			}
			for i := range got {
				if got[i].Tag != tt.items[i].Tag {
					t.Fatalf("item %d tag = 0x%02X, want 0x%02X", i, got[i].Tag, tt.items[i].Tag)
				}
				if !bytes.Equal(got[i].Value, tt.items[i].Value) {
					t.Fatalf("item %d value = % X, want % X", i, got[i].Value, tt.items[i].Value)
				}
			}
		})
	}
}
