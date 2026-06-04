package protocol

import (
	"bytes"
	"encoding"
	"errors"
	"io"
	"os"
	"regexp"
	"testing"
)

func TestTLVsImplementBinaryMarshaler(t *testing.T) {
	var _ encoding.BinaryMarshaler = TLVs{}
}

func TestTLVMarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		tlvs    TLVs
		want    []byte
		wantErr bool
	}{
		{
			name: "valid",
			tlvs: TLVs{
				{Type: 0x02, Len: 4, Value: []byte{0x00, 0x00, 0x00, 0x00}},
				{Type: 0x10, Len: 1, Value: []byte{0xaa}},
			},
			want: []byte{
				0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x10, 0x01, 0x00, 0xaa,
			},
		},
		{
			name:    "length mismatch",
			tlvs:    TLVs{{Type: 0x10, Len: 2, Value: []byte{0xaa}}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.tlvs.MarshalBinary()
			if tt.wantErr {
				if err == nil {
					t.Fatal("MarshalBinary() error = nil, want non-nil")
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

func TestTLVReadFromReturnsWireLength(t *testing.T) {
	data := []byte{
		0x02, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x10, 0x01, 0x00,
		0xaa,
	}
	var tlvs TLVs

	n, err := tlvs.ReadFrom(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}
	if n != int64(len(data)) {
		t.Fatalf("ReadFrom length = %d, want %d", n, len(data))
	}
}

func TestTLVWriteToReturnsWireLength(t *testing.T) {
	tlvs := TLVs{
		{Type: 0x02, Len: 4, Value: []byte{0x00, 0x00, 0x00, 0x00}},
		{Type: 0x10, Len: 1, Value: []byte{0xaa}},
	}
	var buf bytes.Buffer

	n, err := tlvs.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	if n != int64(buf.Len()) {
		t.Fatalf("WriteTo length = %d, want %d", n, buf.Len())
	}
}

func TestTLVWriteToRejectsLengthMismatch(t *testing.T) {
	tlvs := TLVs{{Type: 0x10, Len: 2, Value: []byte{0xaa}}}

	_, err := tlvs.WriteTo(io.Discard)
	if err == nil {
		t.Fatal("WriteTo error = nil, want length mismatch")
	}
}

func TestQMIErrorFallbackIncludesCode(t *testing.T) {
	err := QMIError(65000)

	if got, want := err.Error(), "QMI error 65000"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, QMIError(65000)) {
		t.Fatal("QMIError should remain comparable through errors.Is")
	}
}

func TestQMIErrorInvalidArgumentHasText(t *testing.T) {
	if got, want := QMIErrorInvalidArgument.Error(), "Invalid argument"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

func TestQMIErrorLaterCodesHaveText(t *testing.T) {
	tests := map[QMIError]string{
		QMIErrorInvalidIndex:               "Invalid index",
		QMIErrorOperationInProgress:        "Operation in progress",
		QMIErrorCatEnvelopeCommandFailed:   "CAT envelope command failed",
		QMIErrorFwUpdateDiscontinuousFrame: "Firmware update discontinuous frame",
	}

	for code, want := range tests {
		if got := code.Error(); got != want {
			t.Fatalf("%d Error() = %q, want %q", code, got, want)
		}
	}
}

func TestQMIErrorTextCoversDeclaredErrors(t *testing.T) {
	data, err := os.ReadFile("errors.go")
	if err != nil {
		t.Fatalf("read errors.go: %v", err)
	}

	constRe := regexp.MustCompile(`(?m)^\s*(QMIError[A-Za-z0-9]+)\s+QMIError\s*=`)
	mapRe := regexp.MustCompile(`(?m)^\s*(QMIError[A-Za-z0-9]+):\s*"`)

	mapped := make(map[string]bool)
	for _, match := range mapRe.FindAllStringSubmatch(string(data), -1) {
		mapped[match[1]] = true
	}

	for _, match := range constRe.FindAllStringSubmatch(string(data), -1) {
		if !mapped[match[1]] {
			t.Fatalf("%s is declared but not mapped to text", match[1])
		}
	}
}
