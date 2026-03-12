package driver

import (
	"errors"
	"testing"

	"github.com/damonto/ims-client/apdu"
)

func TestValidateReaderName(t *testing.T) {
	tests := []struct {
		name    string
		reader  string
		wantErr string
	}{
		{name: "ok", reader: "reader-1"},
		{name: "empty", wantErr: "selecting reader: reader name is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateReaderName(tt.reader)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("validateReaderName() error = %v", err)
			}
			if tt.wantErr != "" && (err == nil || err.Error() != tt.wantErr) {
				t.Fatalf("validateReaderName() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestEnsureReaderExists(t *testing.T) {
	tests := []struct {
		name    string
		readers []string
		wanted  string
		wantErr error
	}{
		{name: "exact match", readers: []string{"r1", "r2"}, wanted: "r2"},
		{name: "missing reader", readers: []string{"r1"}, wanted: "r2", wantErr: apdu.ErrReaderNotFound},
		{name: "no readers", wanted: "r1", wantErr: apdu.ErrReaderNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ensureReaderExists(tt.readers, tt.wanted)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ensureReaderExists() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
