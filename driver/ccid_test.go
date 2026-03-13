package driver

import (
	"testing"

	"github.com/ElMostafaIdrassi/goscard"
)

func TestCCIDSetReaderRejectsEmptyName(t *testing.T) {
	tests := []struct {
		name    string
		reader  string
		wantErr string
	}{
		{name: "empty", wantErr: "selecting reader: reader name is empty"},
		{name: "blank", reader: "   ", wantErr: "selecting reader: reader name is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := goscard.Context{}
			driver := &CCID{ctx: &ctx}
			err := driver.SetReader(tt.reader)
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("SetReader() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
