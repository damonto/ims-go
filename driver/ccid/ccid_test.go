package ccid

import "testing"

func TestOpenRejectsEmptyReaderName(t *testing.T) {
	tests := []struct {
		name      string
		reader    string
		wantError string
	}{
		{name: "empty", wantError: "opening reader: reader name is empty"},
		{name: "blank", reader: "   ", wantError: "opening reader: reader name is empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Open(tt.reader)
			if err == nil || err.Error() != tt.wantError {
				t.Fatalf("Open() error = %v, want %q", err, tt.wantError)
			}
		})
	}
}
