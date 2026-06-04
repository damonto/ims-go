package ccid

import (
	"context"
	"errors"
	"testing"

	"github.com/ElMostafaIdrassi/goscard"
)

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
			_, err := Open(context.Background(), tt.reader)
			if err == nil || err.Error() != tt.wantError {
				t.Fatalf("Open() error = %v, want %q", err, tt.wantError)
			}
		})
	}
}

func TestOpenUsesCallerContext(t *testing.T) {
	tests := []struct {
		name    string
		context func() context.Context
		wantErr error
	}{
		{
			name: "canceled",
			context: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			wantErr: context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Open(tt.context(), "reader")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Open() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestIORequestForProtocol(t *testing.T) {
	tests := []struct {
		name     string
		protocol goscard.SCardProtocol
		want     *goscard.SCardIORequest
		wantErr  bool
	}{
		{name: "t0", protocol: goscard.SCardProtocolT0, want: &goscard.SCardIoRequestT0},
		{name: "t1", protocol: goscard.SCardProtocolT1, want: &goscard.SCardIoRequestT1},
		{name: "unsupported", protocol: goscard.SCardProtocolRaw, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ioRequestForProtocol(tt.protocol)
			if tt.wantErr {
				if err == nil {
					t.Fatal("ioRequestForProtocol() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ioRequestForProtocol() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("ioRequestForProtocol() = %p, want %p", got, tt.want)
			}
		})
	}
}
