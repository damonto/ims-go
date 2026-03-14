package command

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/damonto/ims-client/usim/apdu"
)

type scriptReader struct {
	steps []scriptStep
	idx   int
}

type scriptStep struct {
	wantAPDU string
	resp     []byte
	err      error
}

func (r *scriptReader) Transmit(_ context.Context, req []byte) ([]byte, error) {
	step := r.steps[r.idx]
	r.idx++
	if got := strings.ToUpper(hex.EncodeToString(req)); got != step.wantAPDU {
		return nil, errors.New("unexpected request")
	}
	if step.err != nil {
		return nil, step.err
	}
	return step.resp, nil
}

func (r *scriptReader) Close() error { return nil }

func TestExecute(t *testing.T) {
	tests := []struct {
		name     string
		reader   *scriptReader
		command  Command[[]byte]
		want     []byte
		wantErr  error
		wantText string
	}{
		{
			name: "success",
			reader: &scriptReader{steps: []scriptStep{
				{wantAPDU: "00B0000010", resp: []byte{0xDE, 0xAD, 0x90, 0x00}},
			}},
			command: ReadBinary{Length: 0x10},
			want:    []byte{0xDE, 0xAD},
		},
		{
			name: "get response follow up",
			reader: &scriptReader{steps: []scriptStep{
				{wantAPDU: "00B0000010", resp: []byte{0x61, 0x02}},
				{wantAPDU: "00C0000002", resp: []byte{0xDE, 0xAD, 0x90, 0x00}},
			}},
			command: ReadBinary{Length: 0x10},
			want:    []byte{0xDE, 0xAD},
		},
		{
			name: "status error",
			reader: &scriptReader{steps: []scriptStep{
				{wantAPDU: "00B0000010", resp: []byte{0x6A, 0x82}},
			}},
			command: ReadBinary{Length: 0x10},
			wantErr: apdu.StatusError{SW: 0x6A82},
		},
		{
			name: "reader error",
			reader: &scriptReader{steps: []scriptStep{
				{wantAPDU: "00B0000010", err: errors.New("boom")},
			}},
			command:  ReadBinary{Length: 0x10},
			wantText: "boom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Execute(context.Background(), tt.reader, tt.command)
			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Execute() error = %v, want %v", err, tt.wantErr)
				}
			case tt.wantText != "":
				if err == nil || !strings.Contains(err.Error(), tt.wantText) {
					t.Fatalf("Execute() error = %v, want text %q", err, tt.wantText)
				}
			default:
				if err != nil {
					t.Fatalf("Execute() error = %v", err)
				}
				if !bytes.Equal(got, tt.want) {
					t.Fatalf("Execute() = %X, want %X", got, tt.want)
				}
			}
		})
	}
}

func TestTypedCommands(t *testing.T) {
	res := []byte{0x11, 0x22, 0x33, 0x44}
	ck := bytes.Repeat([]byte{0xAA}, 16)
	ik := bytes.Repeat([]byte{0xBB}, 16)
	auts := bytes.Repeat([]byte{0xCC}, 14)
	akaSuccess := append(
		append(
			append(
				append([]byte{0xDB, byte(len(res))}, res...),
				byte(len(ck)),
			),
			ck...,
		),
		append([]byte{byte(len(ik))}, ik...)...,
	)
	akaSuccess = append(akaSuccess, 0x90, 0x00)
	akaSyncFailure := append(append([]byte{0xDC, byte(len(auts))}, auts...), 0x90, 0x00)

	tests := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "read imsi",
			check: func(t *testing.T) {
				got, err := ReadIMSI{}.DecodeResponse(apdu.Response{0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0x90, 0x00})
				if err != nil {
					t.Fatalf("DecodeResponse() error = %v", err)
				}
				if got.Digits != "001010123456789" || got.MCC != "001" || got.MNC != "010" {
					t.Fatalf("DecodeResponse() = %+v, want digits=001010123456789 mcc=001 mnc=010", got)
				}
			},
		},
		{
			name: "read imsi keeps real leading nine",
			check: func(t *testing.T) {
				got, err := ReadIMSI{}.DecodeResponse(apdu.Response{0x08, 0x99, 0x10, 0x07, 0x10, 0x32, 0x54, 0x76, 0x98, 0x90, 0x00})
				if err != nil {
					t.Fatalf("DecodeResponse() error = %v", err)
				}
				if got.Digits != "901700123456789" || got.MCC != "901" || got.MNC != "700" {
					t.Fatalf("DecodeResponse() = %+v, want digits=901700123456789 mcc=901 mnc=700", got)
				}
			},
		},
		{
			name: "read iccid",
			check: func(t *testing.T) {
				got, err := ReadICCID{}.DecodeResponse(apdu.Response{0x98, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x90, 0x00})
				if err != nil {
					t.Fatalf("DecodeResponse() error = %v", err)
				}
				if got != "8986000000000000000" {
					t.Fatalf("DecodeResponse() = %q, want %q", got, "8986000000000000000")
				}
			},
		},
		{
			name: "read smsc malformed short record",
			check: func(t *testing.T) {
				_, err := ReadSMSCRecord{RecordSize: 10}.DecodeResponse(apdu.Response{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x00})
				if err == nil || err.Error() != "reading EF_SMSP: malformed record" {
					t.Fatalf("DecodeResponse() error = %v, want %q", err, "reading EF_SMSP: malformed record")
				}
			},
		},
		{
			name: "read smsc ignores impossible address length",
			check: func(t *testing.T) {
				record := make([]byte, 28)
				copy(record[13:25], []byte{0x0C, 0x91, 0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0x65, 0x87, 0x09})

				got, err := ReadSMSCRecord{RecordSize: 28}.DecodeResponse(apdu.Response(append(record, 0x90, 0x00)))
				if err != nil {
					t.Fatalf("DecodeResponse() error = %v", err)
				}
				if got != "" {
					t.Fatalf("DecodeResponse() = %q, want empty string", got)
				}
			},
		},
		{
			name: "read ef dir record",
			check: func(t *testing.T) {
				got, err := ReadEFDirRecord{}.DecodeResponse(apdu.Response{0x61, 0x0F, 0x4F, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0x50, 0x04, 0x55, 0x53, 0x49, 0x4D, 0x90, 0x00})
				if err != nil {
					t.Fatalf("DecodeResponse() error = %v", err)
				}
				if got.Label != "USIM" || !bytes.Equal(got.AID, []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}) {
					t.Fatalf("DecodeResponse() = %+v", got)
				}
			},
		},
		{
			name: "aka success",
			check: func(t *testing.T) {
				got, err := Authenticate3G{}.DecodeResponse(apdu.Response(akaSuccess))
				if err != nil {
					t.Fatalf("DecodeResponse() error = %v", err)
				}
				if !bytes.Equal(got.RES, res) || !bytes.Equal(got.CK, ck) || !bytes.Equal(got.IK, ik) {
					t.Fatalf("DecodeResponse() = %+v", got)
				}
			},
		},
		{
			name: "aka sync failure",
			check: func(t *testing.T) {
				got, err := Authenticate3G{}.DecodeResponse(apdu.Response(akaSyncFailure))
				if err != nil {
					t.Fatalf("DecodeResponse() error = %v", err)
				}
				if !got.IsSynchronizationFailure() || !bytes.Equal(got.AUTS, auts) {
					t.Fatalf("DecodeResponse() = %+v", got)
				}
			},
		},
		{
			name: "aka reject",
			check: func(t *testing.T) {
				got, err := Authenticate3G{}.DecodeResponse(apdu.Response{0xDC, 0x00, 0x90, 0x00})
				if err != nil {
					t.Fatalf("DecodeResponse() error = %v", err)
				}
				if !got.IsAuthenticationReject() {
					t.Fatalf("DecodeResponse() = %+v, want reject", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.check)
	}
}

func TestFindAIDRun(t *testing.T) {
	reader := &scriptReader{steps: []scriptStep{
		{wantAPDU: "00A40004023F00", resp: []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x38, 0x80, 0x02, 0x00, 0x02, 0x90, 0x00}},
		{wantAPDU: "00A40004022F00", resp: []byte{0x62, 0x0B, 0x82, 0x05, 0x42, 0x21, 0x00, 0x14, 0x01, 0x80, 0x02, 0x00, 0x14, 0x90, 0x00}},
		{wantAPDU: "00B2010414", resp: []byte{0x61, 0x0F, 0x4F, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0x50, 0x04, 0x55, 0x53, 0x49, 0x4D, 0x90, 0x00}},
	}}

	got, err := FindAID{
		Label:    "USIM",
		Prefix:   []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02},
		NotFound: errors.New("not found"),
	}.Run(context.Background(), reader)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	want := []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}
	if !bytes.Equal(got, want) {
		t.Fatalf("Run() = %X, want %X", got, want)
	}
}

func TestAppReaders(t *testing.T) {
	tests := []struct {
		name        string
		check       func(t *testing.T)
		wantErrText string
	}{
		{
			name: "read iccid",
			check: func(t *testing.T) {
				app := App{Reader: &scriptReader{steps: []scriptStep{
					{wantAPDU: "00A4040407A0000000871002", resp: []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x38, 0x80, 0x02, 0x00, 0x02, 0x90, 0x00}},
					{wantAPDU: "00A40804022FE2", resp: []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x21, 0x80, 0x02, 0x00, 0x0A, 0x90, 0x00}},
					{wantAPDU: "00B000000A", resp: []byte{0x98, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x90, 0x00}},
				}}, AID: []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}}

				got, err := app.ReadICCID(context.Background(), []byte{0x2F, 0xE2})
				if err != nil {
					t.Fatalf("ReadICCID() error = %v", err)
				}
				if got != "8986000000000000000" {
					t.Fatalf("ReadICCID() = %q, want %q", got, "8986000000000000000")
				}
			},
		},
		{
			name: "read first linear fixed text record",
			check: func(t *testing.T) {
				app := App{Reader: &scriptReader{steps: []scriptStep{
					{wantAPDU: "00A4040407A0000000871004", resp: []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x38, 0x80, 0x02, 0x00, 0x02, 0x90, 0x00}},
					{wantAPDU: "00A40004026F04", resp: []byte{0x62, 0x0B, 0x82, 0x05, 0x42, 0x21, 0x00, 0x10, 0x02, 0x80, 0x02, 0x00, 0x20, 0x90, 0x00}},
					{wantAPDU: "00B2010410", resp: append([]byte("sip:test@ims\xFF\xFF\xFF\xFF"), 0x90, 0x00)},
				}}, AID: []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04}}

				got, err := app.ReadLinearFixedTextFirst(context.Background(), []byte{0x6F, 0x04}, "reading EF_IMPU")
				if err != nil {
					t.Fatalf("ReadLinearFixedTextFirst() error = %v", err)
				}
				if got != "sip:test@ims" {
					t.Fatalf("ReadLinearFixedTextFirst() = %q, want %q", got, "sip:test@ims")
				}
			},
		},
		{
			name: "skip empty first record",
			check: func(t *testing.T) {
				app := App{Reader: &scriptReader{steps: []scriptStep{
					{wantAPDU: "00A4040407A0000000871004", resp: []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x38, 0x80, 0x02, 0x00, 0x02, 0x90, 0x00}},
					{wantAPDU: "00A40004026F04", resp: []byte{0x62, 0x0B, 0x82, 0x05, 0x42, 0x21, 0x00, 0x10, 0x02, 0x80, 0x02, 0x00, 0x20, 0x90, 0x00}},
					{wantAPDU: "00B2010410", resp: []byte{0xFF, 0xFF, 0xFF, 0x90, 0x00}},
					{wantAPDU: "00B2020410", resp: append([]byte("sip:next@ims\xFF\xFF\xFF\xFF"), 0x90, 0x00)},
				}}, AID: []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04}}

				got, err := app.ReadLinearFixedTextFirst(context.Background(), []byte{0x6F, 0x04}, "reading EF_IMPU")
				if err != nil {
					t.Fatalf("ReadLinearFixedTextFirst() error = %v", err)
				}
				if got != "sip:next@ims" {
					t.Fatalf("ReadLinearFixedTextFirst() = %q, want %q", got, "sip:next@ims")
				}
			},
		},
		{
			name: "no populated record is an error",
			check: func(t *testing.T) {
				app := App{Reader: &scriptReader{steps: []scriptStep{
					{wantAPDU: "00A4040407A0000000871004", resp: []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x38, 0x80, 0x02, 0x00, 0x02, 0x90, 0x00}},
					{wantAPDU: "00A40004026F04", resp: []byte{0x62, 0x0B, 0x82, 0x05, 0x42, 0x21, 0x00, 0x10, 0x02, 0x80, 0x02, 0x00, 0x20, 0x90, 0x00}},
					{wantAPDU: "00B2010410", resp: []byte{0xFF, 0xFF, 0xFF, 0x90, 0x00}},
					{wantAPDU: "00B2020410", resp: []byte{0xFF, 0xFF, 0xFF, 0x90, 0x00}},
				}}, AID: []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04}}

				_, err := app.ReadLinearFixedTextFirst(context.Background(), []byte{0x6F, 0x04}, "reading EF_IMPU")
				if err == nil {
					t.Fatal("ReadLinearFixedTextFirst() error = nil, want non-nil")
				}
				if !strings.Contains(err.Error(), "no populated record") {
					t.Fatalf("ReadLinearFixedTextFirst() error = %v, want no populated record", err)
				}
			},
		},
		{
			name: "read telecom psi smsc by path",
			check: func(t *testing.T) {
				app := App{Reader: &scriptReader{steps: []scriptStep{
					{wantAPDU: "00A4040407A0000000871002", resp: []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x38, 0x80, 0x02, 0x00, 0x02, 0x90, 0x00}},
					{wantAPDU: "00A40804047F106FE5", resp: []byte{0x62, 0x0B, 0x82, 0x05, 0x42, 0x21, 0x00, 0x20, 0x01, 0x80, 0x02, 0x00, 0x20, 0x90, 0x00}},
					{wantAPDU: "00B2010420", resp: append(tlvTextRecord("sip:smsc@example.com", 32), 0x90, 0x00)},
				}}, AID: []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}}

				got, err := app.ReadLinearFixedTextPathFirst(context.Background(), []byte{0x7F, 0x10, 0x6F, 0xE5}, "reading EFPSISMSC")
				if err != nil {
					t.Fatalf("ReadLinearFixedTextPathFirst() error = %v", err)
				}
				if got != "sip:smsc@example.com" {
					t.Fatalf("ReadLinearFixedTextPathFirst() = %q, want %q", got, "sip:smsc@example.com")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.check)
	}
}

func tlvTextRecord(value string, size int) []byte {
	record := append([]byte{0x80, byte(len(value))}, []byte(value)...)
	for len(record) < size {
		record = append(record, 0xFF)
	}
	return record
}
