package command

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/damonto/ims-client/usim/apdu"
	usimreader "github.com/damonto/ims-client/usim/reader"
	"github.com/damonto/ims-client/usim/simfile"
)

type fakeReader struct {
	listApplications  func(context.Context) ([]usimreader.Application, error)
	getFileAttributes func(context.Context, usimreader.FileRef) (usimreader.FileAttributes, error)
	readTransparent   func(context.Context, usimreader.TransparentRead) ([]byte, error)
	readRecord        func(context.Context, usimreader.RecordRead) ([]byte, error)
	authenticate3G    func(context.Context, usimreader.AuthenticateRequest) ([]byte, error)
	smsPPDownload     func(context.Context, usimreader.SMSPPDownloadRequest) (usimreader.SMSPPDownloadResponse, error)
}

func (r *fakeReader) ListApplications(ctx context.Context) ([]usimreader.Application, error) {
	if r.listApplications == nil {
		return nil, errors.New("ListApplications was not expected")
	}
	return r.listApplications(ctx)
}

func (r *fakeReader) GetFileAttributes(ctx context.Context, file usimreader.FileRef) (usimreader.FileAttributes, error) {
	if r.getFileAttributes == nil {
		return usimreader.FileAttributes{}, errors.New("GetFileAttributes was not expected")
	}
	return r.getFileAttributes(ctx, file)
}

func (r *fakeReader) ReadTransparent(ctx context.Context, req usimreader.TransparentRead) ([]byte, error) {
	if r.readTransparent == nil {
		return nil, errors.New("ReadTransparent was not expected")
	}
	return r.readTransparent(ctx, req)
}

func (r *fakeReader) ReadRecord(ctx context.Context, req usimreader.RecordRead) ([]byte, error) {
	if r.readRecord == nil {
		return nil, errors.New("ReadRecord was not expected")
	}
	return r.readRecord(ctx, req)
}

func (r *fakeReader) Authenticate3G(ctx context.Context, req usimreader.AuthenticateRequest) ([]byte, error) {
	if r.authenticate3G == nil {
		return nil, errors.New("Authenticate3G was not expected")
	}
	return r.authenticate3G(ctx, req)
}

func (r *fakeReader) SMSPPDownload(ctx context.Context, req usimreader.SMSPPDownloadRequest) (usimreader.SMSPPDownloadResponse, error) {
	if r.smsPPDownload == nil {
		return usimreader.SMSPPDownloadResponse{}, errors.New("SMSPPDownload was not expected")
	}
	return r.smsPPDownload(ctx, req)
}

func (r *fakeReader) Close() error { return nil }

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
	reader := &fakeReader{
		listApplications: func(context.Context) ([]usimreader.Application, error) {
			return []usimreader.Application{
				{AID: []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}, Label: "USIM"},
			}, nil
		},
	}

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
	usimAID := []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}
	isimAID := []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04}

	tests := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "read iccid",
			check: func(t *testing.T) {
				app := App{Reader: &fakeReader{
					getFileAttributes: func(_ context.Context, file usimreader.FileRef) (usimreader.FileAttributes, error) {
						if !bytes.Equal(file.AID, usimAID) || !bytes.Equal(file.Path, []byte{0x2F, 0xE2}) {
							t.Fatalf("GetFileAttributes() file = %+v", file)
						}
						return usimreader.FileAttributes{FileStructure: simfile.StructureTransparent, FileSize: 10}, nil
					},
					readTransparent: func(_ context.Context, req usimreader.TransparentRead) ([]byte, error) {
						if req.Length != 10 {
							t.Fatalf("ReadTransparent() length = %d, want 10", req.Length)
						}
						return []byte{0x98, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0}, nil
					},
				}, AID: usimAID}

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
				app := App{Reader: &fakeReader{
					getFileAttributes: func(_ context.Context, file usimreader.FileRef) (usimreader.FileAttributes, error) {
						if !bytes.Equal(file.AID, isimAID) || !bytes.Equal(file.Path, []byte{0x6F, 0x04}) {
							t.Fatalf("GetFileAttributes() file = %+v", file)
						}
						return usimreader.FileAttributes{FileStructure: simfile.StructureLinearFixed, RecordSize: 16, RecordCount: 2}, nil
					},
					readRecord: func(_ context.Context, req usimreader.RecordRead) ([]byte, error) {
						if req.Record != 1 || req.Length != 16 {
							t.Fatalf("ReadRecord() req = %+v", req)
						}
						return append([]byte{0x80, 0x0C}, []byte("sip:test@ims\xFF\xFF")...), nil
					},
				}, AID: isimAID}

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
				app := App{Reader: &fakeReader{
					getFileAttributes: func(context.Context, usimreader.FileRef) (usimreader.FileAttributes, error) {
						return usimreader.FileAttributes{FileStructure: simfile.StructureLinearFixed, RecordSize: 16, RecordCount: 2}, nil
					},
					readRecord: func(_ context.Context, req usimreader.RecordRead) ([]byte, error) {
						switch req.Record {
						case 1:
							return []byte{0xFF, 0xFF, 0xFF}, nil
						case 2:
							return append([]byte{0x80, 0x0C}, []byte("sip:next@ims\xFF\xFF")...), nil
						default:
							t.Fatalf("ReadRecord() unexpected record %d", req.Record)
							return nil, nil
						}
					},
				}, AID: isimAID}

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
				app := App{Reader: &fakeReader{
					getFileAttributes: func(context.Context, usimreader.FileRef) (usimreader.FileAttributes, error) {
						return usimreader.FileAttributes{FileStructure: simfile.StructureLinearFixed, RecordSize: 16, RecordCount: 2}, nil
					},
					readRecord: func(context.Context, usimreader.RecordRead) ([]byte, error) {
						return []byte{0xFF, 0xFF, 0xFF}, nil
					},
				}, AID: isimAID}

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
				app := App{Reader: &fakeReader{
					getFileAttributes: func(_ context.Context, file usimreader.FileRef) (usimreader.FileAttributes, error) {
						if !bytes.Equal(file.Path, []byte{0x7F, 0x10, 0x6F, 0xE5}) {
							t.Fatalf("GetFileAttributes() file = %+v", file)
						}
						return usimreader.FileAttributes{FileStructure: simfile.StructureLinearFixed, RecordSize: 32, RecordCount: 1}, nil
					},
					readRecord: func(_ context.Context, req usimreader.RecordRead) ([]byte, error) {
						if req.Record != 1 || req.Length != 32 {
							t.Fatalf("ReadRecord() req = %+v", req)
						}
						return tlvTextRecord("sip:smsc@example.com", 32), nil
					},
				}, AID: usimAID}

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
