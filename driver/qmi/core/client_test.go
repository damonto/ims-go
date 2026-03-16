package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	usimreader "github.com/damonto/ims-client/usim/reader"
	"github.com/damonto/ims-client/usim/simfile"
)

type fakeTransport struct {
	t          *testing.T
	calls      []transportCall
	idx        int
	closeCalls int
	closeErr   error
}

type transportCall struct {
	check func(Request)
	resp  Response
	err   error
}

func (t *fakeTransport) Do(_ context.Context, req Request) (Response, error) {
	t.t.Helper()
	if t.idx >= len(t.calls) {
		t.t.Fatalf("Do() got unexpected request: %+v", req)
	}

	call := t.calls[t.idx]
	t.idx++
	if call.check != nil {
		call.check(req)
	}
	if call.err != nil {
		return Response{}, call.err
	}
	return call.resp, nil
}

func (t *fakeTransport) Close() error {
	t.closeCalls++
	return t.closeErr
}

func TestReaderUIMMessages(t *testing.T) {
	isimAID := []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04}
	reader := &Reader{
		Transport: &fakeTransport{
			t: t,
			calls: []transportCall{
				{
					check: func(req Request) {
						if req.MessageID != MessageGetFileAttrs {
							t.Fatalf("messageID = 0x%04X, want 0x%04X", req.MessageID, MessageGetFileAttrs)
						}
						assertTLV(t, req.TLVs, 0x01, []byte{byte(SessionPrimaryGWProvisioning), 0x00})
						assertTLV(t, req.TLVs, 0x02, []byte{0xE2, 0x2F, 0x02, 0x00, 0x3F})
					},
					resp: successResponse(MessageGetFileAttrs,
						TLVBytes(0x10, []byte{0x90, 0x00}),
						TLVBytes(0x11, encodeFileAttributes(10, 0x2FE2, 0, 0, 0, []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x21, 0x80, 0x02, 0x00, 0x0A})),
					),
				},
				{
					check: func(req Request) {
						if req.MessageID != MessageReadTransparent {
							t.Fatalf("messageID = 0x%04X, want 0x%04X", req.MessageID, MessageReadTransparent)
						}
						assertTLV(t, req.TLVs, 0x01, []byte{byte(SessionPrimaryGWProvisioning), 0x00})
						assertTLV(t, req.TLVs, 0x02, []byte{0x07, 0x6F, 0x04, 0x00, 0x3F, 0xFF, 0x7F})
						assertTLV(t, req.TLVs, 0x03, []byte{0x00, 0x00, 0x09, 0x00})
					},
					resp: successResponse(MessageReadTransparent,
						TLVBytes(0x10, []byte{0x90, 0x00}),
						TLVBytes(0x11, encodeLengthPrefixed([]byte{0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98})),
					),
				},
				{
					check: func(req Request) {
						if req.MessageID != MessageReadRecord {
							t.Fatalf("messageID = 0x%04X, want 0x%04X", req.MessageID, MessageReadRecord)
						}
						assertTLV(t, req.TLVs, 0x01, append([]byte{byte(SessionCardSlot1), byte(len(isimAID))}, isimAID...))
					},
					resp: errorResponse(MessageReadRecord, ErrorInvalidSessionType),
				},
				{
					check: func(req Request) {
						assertTLV(t, req.TLVs, 0x01, append([]byte{byte(SessionNonProvisioningSlot1), byte(len(isimAID))}, isimAID...))
						assertTLV(t, req.TLVs, 0x02, []byte{0x04, 0x6F, 0x00})
						assertTLV(t, req.TLVs, 0x03, []byte{0x01, 0x00, 0x20, 0x00})
					},
					resp: successResponse(MessageReadRecord,
						TLVBytes(0x10, []byte{0x90, 0x00}),
						TLVBytes(0x11, encodeLengthPrefixed(tlvTextRecord("sip:alice@ims.example.com", 32))),
					),
				},
				{
					check: func(req Request) {
						if req.MessageID != MessageAuthenticate {
							t.Fatalf("messageID = 0x%04X, want 0x%04X", req.MessageID, MessageAuthenticate)
						}
						assertTLV(t, req.TLVs, 0x01, []byte{byte(SessionPrimaryGWProvisioning), 0x00})
						assertTLV(t, req.TLVs, 0x02, []byte{
							Authenticate3GContext,
							0x22, 0x00,
							0x10, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
							0x10, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
						})
					},
					resp: successResponse(MessageAuthenticate,
						TLVBytes(0x10, []byte{0x90, 0x00}),
						TLVBytes(0x11, encodeLengthPrefixed([]byte{0xDC, 0x00})),
					),
				},
			},
		},
		Slot:     1,
		ClientID: 7,
	}

	attrs, err := reader.GetFileAttributes(context.Background(), usimreader.FileRef{Path: []byte{0x2F, 0xE2}})
	if err != nil {
		t.Fatalf("GetFileAttributes() error = %v", err)
	}
	if attrs.FileStructure != simfile.StructureTransparent || attrs.FileSize != 10 {
		t.Fatalf("GetFileAttributes() = %+v", attrs)
	}

	imsiRaw, err := reader.ReadTransparent(context.Background(), usimreader.TransparentRead{
		File:   usimreader.FileRef{AID: []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}, Path: []byte{0x6F, 0x07}},
		Length: 9,
	})
	if err != nil {
		t.Fatalf("ReadTransparent() error = %v", err)
	}
	if !bytes.Equal(imsiRaw, []byte{0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98}) {
		t.Fatalf("ReadTransparent() = %X", imsiRaw)
	}

	impuRaw, err := reader.ReadRecord(context.Background(), usimreader.RecordRead{
		File:   usimreader.FileRef{AID: isimAID, Path: []byte{0x6F, 0x04}},
		Record: 1,
		Length: 32,
	})
	if err != nil {
		t.Fatalf("ReadRecord() error = %v", err)
	}
	if !bytes.Equal(impuRaw, tlvTextRecord("sip:alice@ims.example.com", 32)) {
		t.Fatalf("ReadRecord() = %X", impuRaw)
	}

	auth, err := reader.Authenticate3G(context.Background(), usimreader.AuthenticateRequest{
		Rand: bytes.Repeat([]byte{0x01}, 16),
		AUTN: bytes.Repeat([]byte{0x02}, 16),
	})
	if err != nil {
		t.Fatalf("Authenticate3G() error = %v", err)
	}
	if !bytes.Equal(auth, []byte{0xDC, 0x00}) {
		t.Fatalf("Authenticate3G() = %X, want DC00", auth)
	}
}

func TestFileRequestStrategy(t *testing.T) {
	isimAID := []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04}
	usimAID := []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}

	tests := []struct {
		name         string
		file         usimreader.FileRef
		wantPath     []byte
		wantSessions []sessionRequest
	}{
		{
			name:         "mf file uses primary provisioning session",
			file:         usimreader.FileRef{Path: []byte{0x2F, 0xE2}},
			wantPath:     []byte{0x3F, 0x00, 0x2F, 0xE2},
			wantSessions: []sessionRequest{{session: SessionPrimaryGWProvisioning}},
		},
		{
			name:         "explicit master file path is preserved",
			file:         usimreader.FileRef{Path: []byte{0x3F, 0x00, 0x2F, 0x00}},
			wantPath:     []byte{0x3F, 0x00, 0x2F, 0x00},
			wantSessions: []sessionRequest{{session: SessionPrimaryGWProvisioning}},
		},
		{
			name:         "usim app expands path through current ADF",
			file:         usimreader.FileRef{AID: usimAID, Path: []byte{0x6F, 0x07}},
			wantPath:     []byte{0x3F, 0x00, 0x7F, 0xFF, 0x6F, 0x07},
			wantSessions: []sessionRequest{{session: SessionPrimaryGWProvisioning}},
		},
		{
			name:     "isim app keeps retry session fallback",
			file:     usimreader.FileRef{AID: isimAID, Path: []byte{0x6F, 0x04}},
			wantPath: []byte{0x6F, 0x04},
			wantSessions: []sessionRequest{
				{session: SessionCardSlot1, aid: isimAID},
				{session: SessionNonProvisioningSlot1, aid: isimAID},
			},
		},
	}

	reader := &Reader{Slot: 1}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath := reader.requestFilePath(tt.file)
			if !bytes.Equal(gotPath, tt.wantPath) {
				t.Fatalf("requestFilePath() = % X, want % X", gotPath, tt.wantPath)
			}

			gotSessions, err := reader.sessionsForFile(tt.file)
			if err != nil {
				t.Fatalf("sessionsForFile() error = %v", err)
			}
			if len(gotSessions) != len(tt.wantSessions) {
				t.Fatalf("sessionsForFile() len = %d, want %d", len(gotSessions), len(tt.wantSessions))
			}
			for i := range gotSessions {
				if gotSessions[i].session != tt.wantSessions[i].session {
					t.Fatalf("sessionsForFile()[%d].session = %d, want %d", i, gotSessions[i].session, tt.wantSessions[i].session)
				}
				if !bytes.Equal(gotSessions[i].aid, tt.wantSessions[i].aid) {
					t.Fatalf("sessionsForFile()[%d].aid = % X, want % X", i, gotSessions[i].aid, tt.wantSessions[i].aid)
				}
			}
		})
	}
}

func TestEnsureSlotActivated(t *testing.T) {
	tests := []struct {
		name    string
		slot    uint8
		ctx     func() context.Context
		calls   []transportCall
		wantErr string
	}{
		{
			name: "already active",
			slot: 2,
			ctx:  context.Background,
			calls: []transportCall{
				{resp: successResponse(MessageGetSlotStatus, TLVBytes(0x10, encodeSlotStatus(2)))},
			},
		},
		{
			name: "switch then ready",
			slot: 2,
			ctx:  context.Background,
			calls: []transportCall{
				{resp: successResponse(MessageGetSlotStatus, TLVBytes(0x10, encodeSlotStatus(1)))},
				{
					check: func(req Request) {
						assertTLV(t, req.TLVs, 0x01, []byte{0x01})
						assertTLV(t, req.TLVs, 0x02, []byte{0x02, 0x00, 0x00, 0x00})
					},
					resp: successResponse(MessageSwitchSlot),
				},
				{resp: successResponse(MessageGetCardStatus, TLVBytes(0x10, encodeCardStatus(false)))},
				{resp: successResponse(MessageGetCardStatus, TLVBytes(0x10, encodeCardStatus(true)))},
			},
		},
		{
			name: "unsupported get slot status",
			slot: 1,
			ctx:  context.Background,
			calls: []transportCall{
				{resp: errorResponse(MessageGetSlotStatus, ErrorNotSupported)},
			},
		},
		{
			name: "timeout waiting for app readiness",
			slot: 2,
			ctx: func() context.Context {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				t.Cleanup(cancel)
				return ctx
			},
			calls: []transportCall{
				{resp: successResponse(MessageGetSlotStatus, TLVBytes(0x10, encodeSlotStatus(1)))},
				{resp: successResponse(MessageSwitchSlot)},
				{resp: successResponse(MessageGetCardStatus, TLVBytes(0x10, encodeCardStatus(false)))},
			},
			wantErr: "waiting for card readiness",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &Reader{
				Transport: &fakeTransport{t: t, calls: tt.calls},
				Slot:      tt.slot,
				ClientID:  7,
			}

			err := reader.ensureSlotActivated(tt.ctx())
			switch {
			case tt.wantErr == "":
				if err != nil {
					t.Fatalf("ensureSlotActivated() error = %v", err)
				}
			case err == nil || !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("ensureSlotActivated() error = %v, want text %q", err, tt.wantErr)
			}
		})
	}
}

func TestReaderCloseIsIdempotent(t *testing.T) {
	transport := &fakeTransport{
		t: t,
		calls: []transportCall{
			{
				check: func(req Request) {
					if req.Service != ServiceControl {
						t.Fatalf("Service = %v, want %v", req.Service, ServiceControl)
					}
					if req.ClientID != 0 {
						t.Fatalf("ClientID = %d, want 0", req.ClientID)
					}
					if req.MessageID != MessageReleaseClientID {
						t.Fatalf("MessageID = 0x%04X, want 0x%04X", req.MessageID, MessageReleaseClientID)
					}
					assertTLV(t, req.TLVs, 0x01, []byte{byte(ServiceUIM), 0x07})
				},
				resp: Response{
					Service:   ServiceControl,
					MessageID: MessageReleaseClientID,
					TLVs: TLVs{
						TLVBytes(TLVResult, []byte{0x00, 0x00, 0x00, 0x00}),
					},
				},
			},
		},
	}
	reader := &Reader{
		Transport: transport,
		Slot:      1,
		ClientID:  7,
	}

	if err := reader.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if transport.idx != 1 {
		t.Fatalf("Do() calls = %d, want 1", transport.idx)
	}
	if transport.closeCalls != 1 {
		t.Fatalf("Close() calls = %d, want 1", transport.closeCalls)
	}
	if reader.ClientID != 0 {
		t.Fatalf("ClientID = %d, want 0", reader.ClientID)
	}
	if reader.Transport != nil {
		t.Fatal("Transport was not cleared")
	}
}

func assertTLV(t *testing.T, tlvs TLVs, typ byte, want []byte) {
	t.Helper()
	got, ok := tlvs.Find(typ)
	if !ok {
		t.Fatalf("TLV 0x%02X is missing", typ)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("TLV 0x%02X = % X, want % X", typ, got, want)
	}
}

func successResponse(id MessageID, tlvs ...TLV) Response {
	return Response{
		Service:   ServiceUIM,
		ClientID:  7,
		MessageID: id,
		TLVs: append(TLVs{
			TLVBytes(TLVResult, []byte{0x00, 0x00, 0x00, 0x00}),
		}, tlvs...),
	}
}

func errorResponse(id MessageID, err Error) Response {
	return Response{
		Service:   ServiceUIM,
		ClientID:  7,
		MessageID: id,
		TLVs: TLVs{
			TLVBytes(TLVResult, []byte{0x01, 0x00, byte(err), byte(uint16(err) >> 8)}),
		},
	}
}

func encodeLengthPrefixed(data []byte) []byte {
	return append(binary.LittleEndian.AppendUint16(nil, uint16(len(data))), data...)
}

func encodeFileAttributes(fileSize, fileID uint16, fileType byte, recordSize, recordCount uint16, raw []byte) []byte {
	value := binary.LittleEndian.AppendUint16(nil, fileSize)
	value = binary.LittleEndian.AppendUint16(value, fileID)
	value = append(value, fileType)
	value = binary.LittleEndian.AppendUint16(value, recordSize)
	value = binary.LittleEndian.AppendUint16(value, recordCount)
	for range 5 {
		value = append(value, 0x00)
		value = binary.LittleEndian.AppendUint16(value, 0x0000)
	}
	value = binary.LittleEndian.AppendUint16(value, uint16(len(raw)))
	value = append(value, raw...)
	return value
}

func encodeSlotStatus(activeSlot uint8) []byte {
	value := []byte{0x02}
	for slot := uint8(1); slot <= 2; slot++ {
		value = binary.LittleEndian.AppendUint32(value, 2)
		slotState := uint32(0)
		if slot == activeSlot {
			slotState = 1
		}
		value = binary.LittleEndian.AppendUint32(value, slotState)
		value = append(value, 0x01, 0x00)
	}
	return value
}

func encodeCardStatus(ready bool) []byte {
	value := make([]byte, 0, 64)
	value = append(value, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	value = append(value, 0x01)
	value = append(value, 0x01)
	value = append(value, 0x00, 0x00, 0x00, 0x00)
	value = append(value, 0x01)
	state := byte(0x01)
	if ready {
		state = 0x07
	}
	value = append(value, 0x02, state)
	value = append(value, make([]byte, 28)...)
	return value
}

func tlvTextRecord(value string, size int) []byte {
	record := append([]byte{0x80, byte(len(value))}, []byte(value)...)
	for len(record) < size {
		record = append(record, 0xFF)
	}
	return record
}
