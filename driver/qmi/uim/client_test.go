package uim

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/damonto/ims-client/driver/qmi/protocol"
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
	check func(protocol.Request)
	resp  protocol.Response
	err   error
}

func (t *fakeTransport) Do(_ context.Context, req protocol.Request) (protocol.Response, error) {
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
		return protocol.Response{}, call.err
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
					check: func(req protocol.Request) {
						if req.MessageID != protocol.QMIUIMGetFileAttributes {
							t.Fatalf("messageID = 0x%04X, want 0x%04X", req.MessageID, protocol.QMIUIMGetFileAttributes)
						}
						assertTLV(t, req.TLVs, 0x01, []byte{byte(SessionPrimaryGWProvisioning), 0x00})
						assertTLV(t, req.TLVs, 0x02, []byte{0xE2, 0x2F, 0x02, 0x00, 0x3F})
					},
					resp: successResponse(protocol.QMIUIMGetFileAttributes,
						tlvBytes(0x10, []byte{0x90, 0x00}),
						tlvBytes(0x11, encodeFileAttributes(10, 0x2FE2, 0, 0, 0, []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x21, 0x80, 0x02, 0x00, 0x0A})),
					),
				},
				{
					check: func(req protocol.Request) {
						if req.MessageID != protocol.QMIUIMReadTransparent {
							t.Fatalf("messageID = 0x%04X, want 0x%04X", req.MessageID, protocol.QMIUIMReadTransparent)
						}
						assertTLV(t, req.TLVs, 0x01, []byte{byte(SessionPrimaryGWProvisioning), 0x00})
						assertTLV(t, req.TLVs, 0x02, []byte{0x07, 0x6F, 0x04, 0x00, 0x3F, 0xFF, 0x7F})
						assertTLV(t, req.TLVs, 0x03, []byte{0x00, 0x00, 0x09, 0x00})
					},
					resp: successResponse(protocol.QMIUIMReadTransparent,
						tlvBytes(0x10, []byte{0x90, 0x00}),
						tlvBytes(0x11, encodeLengthPrefixed([]byte{0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98})),
					),
				},
				{
					check: func(req protocol.Request) {
						if req.MessageID != protocol.QMIUIMReadRecord {
							t.Fatalf("messageID = 0x%04X, want 0x%04X", req.MessageID, protocol.QMIUIMReadRecord)
						}
						assertTLV(t, req.TLVs, 0x01, append([]byte{byte(SessionCardSlot1), byte(len(isimAID))}, isimAID...))
					},
					resp: errorResponse(protocol.QMIUIMReadRecord, protocol.QMIErrorInvalidSessionType),
				},
				{
					check: func(req protocol.Request) {
						assertTLV(t, req.TLVs, 0x01, append([]byte{byte(SessionNonProvisioningSlot1), byte(len(isimAID))}, isimAID...))
						assertTLV(t, req.TLVs, 0x02, []byte{0x04, 0x6F, 0x00})
						assertTLV(t, req.TLVs, 0x03, []byte{0x01, 0x00, 0x20, 0x00})
					},
					resp: successResponse(protocol.QMIUIMReadRecord,
						tlvBytes(0x10, []byte{0x90, 0x00}),
						tlvBytes(0x11, encodeLengthPrefixed(tlvTextRecord("sip:alice@ims.example.com", 32))),
					),
				},
				{
					check: func(req protocol.Request) {
						if req.MessageID != protocol.QMIUIMAuthenticate {
							t.Fatalf("messageID = 0x%04X, want 0x%04X", req.MessageID, protocol.QMIUIMAuthenticate)
						}
						assertTLV(t, req.TLVs, 0x01, []byte{byte(SessionPrimaryGWProvisioning), 0x00})
						assertTLV(t, req.TLVs, 0x02, []byte{
							authenticate3GContext,
							0x22, 0x00,
							0x10, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
							0x10, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
						})
					},
					resp: successResponse(protocol.QMIUIMAuthenticate,
						tlvBytes(0x10, []byte{0x90, 0x00}),
						tlvBytes(0x11, encodeLengthPrefixed([]byte{0xDC, 0x00})),
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

func TestReaderSMSPPDownloadUsesCATEnvelope(t *testing.T) {
	reader := &Reader{
		Transport: &fakeTransport{
			t: t,
			calls: []transportCall{
				{
					check: func(req protocol.Request) {
						if req.Service != protocol.QMIServiceControl || req.MessageID != protocol.QMICtlCmdGetVersionInfo {
							t.Fatalf("request = service %#x message 0x%04X, want service version info", req.Service, req.MessageID)
						}
					},
					resp: successResponse(protocol.QMICtlCmdGetVersionInfo, tlvBytes(0x01, encodeServiceVersions(
						serviceVersion{Service: protocol.QMIServiceCAT2, Major: 2, Minor: 24},
					))),
				},
				{
					check: func(req protocol.Request) {
						if req.Service != protocol.QMIServiceControl || req.MessageID != protocol.QMICtlCmdAllocateClientID {
							t.Fatalf("request = service %#x message 0x%04X, want CAT2 client allocation", req.Service, req.MessageID)
						}
						assertTLV(t, req.TLVs, 0x01, []byte{byte(protocol.QMIServiceCAT2)})
					},
					resp: successResponse(protocol.QMICtlCmdAllocateClientID, tlvBytes(0x01, []byte{byte(protocol.QMIServiceCAT2), 9})),
				},
				{
					check: func(req protocol.Request) {
						if req.Service != protocol.QMIServiceCAT2 || req.ClientID != 9 || req.MessageID != protocol.QMICATSendEnvelope {
							t.Fatalf("request = service %#x client %d message 0x%04X, want CAT2 envelope", req.Service, req.ClientID, req.MessageID)
						}
						assertTLV(t, req.TLVs, 0x01, []byte{
							0x09, 0x00,
							0x10, 0x00,
							0xD1, 0x0E,
							0x82, 0x02, 0x83, 0x81,
							0x86, 0x03, 0x91, 0x21, 0x43,
							0x8B, 0x03, 0x00, 0x7F, 0xF6,
						})
						assertTLV(t, req.TLVs, 0x10, []byte{0x01})
					},
					resp: successResponse(protocol.QMICATSendEnvelope, tlvBytes(0x10, []byte{0x90, 0x00, 0x00})),
				},
			},
		},
		Slot:     1,
		ClientID: 7,
	}

	got, err := reader.SMSPPDownload(context.Background(), usimreader.SMSPPDownloadRequest{
		ServiceCenterAddress: "+1234",
		TPDU:                 []byte{0x00, 0x7F, 0xF6},
	})
	if err != nil {
		t.Fatalf("SMSPPDownload() error = %v", err)
	}
	if got.SW1 != 0x90 || got.SW2 != 0x00 {
		t.Fatalf("SMSPPDownload() status = %02X%02X, want 9000", got.SW1, got.SW2)
	}
}

func TestReaderSMSPPDownloadUsesCATWhenOnlyCATIsExposed(t *testing.T) {
	reader := &Reader{
		Transport: &fakeTransport{
			t: t,
			calls: []transportCall{
				{
					check: func(req protocol.Request) {
						if req.Service != protocol.QMIServiceControl || req.MessageID != protocol.QMICtlCmdGetVersionInfo {
							t.Fatalf("request = service %#x message 0x%04X, want service version info", req.Service, req.MessageID)
						}
					},
					resp: successResponse(protocol.QMICtlCmdGetVersionInfo, tlvBytes(0x01, encodeServiceVersions(
						serviceVersion{Service: protocol.QMIServiceCAT, Major: 1, Minor: 0},
					))),
				},
				{
					check: func(req protocol.Request) {
						if req.Service != protocol.QMIServiceControl || req.MessageID != protocol.QMICtlCmdAllocateClientID {
							t.Fatalf("request = service %#x message 0x%04X, want CAT client allocation", req.Service, req.MessageID)
						}
						assertTLV(t, req.TLVs, 0x01, []byte{byte(protocol.QMIServiceCAT)})
					},
					resp: successResponse(protocol.QMICtlCmdAllocateClientID, tlvBytes(0x01, []byte{byte(protocol.QMIServiceCAT), 10})),
				},
				{
					check: func(req protocol.Request) {
						if req.Service != protocol.QMIServiceCAT || req.ClientID != 10 || req.MessageID != protocol.QMICATSendEnvelope {
							t.Fatalf("request = service %#x client %d message 0x%04X, want CAT envelope", req.Service, req.ClientID, req.MessageID)
						}
						assertTLV(t, req.TLVs, 0x01, []byte{
							0x09, 0x00,
							0x10, 0x00,
							0xD1, 0x0E,
							0x82, 0x02, 0x83, 0x81,
							0x86, 0x03, 0x91, 0x21, 0x43,
							0x8B, 0x03, 0x00, 0x7F, 0xF6,
						})
						if _, ok := tlvValue(req.TLVs, 0x10); ok {
							t.Fatal("CAT envelope request includes slot TLV 0x10, want CAT1 request without slot")
						}
					},
					resp: successResponse(protocol.QMICATSendEnvelope, tlvBytes(0x10, []byte{0x90, 0x00, 0x00})),
				},
			},
		},
		Slot:     1,
		ClientID: 7,
	}

	got, err := reader.SMSPPDownload(context.Background(), usimreader.SMSPPDownloadRequest{
		ServiceCenterAddress: "+1234",
		TPDU:                 []byte{0x00, 0x7F, 0xF6},
	})
	if err != nil {
		t.Fatalf("SMSPPDownload() error = %v", err)
	}
	if got.SW1 != 0x90 || got.SW2 != 0x00 {
		t.Fatalf("SMSPPDownload() status = %02X%02X, want 9000", got.SW1, got.SW2)
	}
	if reader.CATService != protocol.QMIServiceCAT || reader.CATClientID != 10 {
		t.Fatalf("CAT client = service %#x client %d, want CAT client 10", reader.CATService, reader.CATClientID)
	}
}

func TestReaderSMSPPDownloadDoesNotFallbackAfterCAT2EnvelopeError(t *testing.T) {
	reader := &Reader{
		Transport: &fakeTransport{
			t: t,
			calls: []transportCall{
				{
					check: func(req protocol.Request) {
						if req.Service != protocol.QMIServiceControl || req.MessageID != protocol.QMICtlCmdGetVersionInfo {
							t.Fatalf("request = service %#x message 0x%04X, want service version info", req.Service, req.MessageID)
						}
					},
					resp: successResponse(protocol.QMICtlCmdGetVersionInfo, tlvBytes(0x01, encodeServiceVersions(
						serviceVersion{Service: protocol.QMIServiceCAT2, Major: 2, Minor: 24},
						serviceVersion{Service: protocol.QMIServiceCAT, Major: 1, Minor: 0},
					))),
				},
				{
					check: func(req protocol.Request) {
						if req.Service != protocol.QMIServiceControl || req.MessageID != protocol.QMICtlCmdAllocateClientID {
							t.Fatalf("request = service %#x message 0x%04X, want CAT2 client allocation", req.Service, req.MessageID)
						}
						assertTLV(t, req.TLVs, 0x01, []byte{byte(protocol.QMIServiceCAT2)})
					},
					resp: successResponse(protocol.QMICtlCmdAllocateClientID, tlvBytes(0x01, []byte{byte(protocol.QMIServiceCAT2), 9})),
				},
				{
					check: func(req protocol.Request) {
						if req.Service != protocol.QMIServiceCAT2 || req.ClientID != 9 || req.MessageID != protocol.QMICATSendEnvelope {
							t.Fatalf("request = service %#x client %d message 0x%04X, want CAT2 envelope", req.Service, req.ClientID, req.MessageID)
						}
					},
					resp: errorResponse(protocol.QMICATSendEnvelope, protocol.QMIErrorInvalidOperation),
				},
			},
		},
		Slot:     1,
		ClientID: 7,
	}

	if _, err := reader.SMSPPDownload(context.Background(), usimreader.SMSPPDownloadRequest{
		ServiceCenterAddress: "+1234",
		TPDU:                 []byte{0x00, 0x7F, 0xF6},
	}); err == nil || !strings.Contains(err.Error(), "Invalid operation") {
		t.Fatalf("SMSPPDownload() error = %v, want Invalid operation", err)
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
				{resp: successResponse(protocol.QMIUIMGetSlotStatus, tlvBytes(0x10, encodeSlotStatus(2)))},
			},
		},
		{
			name: "switch then ready",
			slot: 2,
			ctx:  context.Background,
			calls: []transportCall{
				{resp: successResponse(protocol.QMIUIMGetSlotStatus, tlvBytes(0x10, encodeSlotStatus(1)))},
				{
					check: func(req protocol.Request) {
						assertTLV(t, req.TLVs, 0x01, []byte{0x01})
						assertTLV(t, req.TLVs, 0x02, []byte{0x02, 0x00, 0x00, 0x00})
					},
					resp: successResponse(protocol.QMIUIMSwitchSlot),
				},
				{resp: successResponse(protocol.QMIUIMGetCardStatus, tlvBytes(0x10, encodeCardStatus(false)))},
				{resp: successResponse(protocol.QMIUIMGetCardStatus, tlvBytes(0x10, encodeCardStatus(true)))},
			},
		},
		{
			name: "unsupported get slot status",
			slot: 1,
			ctx:  context.Background,
			calls: []transportCall{
				{resp: errorResponse(protocol.QMIUIMGetSlotStatus, protocol.QMIErrorNotSupported)},
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
				{resp: successResponse(protocol.QMIUIMGetSlotStatus, tlvBytes(0x10, encodeSlotStatus(1)))},
				{resp: successResponse(protocol.QMIUIMSwitchSlot)},
				{resp: successResponse(protocol.QMIUIMGetCardStatus, tlvBytes(0x10, encodeCardStatus(false)))},
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
				check: func(req protocol.Request) {
					if req.Service != protocol.QMIServiceControl {
						t.Fatalf("Service = %v, want %v", req.Service, protocol.QMIServiceControl)
					}
					if req.ClientID != 0 {
						t.Fatalf("ClientID = %d, want 0", req.ClientID)
					}
					if req.MessageID != protocol.QMICtlCmdReleaseClientID {
						t.Fatalf("protocol.MessageID = 0x%04X, want 0x%04X", req.MessageID, protocol.QMICtlCmdReleaseClientID)
					}
					assertTLV(t, req.TLVs, 0x01, []byte{byte(protocol.QMIServiceUIM), 0x07})
				},
				resp: protocol.Response{
					Service:   protocol.QMIServiceControl,
					MessageID: protocol.QMICtlCmdReleaseClientID,
					TLVs: protocol.TLVs{
						tlvBytes(qmiTLVResult, []byte{0x00, 0x00, 0x00, 0x00}),
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

func assertTLV(t *testing.T, tlvs protocol.TLVs, typ byte, want []byte) {
	t.Helper()
	got, ok := tlvValue(tlvs, typ)
	if !ok {
		t.Fatalf("TLV 0x%02X is missing", typ)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("TLV 0x%02X = % X, want % X", typ, got, want)
	}
}

func successResponse(id protocol.MessageID, tlvs ...protocol.TLV) protocol.Response {
	return protocol.Response{
		Service:   protocol.QMIServiceUIM,
		ClientID:  7,
		MessageID: id,
		TLVs: append(protocol.TLVs{
			tlvBytes(qmiTLVResult, []byte{0x00, 0x00, 0x00, 0x00}),
		}, tlvs...),
	}
}

func errorResponse(id protocol.MessageID, err protocol.QMIError) protocol.Response {
	return protocol.Response{
		Service:   protocol.QMIServiceUIM,
		ClientID:  7,
		MessageID: id,
		TLVs: protocol.TLVs{
			tlvBytes(qmiTLVResult, []byte{0x01, 0x00, byte(err), byte(uint16(err) >> 8)}),
		},
	}
}

func encodeLengthPrefixed(data []byte) []byte {
	return append(binary.LittleEndian.AppendUint16(nil, uint16(len(data))), data...)
}

func encodeServiceVersions(versions ...serviceVersion) []byte {
	out := []byte{byte(len(versions))}
	for _, version := range versions {
		out = append(out, byte(version.Service))
		out = binary.LittleEndian.AppendUint16(out, version.Major)
		out = binary.LittleEndian.AppendUint16(out, version.Minor)
	}
	return out
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
