package uim

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"testing"

	"github.com/damonto/ims-client/usim"
)

type simTransport struct {
	files map[string]simFile
	auth  []byte
}

type simFile struct {
	attrs FileAttributes
	data  []byte
	rows  map[uint16][]byte
}

func (t *simTransport) Do(_ context.Context, req Request) (Response, error) {
	switch req.MessageID {
	case MessageGetFileAttrs:
		session, aid := decodeSessionTLV(req.TLVs)
		path := decodeFileTLV(req.TLVs)
		file, ok := t.files[simFileKey(session, aid, path)]
		if !ok {
			return errorResponse(MessageGetFileAttrs, ErrorSIMFileNotFound), nil
		}
		return successResponse(MessageGetFileAttrs,
			TLVBytes(0x10, []byte{0x90, 0x00}),
			TLVBytes(0x11, encodeFileAttributes(file.attrs.FileSize, file.attrs.FileID, file.attrs.FileType, file.attrs.RecordSize, file.attrs.RecordCount, file.attrs.Raw)),
		), nil
	case MessageReadTransparent:
		session, aid := decodeSessionTLV(req.TLVs)
		path := decodeFileTLV(req.TLVs)
		file, ok := t.files[simFileKey(session, aid, path)]
		if !ok || len(file.data) == 0 {
			return errorResponse(MessageReadTransparent, ErrorSIMFileNotFound), nil
		}
		return successResponse(MessageReadTransparent,
			TLVBytes(0x10, []byte{0x90, 0x00}),
			TLVBytes(0x11, encodeLengthPrefixed(file.data)),
		), nil
	case MessageReadRecord:
		session, aid := decodeSessionTLV(req.TLVs)
		path := decodeFileTLV(req.TLVs)
		record := decodeRecordTLV(req.TLVs)
		file, ok := t.files[simFileKey(session, aid, path)]
		if !ok {
			return errorResponse(MessageReadRecord, ErrorSIMFileNotFound), nil
		}
		row, ok := file.rows[record]
		if !ok {
			return errorResponse(MessageReadRecord, ErrorSIMFileNotFound), nil
		}
		return successResponse(MessageReadRecord,
			TLVBytes(0x10, []byte{0x90, 0x00}),
			TLVBytes(0x11, encodeLengthPrefixed(row)),
		), nil
	case MessageAuthenticate:
		return successResponse(MessageAuthenticate,
			TLVBytes(0x10, []byte{0x90, 0x00}),
			TLVBytes(0x11, encodeLengthPrefixed(t.auth)),
		), nil
	default:
		return Response{}, fmt.Errorf("unexpected message 0x%04X", req.MessageID)
	}
}

func (t *simTransport) Close() error {
	return nil
}

func TestLoadWithFakeQMITransport(t *testing.T) {
	tests := []struct {
		name      string
		transport *simTransport
		check     func(t *testing.T, card *usim.Card)
	}{
		{
			name:      "usim only with missing optional files",
			transport: newUSIMOnlyTransport(),
			check: func(t *testing.T, card *usim.Card) {
				t.Helper()
				if got := card.ICCID(); got != "8986000000000000000" {
					t.Fatalf("ICCID() = %q", got)
				}
				if got := card.IMSI(); got != "001010123456789" {
					t.Fatalf("IMSI() = %q", got)
				}
				if got := card.MNC(); got != "001" {
					t.Fatalf("MNC() = %q", got)
				}
				if got := card.SMSC(); got != "" {
					t.Fatalf("SMSC() = %q, want empty", got)
				}
				if got := card.PrivateIdentity(); got != "" {
					t.Fatalf("PrivateIdentity() = %q, want empty", got)
				}
			},
		},
		{
			name:      "usim and isim",
			transport: newUSIMISIMTransport(),
			check: func(t *testing.T, card *usim.Card) {
				t.Helper()
				if got := card.PrivateIdentity(); got != "alice@ims.example.com" {
					t.Fatalf("PrivateIdentity() = %q", got)
				}
				if got := card.PublicIdentity(); got != "sip:alice@ims.example.com" {
					t.Fatalf("PublicIdentity() = %q", got)
				}
				if got := card.HomeDomain(); got != "ims.example.com" {
					t.Fatalf("HomeDomain() = %q", got)
				}
				if got := card.ServiceCentre().PSI; got != "sip:isim-smsc@example.com" {
					t.Fatalf("ServiceCentre().PSI = %q", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &Reader{
				Transport: tt.transport,
				Slot:      1,
				ClientID:  1,
			}
			card, err := usim.Load(context.Background(), reader, slog.Default())
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			tt.check(t, card)
		})
	}
}

func TestAKAWithFakeQMITransport(t *testing.T) {
	tests := []struct {
		name  string
		body  []byte
		check func(t *testing.T, got usim.AKAResult)
	}{
		{
			name: "success",
			body: []byte{
				0xDB, 0x04, 0x11, 0x22, 0x33, 0x44,
				0x10, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
				0x10, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
			},
			check: func(t *testing.T, got usim.AKAResult) {
				t.Helper()
				if !got.IsSuccess() {
					t.Fatalf("AKA() = %+v, want success", got)
				}
			},
		},
		{
			name: "sync failure",
			body: append([]byte{0xDC, 0x0E}, bytes.Repeat([]byte{0xAA}, 14)...),
			check: func(t *testing.T, got usim.AKAResult) {
				t.Helper()
				if !got.IsSynchronizationFailure() {
					t.Fatalf("AKA() = %+v, want sync failure", got)
				}
			},
		},
		{
			name: "reject",
			body: []byte{0xDC, 0x00},
			check: func(t *testing.T, got usim.AKAResult) {
				t.Helper()
				if !got.IsAuthenticationReject() {
					t.Fatalf("AKA() = %+v, want reject", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &Reader{
				Transport: &simTransport{
					files: newUSIMOnlyTransport().files,
					auth:  tt.body,
				},
				Slot:     1,
				ClientID: 1,
			}
			card, err := usim.Load(context.Background(), reader, slog.Default())
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			got, err := card.AKA(context.Background(), bytes.Repeat([]byte{0x01}, 16), bytes.Repeat([]byte{0x02}, 16))
			if err != nil {
				t.Fatalf("AKA() error = %v", err)
			}
			tt.check(t, got)
		})
	}
}

func newUSIMOnlyTransport() *simTransport {
	files := map[string]simFile{
		simFileKey(SessionPrimaryGWProvisioning, nil, []byte{0x3F, 0x00, 0x2F, 0x00}): {
			attrs: makeAttrs(20, 0x2F00, 2, 20, 1, "620B8205422100140180020014"),
			rows: map[uint16][]byte{
				1: mustHex("610F4F07A000000087100250045553494D"),
			},
		},
		simFileKey(SessionPrimaryGWProvisioning, nil, []byte{0x3F, 0x00, 0x2F, 0xE2}): {
			attrs: makeAttrs(10, 0x2FE2, 0, 0, 0, "6208820241218002000A"),
			data:  mustHex("986800000000000000F0"),
		},
		simFileKey(SessionPrimaryGWProvisioning, nil, []byte{0x3F, 0x00, 0x7F, 0xFF, 0x6F, 0x07}): {
			attrs: makeAttrs(9, 0x6F07, 0, 0, 0, "62088202412180020009"),
			data:  mustHex("080910101032547698"),
		},
		simFileKey(SessionPrimaryGWProvisioning, nil, []byte{0x3F, 0x00, 0x7F, 0xFF, 0x6F, 0xAD}): {
			attrs: makeAttrs(4, 0x6FAD, 0, 0, 0, "62088202412180020004"),
			data:  []byte{0x00, 0x00, 0x00, 0x02},
		},
	}
	return &simTransport{files: files, auth: []byte{0xDC, 0x00}}
}

func newUSIMISIMTransport() *simTransport {
	isimAID := []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04}
	files := newUSIMOnlyTransport().files
	files[simFileKey(SessionPrimaryGWProvisioning, nil, []byte{0x3F, 0x00, 0x2F, 0x00})] = simFile{
		attrs: makeAttrs(40, 0x2F00, 2, 20, 2, "620B8205422100140280020028"),
		rows: map[uint16][]byte{
			1: mustHex("610F4F07A000000087100250045553494D"),
			2: mustHex("610F4F07A000000087100450044953494D"),
		},
	}
	files[simFileKey(SessionPrimaryGWProvisioning, nil, []byte{0x3F, 0x00, 0x7F, 0xFF, 0x6F, 0x42})] = simFile{
		attrs: makeAttrs(28, 0x6F42, 2, 28, 1, "620B82054221001C018002001C"),
		rows: map[uint16][]byte{
			1: smscRecord(28, 0x91, 0x55, 0x15, 0x00, 0x00, 0x00, 0xF0),
		},
	}
	files[simFileKey(SessionPrimaryGWProvisioning, nil, []byte{0x3F, 0x00, 0x7F, 0xFF, 0x7F, 0x10, 0x6F, 0xE5})] = simFile{
		attrs: makeAttrs(32, 0x6FE5, 2, 32, 1, "620B8205422100200180020020"),
		rows: map[uint16][]byte{
			1: tlvTextRecord("sip:usim-smsc@example.com", 32),
		},
	}
	files[simFileKey(SessionCardSlot1, isimAID, []byte{0x6F, 0x02})] = simFile{
		attrs: makeAttrs(32, 0x6F02, 0, 0, 0, "62088202412180020020"),
		data:  tlvTextBinary("alice@ims.example.com", 32),
	}
	files[simFileKey(SessionCardSlot1, isimAID, []byte{0x6F, 0x04})] = simFile{
		attrs: makeAttrs(32, 0x6F04, 2, 32, 1, "620B8205422100200180020020"),
		rows: map[uint16][]byte{
			1: tlvTextRecord("sip:alice@ims.example.com", 32),
		},
	}
	files[simFileKey(SessionCardSlot1, isimAID, []byte{0x7F, 0x10, 0x6F, 0xE5})] = simFile{
		attrs: makeAttrs(32, 0x6FE5, 2, 32, 1, "620B8205422100200180020020"),
		rows: map[uint16][]byte{
			1: tlvTextRecord("sip:isim-smsc@example.com", 32),
		},
	}
	return &simTransport{files: files, auth: []byte{0xDC, 0x00}}
}

func decodeSessionTLV(tlvs TLVs) (Session, []byte) {
	value, _ := tlvValue(tlvs, 0x01)
	if len(value) < 2 {
		return 0, nil
	}
	return Session(value[0]), bytes.Clone(value[2:])
}

func decodeFileTLV(tlvs TLVs) []byte {
	value, _ := tlvValue(tlvs, 0x02)
	if len(value) < 3 {
		return nil
	}

	fileID := binary.LittleEndian.Uint16(value[:2])
	pathLength := int(value[2])
	path := make([]byte, 0, pathLength+2)
	for i := 0; i < pathLength; i += 2 {
		path = append(path, value[3+i+1], value[3+i])
	}
	return binary.BigEndian.AppendUint16(path, fileID)
}

func decodeRecordTLV(tlvs TLVs) uint16 {
	value, _ := tlvValue(tlvs, 0x03)
	if len(value) < 2 {
		return 0
	}
	return binary.LittleEndian.Uint16(value[:2])
}

func simFileKey(session Session, aid, path []byte) string {
	return fmt.Sprintf("%d:%s:%s", session, hex.EncodeToString(aid), hex.EncodeToString(path))
}

func makeAttrs(fileSize, fileID uint16, fileType byte, recordSize, recordCount uint16, rawHex string) FileAttributes {
	return FileAttributes{
		FileSize:    fileSize,
		FileID:      fileID,
		FileType:    fileType,
		RecordSize:  recordSize,
		RecordCount: recordCount,
		Raw:         mustHex(rawHex),
	}
}

func mustHex(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func tlvTextBinary(value string, size int) []byte {
	data := append([]byte{0x80, byte(len(value))}, []byte(value)...)
	for len(data) < size {
		data = append(data, 0xFF)
	}
	return data
}

func smscRecord(size int, toa byte, digits ...byte) []byte {
	record := make([]byte, size)
	start := size - 28 + 13
	record[start] = byte(len(digits) + 1)
	record[start+1] = toa
	copy(record[start+2:], digits)
	return record
}
