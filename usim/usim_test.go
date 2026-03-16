package usim

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/damonto/ims-client/usim/command"
	usimreader "github.com/damonto/ims-client/usim/reader"
)

type apduScriptTransmitter struct {
	t     *testing.T
	steps []apduScriptStep
	idx   int
}

type apduScriptStep struct {
	wantAPDU string
	resp     []byte
	err      error
}

func (s *apduScriptTransmitter) Transmit(_ context.Context, req []byte) ([]byte, error) {
	s.t.Helper()
	if s.idx >= len(s.steps) {
		s.t.Fatalf("Transmit() got unexpected request %X", req)
	}
	step := s.steps[s.idx]
	s.idx++
	if got := strings.ToUpper(hex.EncodeToString(req)); got != step.wantAPDU {
		s.t.Fatalf("Transmit() APDU = %s, want %s", got, step.wantAPDU)
	}
	if step.err != nil {
		return nil, step.err
	}
	return step.resp, nil
}

func (s *apduScriptTransmitter) Close() error {
	return nil
}

func TestReaderReadTransparentUsesExpectedAPDUs(t *testing.T) {
	aid := []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}
	reader := New(&apduScriptTransmitter{
		t: t,
		steps: []apduScriptStep{
			{wantAPDU: "00A4040407A0000000871002", resp: []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x38, 0x80, 0x02, 0x00, 0x02, 0x90, 0x00}},
			{wantAPDU: "00A40004026F07", resp: []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x21, 0x80, 0x02, 0x00, 0x09, 0x90, 0x00}},
			{wantAPDU: "00B0000009", resp: []byte{0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0x90, 0x00}},
		},
	})

	got, err := reader.ReadTransparent(context.Background(), usimreader.TransparentRead{
		File:   usimreader.FileRef{AID: aid, Path: []byte{0x6F, 0x07}},
		Length: 9,
	})
	if err != nil {
		t.Fatalf("ReadTransparent() error = %v", err)
	}
	if gotText := strings.ToUpper(hex.EncodeToString(got)); gotText != "080910101032547698" {
		t.Fatalf("ReadTransparent() = %s", gotText)
	}
}

func TestReaderReadRecordFollowsGetResponse(t *testing.T) {
	reader := New(&apduScriptTransmitter{
		t: t,
		steps: []apduScriptStep{
			{wantAPDU: "00A40004023F00", resp: []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x38, 0x80, 0x02, 0x00, 0x02, 0x90, 0x00}},
			{wantAPDU: "00A40004022F00", resp: []byte{0x62, 0x0B, 0x82, 0x05, 0x42, 0x21, 0x00, 0x14, 0x01, 0x80, 0x02, 0x00, 0x14, 0x90, 0x00}},
			{wantAPDU: "00B2010414", resp: []byte{0x61, 0x0F, 0x4F, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0x50, 0x04, 0x55, 0x53, 0x49, 0x4D, 0x90, 0x00}},
			{wantAPDU: "00C000000F", resp: []byte{0x61, 0x0F, 0x4F, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0x50, 0x04, 0x55, 0x53, 0x49, 0x4D, 0x90, 0x00}},
		},
	})

	apps, err := reader.ListApplications(context.Background())
	if err != nil {
		t.Fatalf("ListApplications() error = %v", err)
	}
	if len(apps) != 1 || strings.ToUpper(hex.EncodeToString(apps[0].AID)) != "A0000000871002" {
		t.Fatalf("ListApplications() = %+v", apps)
	}
}

func TestReaderAuthenticate3GUsesExpectedAPDU(t *testing.T) {
	rand := []byte{0x01, 0x02, 0x03, 0x04}
	autn := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	want := command.Authenticate3G{Rand: rand, AUTN: autn}.APDU()

	reader := New(&apduScriptTransmitter{
		t: t,
		steps: []apduScriptStep{
			{
				wantAPDU: strings.ToUpper(hex.EncodeToString(want)),
				resp:     []byte{0xDB, 0x02, 0x11, 0x22, 0x90, 0x00},
			},
		},
	})

	got, err := reader.Authenticate3G(context.Background(), usimreader.AuthenticateRequest{Rand: rand, AUTN: autn})
	if err != nil {
		t.Fatalf("Authenticate3G() error = %v", err)
	}
	if gotText := strings.ToUpper(hex.EncodeToString(got)); gotText != "DB021122" {
		t.Fatalf("Authenticate3G() = %s", gotText)
	}
}

func TestReaderAuthenticate3GSelectsApplicationWhenAIDProvided(t *testing.T) {
	aid := []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}
	rand := []byte{0x01, 0x02, 0x03, 0x04}
	autn := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	want := command.Authenticate3G{Rand: rand, AUTN: autn}.APDU()

	reader := New(&apduScriptTransmitter{
		t: t,
		steps: []apduScriptStep{
			{
				wantAPDU: "00A4040407A0000000871002",
				resp:     []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x38, 0x80, 0x02, 0x00, 0x02, 0x90, 0x00},
			},
			{
				wantAPDU: strings.ToUpper(hex.EncodeToString(want)),
				resp:     []byte{0xDB, 0x02, 0x11, 0x22, 0x90, 0x00},
			},
		},
	})

	got, err := reader.Authenticate3G(context.Background(), usimreader.AuthenticateRequest{
		AID:  aid,
		Rand: rand,
		AUTN: autn,
	})
	if err != nil {
		t.Fatalf("Authenticate3G() error = %v", err)
	}
	if gotText := strings.ToUpper(hex.EncodeToString(got)); gotText != "DB021122" {
		t.Fatalf("Authenticate3G() = %s", gotText)
	}
}

func TestReaderAuthenticate3GClearsSelectedFileCache(t *testing.T) {
	aid := []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}
	rand := []byte{0x01, 0x02, 0x03, 0x04}
	autn := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	auth := command.Authenticate3G{Rand: rand, AUTN: autn}.APDU()

	reader := New(&apduScriptTransmitter{
		t: t,
		steps: []apduScriptStep{
			{wantAPDU: "00A4040407A0000000871002", resp: []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x38, 0x80, 0x02, 0x00, 0x02, 0x90, 0x00}},
			{wantAPDU: "00A40004026F07", resp: []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x21, 0x80, 0x02, 0x00, 0x09, 0x90, 0x00}},
			{wantAPDU: "00B0000009", resp: []byte{0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0x90, 0x00}},
			{wantAPDU: "00A4040407A0000000871002", resp: []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x38, 0x80, 0x02, 0x00, 0x02, 0x90, 0x00}},
			{wantAPDU: strings.ToUpper(hex.EncodeToString(auth)), resp: []byte{0xDB, 0x02, 0x11, 0x22, 0x90, 0x00}},
			{wantAPDU: "00A4040407A0000000871002", resp: []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x38, 0x80, 0x02, 0x00, 0x02, 0x90, 0x00}},
			{wantAPDU: "00A40004026F07", resp: []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x21, 0x80, 0x02, 0x00, 0x09, 0x90, 0x00}},
			{wantAPDU: "00B0000009", resp: []byte{0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0x90, 0x00}},
		},
	})

	req := usimreader.TransparentRead{
		File:   usimreader.FileRef{AID: aid, Path: []byte{0x6F, 0x07}},
		Length: 9,
	}
	if _, err := reader.ReadTransparent(context.Background(), req); err != nil {
		t.Fatalf("ReadTransparent() before Authenticate3G error = %v", err)
	}
	if _, err := reader.Authenticate3G(context.Background(), usimreader.AuthenticateRequest{
		AID:  aid,
		Rand: rand,
		AUTN: autn,
	}); err != nil {
		t.Fatalf("Authenticate3G() error = %v", err)
	}
	if _, err := reader.ReadTransparent(context.Background(), req); err != nil {
		t.Fatalf("ReadTransparent() after Authenticate3G error = %v", err)
	}
}

func TestReaderCloseDelegatesToTransmitter(t *testing.T) {
	tx := &closingTransmitter{}
	reader := New(tx)
	if err := reader.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !tx.closed {
		t.Fatal("Close() did not close transmitter")
	}
}

type closingTransmitter struct {
	closed bool
}

func (t *closingTransmitter) Transmit(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("unexpected transmit")
}

func (t *closingTransmitter) Close() error {
	t.closed = true
	return nil
}
