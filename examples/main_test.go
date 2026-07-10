package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/damonto/ims-go/wfcsetup"
)

func TestTCPAPDUFrameRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"select", []byte{0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00}},
		{"status", []byte{0x90, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeTCPAPDUFrame(&buf, tt.payload); err != nil {
				t.Fatalf("writeTCPAPDUFrame() error = %v", err)
			}

			got, err := readTCPAPDUFrame(&buf)
			if err != nil {
				t.Fatalf("readTCPAPDUFrame() error = %v", err)
			}
			if !bytes.Equal(got, tt.payload) {
				t.Fatalf("readTCPAPDUFrame() = %X, want %X", got, tt.payload)
			}
		})
	}
}

func TestReadTCPAPDUFrameRejectsInvalidFrames(t *testing.T) {
	tests := []struct {
		name    string
		frame   []byte
		wantErr string
	}{
		{
			name:    "empty payload",
			frame:   frameHeader(0),
			wantErr: "payload is empty",
		},
		{
			name:    "oversized payload",
			frame:   frameHeader(maxTCPAPDUFrameLength + 1),
			wantErr: "exceeds limit",
		},
		{
			name:    "truncated payload",
			frame:   append(frameHeader(3), 0x90, 0x00),
			wantErr: "reading APDU frame payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := readTCPAPDUFrame(bytes.NewReader(tt.frame))
			if err == nil {
				t.Fatal("readTCPAPDUFrame() error = nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("readTCPAPDUFrame() error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestTCPAPDUTransmitterTransmit(t *testing.T) {
	req := []byte{0x00, 0xA4, 0x04, 0x04, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}
	resp := []byte{0x61, 0x0F}
	client, server := net.Pipe()
	defer client.Close()

	serverErr := make(chan error, 1)
	go func() {
		defer server.Close()

		got, err := readTCPAPDUFrame(server)
		if err != nil {
			serverErr <- err
			return
		}
		if !bytes.Equal(got, req) {
			serverErr <- fmt.Errorf("server request = %X, want %X", got, req)
			return
		}
		serverErr <- writeTCPAPDUFrame(server, resp)
	}()

	tx := &tcpAPDUTransmitter{
		conn:    client,
		timeout: time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	got, err := tx.Transmit(ctx, req)
	if err != nil {
		t.Fatalf("Transmit() error = %v", err)
	}
	if !bytes.Equal(got, resp) {
		t.Fatalf("Transmit() = %X, want %X", got, resp)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func TestWFCUserActionFromError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want wfcUserAction
		ok   bool
	}{
		{
			name: "nsds websheet",
			err: &wfcsetup.Error{
				Err: wfcsetup.ErrUserActionRequired,
				Result: wfcsetup.Result{
					Scheme:  wfcsetup.SchemeNSDS,
					Carrier: "AT&T",
					Websheet: &wfcsetup.Websheet{
						URL:        "https://example.test/e911",
						Data:       "token=abc",
						Title:      "Wi-Fi Calling",
						ClientName: "WiFiCallingWebViewController",
					},
				},
			},
			want: wfcUserAction{
				Source:     "nsds",
				Carrier:    "AT&T",
				URL:        "https://example.test/e911",
				Data:       "token=abc",
				Title:      "Wi-Fi Calling",
				ClientName: "WiFiCallingWebViewController",
			},
			ok: true,
		},
		{
			name: "ts43 web flow",
			err: &wfcsetup.Error{
				Err: wfcsetup.ErrUserActionRequired,
				Result: wfcsetup.Result{
					Scheme:  wfcsetup.SchemeTS43,
					Carrier: "Carrier",
					Websheet: &wfcsetup.Websheet{
						URL:   "https://example.test/flow",
						Data:  "session=1",
						Title: "Wi-Fi Calling",
					},
				},
			},
			want: wfcUserAction{
				Source:  "ts43",
				Carrier: "Carrier",
				URL:     "https://example.test/flow",
				Data:    "session=1",
				Title:   "Wi-Fi Calling",
			},
			ok: true,
		},
		{
			name: "other error",
			err:  errors.New("boom"),
			ok:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := wfcUserActionFromError(tt.err)
			if ok != tt.ok {
				t.Fatalf("wfcUserActionFromError() ok = %v, want %v", ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("wfcUserActionFromError() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestConnectWithWFCUserActionPolling(t *testing.T) {
	tests := []struct {
		name      string
		errors    []error
		wantCalls int
		wantErr   string
	}{
		{
			name: "polls after user action",
			errors: []error{
				&wfcsetup.Error{
					Err: wfcsetup.ErrUserActionRequired,
					Result: wfcsetup.Result{
						Scheme:   wfcsetup.SchemeNSDS,
						Websheet: &wfcsetup.Websheet{URL: "https://example.test/e911"},
					},
				},
				nil,
			},
			wantCalls: 2,
		},
		{
			name: "polls after pending retry",
			errors: []error{
				&wfcsetup.Error{
					Err: wfcsetup.ErrPending,
					Result: wfcsetup.Result{
						Pending:    true,
						RetryAfter: time.Nanosecond,
					},
				},
				nil,
			},
			wantCalls: 2,
		},
		{
			name:      "returns non user action error",
			errors:    []error{errors.New("boom")},
			wantCalls: 1,
			wantErr:   "boom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls int
			err := connectWithWFCServiceFlow(context.Background(), func(context.Context) error {
				if calls >= len(tt.errors) {
					t.Fatalf("connect calls = %d, want at most %d", calls+1, len(tt.errors))
				}
				err := tt.errors[calls]
				calls++
				return err
			}, time.Nanosecond, func(context.Context, wfcUserAction) error {
				return nil
			})
			if calls != tt.wantCalls {
				t.Fatalf("connect calls = %d, want %d", calls, tt.wantCalls)
			}
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("connectWithWFCUserActionPolling() error = nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("connectWithWFCUserActionPolling() error = %q, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("connectWithWFCUserActionPolling() error = %v", err)
			}
		})
	}
}

func TestParseWFCServiceFlowCallback(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    bool
		wantErr bool
	}{
		{
			name: "done command",
			line: "DONE",
			want: true,
		},
		{
			name: "dismiss command",
			line: "DISMISS",
		},
		{
			name: "javascript entitlement changed",
			line: "VoWiFiWebServiceFlow.entitlementChanged()",
			want: true,
		},
		{
			name: "javascript dismiss",
			line: "VoWiFiWebServiceFlow.dismissFlow()",
		},
		{
			name: "adapter json",
			line: `TS43_VOWIFI_CALLBACK {"event":"entitlementChanged","href":"https://example.test"}`,
			want: true,
		},
		{
			name:    "unknown",
			line:    "status",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseWFCServiceFlowCallback(tt.line)
			if tt.wantErr {
				if err == nil {
					t.Fatal("parseWFCServiceFlowCallback() error = nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseWFCServiceFlowCallback() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("parseWFCServiceFlowCallback() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServeTCPAPDUConnForwardsAPDU(t *testing.T) {
	req := []byte{0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00}
	resp := []byte{0x90, 0x00}
	client, server := net.Pipe()

	tx := &fakeAPDUTransmitter{
		wantReq: req,
		resp:    resp,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- serveTCPAPDUConn(ctx, server, tx, time.Second)
	}()

	if err := writeTCPAPDUFrame(client, req); err != nil {
		t.Fatalf("writeTCPAPDUFrame() error = %v", err)
	}
	got, err := readTCPAPDUFrame(client)
	if err != nil {
		t.Fatalf("readTCPAPDUFrame() error = %v", err)
	}
	if !bytes.Equal(got, resp) {
		t.Fatalf("readTCPAPDUFrame() = %X, want %X", got, resp)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("client.Close() error = %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("serveTCPAPDUConn() error = %v", err)
	}
}

func frameHeader(length uint32) []byte {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], length)
	return header[:]
}

type fakeAPDUTransmitter struct {
	wantReq []byte
	resp    []byte
	closed  bool
}

func (f *fakeAPDUTransmitter) Transmit(_ context.Context, req []byte) ([]byte, error) {
	if !bytes.Equal(req, f.wantReq) {
		return nil, fmt.Errorf("Transmit() request = %X, want %X", req, f.wantReq)
	}
	if f.resp == nil {
		return nil, errors.New("missing fake response")
	}
	return append([]byte(nil), f.resp...), nil
}

func (f *fakeAPDUTransmitter) Close() error {
	f.closed = true
	return nil
}
