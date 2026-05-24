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
