package session

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func TestSTUNBindingResponseRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		peer *net.UDPAddr
	}{
		{"IPv4", &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 5060}},
		{"IPv6", &net.UDPAddr{IP: net.ParseIP("2001:db8::10"), Port: 5060}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, transactionID, err := newSTUNBindingRequest()
			if err != nil {
				t.Fatalf("newSTUNBindingRequest() error = %v", err)
			}
			packet, err := stunBindingResponse(transactionID, tt.peer)
			if err != nil {
				t.Fatalf("stunBindingResponse() error = %v", err)
			}
			var message stunMessage
			if err := message.UnmarshalBinary(packet); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if message.messageType != stunBindingSuccessResponse {
				t.Fatalf("message type = %#x, want %#x", message.messageType, stunBindingSuccessResponse)
			}
			if message.transactionID != transactionID {
				t.Fatal("transaction ID does not match request")
			}
			got, err := net.ResolveUDPAddr("udp", message.mapped)
			if err != nil {
				t.Fatalf("ResolveUDPAddr() error = %v", err)
			}
			if !got.IP.Equal(tt.peer.IP) || got.Port != tt.peer.Port {
				t.Fatalf("mapped address = %v, want %v", got, tt.peer)
			}
		})
	}
}

func TestAwaitSTUNBindingRetransmits(t *testing.T) {
	tests := []struct {
		name          string
		respondOnSend int
		wantWrites    int
	}{
		{"response after two losses", 3, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			sess, err := Open(Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			resultCh := make(chan stunResult, 1)
			transport.onWrite = func([]byte) {
				if transport.writeCount() == tt.respondOnSend {
					resultCh <- stunResult{mapped: "192.0.2.10:5060"}
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := sess.awaitSTUNBinding(ctx, transport, []byte("request"), resultCh, time.Millisecond); err != nil {
				t.Fatalf("awaitSTUNBinding() error = %v", err)
			}
			if got := transport.writeCount(); got != tt.wantWrites {
				t.Fatalf("write count = %d, want %d", got, tt.wantWrites)
			}
		})
	}
}

func TestAwaitSTUNBindingTimesOutAfterRequestLimit(t *testing.T) {
	tests := []struct {
		name       string
		wantWrites int
	}{
		{"RFC 5389 default request count", stunRequestCount},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			sess, err := Open(Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			_, err = sess.awaitSTUNBinding(context.Background(), transport, []byte("request"), make(chan stunResult), time.Millisecond)
			if err == nil {
				t.Fatal("awaitSTUNBinding() error = nil, want timeout")
			}
			if got := transport.writeCount(); got != tt.wantWrites {
				t.Fatalf("write count = %d, want %d", got, tt.wantWrites)
			}
		})
	}
}

func TestHandleSTUNBindingResponseValidation(t *testing.T) {
	tests := []struct {
		name      string
		attribute []byte
		wantError bool
	}{
		{"missing XOR-MAPPED-ADDRESS", nil, true},
		{"unknown required attribute", stunAttribute(0x1234, nil), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			sess, err := Open(Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			transactionID := [12]byte{1, 2, 3}
			resultCh := make(chan stunResult, 1)
			sess.stunPending[transactionID] = stunPendingTransaction{transport: transport, resultCh: resultCh}
			packet := append(stunHeader(stunBindingSuccessResponse, transactionID, len(tt.attribute)), tt.attribute...)
			if err := sess.handleKeepAlivePacket(context.Background(), inboundMessage{packet: packet, transport: transport, peer: transport.remote}); err != nil {
				t.Fatalf("handleKeepAlivePacket() error = %v", err)
			}
			select {
			case result := <-resultCh:
				if (result.err != nil) != tt.wantError {
					t.Fatalf("result error = %v, wantError %t", result.err, tt.wantError)
				}
			case <-time.After(time.Second):
				t.Fatal("waiting for STUN result")
			}
		})
	}
}

func TestSTUNUnknownAttributesResponse(t *testing.T) {
	tests := []struct {
		name    string
		unknown []uint16
	}{
		{"one required attribute", []uint16{0x1234}},
		{"two required attributes", []uint16{0x1234, 0x2345}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transactionID := [12]byte{9, 8, 7}
			packet := stunUnknownAttributesResponse(transactionID, tt.unknown)
			if got := binary.BigEndian.Uint16(packet[0:2]); got != stunBindingErrorResponse {
				t.Fatalf("message type = %#x, want Binding Error Response", got)
			}
			var message stunMessage
			if err := message.UnmarshalBinary(packet); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if message.transactionID != transactionID {
				t.Fatal("transaction ID does not match request")
			}
		})
	}
}

func TestSessionCloseUnblocksKeepAlive(t *testing.T) {
	tests := []struct {
		name  string
		local net.Addr
	}{
		{"UDP", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5062}},
		{"TCP", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5062}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			transport.local = tt.local
			sess, err := Open(Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			errCh := make(chan error, 1)
			go func() {
				errCh <- sess.SendKeepAlive(context.Background())
			}()
			waitForWriteCount(t, transport, 1)
			if err := sess.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			select {
			case err := <-errCh:
				if !errors.Is(err, errSessionClosed) {
					t.Fatalf("SendKeepAlive() error = %v, want session closed", err)
				}
			case <-time.After(time.Second):
				t.Fatal("SendKeepAlive() remains blocked after Close")
			}
		})
	}
}

func TestTransportDetachUnblocksKeepAlive(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "promoted primary detaches old keepalive transport"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldTransport := newStubTransport(5062, 5060)
			newTransport := newStubTransport(5064, 5060)
			sess, err := Open(Config{}, oldTransport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			if _, err := sess.AddTransport(newTransport); err != nil {
				t.Fatalf("AddTransport() error = %v", err)
			}
			errCh := make(chan error, 1)
			go func() { errCh <- sess.SendKeepAlive(context.Background()) }()
			waitForWriteCount(t, oldTransport, 1)
			oldAttachment, err := sess.PromotePrimary(newTransport)
			if err != nil {
				t.Fatalf("PromotePrimary() error = %v", err)
			}
			if err := oldAttachment.Close(); err != nil {
				t.Fatalf("old transport Close() error = %v", err)
			}
			select {
			case err := <-errCh:
				if err == nil {
					t.Fatal("SendKeepAlive() error = nil, want detached transport error")
				}
			case <-time.After(time.Second):
				t.Fatal("SendKeepAlive() remains blocked after transport detach")
			}
		})
	}
}

func TestSTUNMessageUnmarshalBinaryRejectsMalformedPackets(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
	}{
		{"short", make([]byte, stunHeaderBytes-1)},
		{"wrong cookie", make([]byte, stunHeaderBytes)},
		{"invalid length", append(stunHeader(stunBindingRequest, [12]byte{}, 4), 0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var message stunMessage
			if err := message.UnmarshalBinary(tt.packet); err == nil {
				t.Fatal("UnmarshalBinary() error = nil, want malformed packet error")
			}
		})
	}
}
