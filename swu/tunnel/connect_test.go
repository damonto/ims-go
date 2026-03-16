package tunnel

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/damonto/ims-client/swu/ike"
)

func TestNewConnectCryptoStateUses32ByteNonce(t *testing.T) {
	crypto, _, _, nonceI, err := newConnectCryptoState(transformDH1024MODP)
	if err != nil {
		t.Fatalf("newConnectCryptoState() error = %v", err)
	}
	if len(nonceI) != 32 {
		t.Fatalf("len(nonceI) = %d, want 32", len(nonceI))
	}
	if len(crypto.nonceI) != 32 {
		t.Fatalf("len(crypto.nonceI) = %d, want 32", len(crypto.nonceI))
	}
}

func TestExchangeIKESAInitCookieHandling(t *testing.T) {
	tests := []struct {
		name        string
		readResults []readResult
		check       func(t *testing.T, conn *fakePacketConn, err error)
	}{
		{
			name: "cookie response retries with cookie payload first",
			readResults: []readResult{
				{
					data: mustIKEPacket(t, ike.IKEHeader{
						InitiatorSPI: 0x0102030405060708,
						Version:      ike.Version20,
						ExchangeType: ike.ExchangeTypeIKESAInit,
						Flags:        ike.FlagResponse,
						MessageID:    0,
					}, []ike.Payload{
						&ike.NotifyPayload{
							NotifyType: notifyTypeCookie,
							Data:       []byte{0x01, 0x02, 0x03, 0x04},
						},
					}),
					addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500},
				},
				{
					data: mustIKEPacket(t, ike.IKEHeader{
						InitiatorSPI: 0x0102030405060708,
						ResponderSPI: 0x1112131415161718,
						Version:      ike.Version20,
						ExchangeType: ike.ExchangeTypeIKESAInit,
						Flags:        ike.FlagResponse,
						MessageID:    0,
					}, nil),
					addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500},
				},
			},
			check: func(t *testing.T, conn *fakePacketConn, err error) {
				t.Helper()
				if err == nil || !strings.Contains(err.Error(), "required payload is missing") {
					t.Fatalf("exchangeIKESAInit() error = %v, want missing payload error after retry", err)
				}
				if len(conn.writes) != 2 {
					t.Fatalf("writes = %d, want 2", len(conn.writes))
				}
				first := mustUnmarshalIKEPacket(t, conn.writes[0])
				if _, ok := first.Payloads[0].(*ike.NotifyPayload); ok {
					t.Fatal("first request unexpectedly included COOKIE notify")
				}
				second := mustUnmarshalIKEPacket(t, conn.writes[1])
				notify, ok := second.Payloads[0].(*ike.NotifyPayload)
				if !ok {
					t.Fatalf("second request payload[0] = %T, want *ike.NotifyPayload", second.Payloads[0])
				}
				if notify.NotifyType != notifyTypeCookie {
					t.Fatalf("second request cookie notify type = %d, want %d", notify.NotifyType, notifyTypeCookie)
				}
				if got := string(notify.Data); got != string([]byte{0x01, 0x02, 0x03, 0x04}) {
					t.Fatalf("second request cookie = %x, want 01020304", notify.Data)
				}
			},
		},
		{
			name: "invalid cookie length fails fast",
			readResults: []readResult{
				{
					data: mustIKEPacket(t, ike.IKEHeader{
						InitiatorSPI: 0x0102030405060708,
						Version:      ike.Version20,
						ExchangeType: ike.ExchangeTypeIKESAInit,
						Flags:        ike.FlagResponse,
						MessageID:    0,
					}, []ike.Payload{
						&ike.NotifyPayload{
							NotifyType: notifyTypeCookie,
							Data:       make([]byte, 65),
						},
					}),
					addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500},
				},
			},
			check: func(t *testing.T, conn *fakePacketConn, err error) {
				t.Helper()
				if err == nil || !strings.Contains(err.Error(), "invalid COOKIE length 65") {
					t.Fatalf("exchangeIKESAInit() error = %v, want invalid COOKIE length", err)
				}
				if len(conn.writes) != 1 {
					t.Fatalf("writes = %d, want 1", len(conn.writes))
				}
			},
		},
		{
			name: "generic ike_sa_init error notify is surfaced",
			readResults: []readResult{
				{
					data: mustIKEPacket(t, ike.IKEHeader{
						InitiatorSPI: 0x0102030405060708,
						Version:      ike.Version20,
						ExchangeType: ike.ExchangeTypeIKESAInit,
						Flags:        ike.FlagResponse,
						MessageID:    0,
					}, []ike.Payload{
						&ike.NotifyPayload{NotifyType: 14},
					}),
					addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500},
				},
			},
			check: func(t *testing.T, conn *fakePacketConn, err error) {
				t.Helper()
				if err == nil || !strings.Contains(err.Error(), "NO_PROPOSAL_CHOSEN (14)") {
					t.Fatalf("exchangeIKESAInit() error = %v, want NO_PROPOSAL_CHOSEN", err)
				}
				if len(conn.writes) != 1 {
					t.Fatalf("writes = %d, want 1", len(conn.writes))
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{
				local:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
				readResults: tt.readResults,
			}
			session := mustDialSession(t, conn)
			state, finish, err := session.prepareConnect("356789012345678", sessionTestCard{})
			if err != nil {
				t.Fatalf("prepareConnect() error = %v", err)
			}
			defer finish()
			err = session.exchangeIKESAInit(context.Background(), state)
			tt.check(t, conn, err)
		})
	}
}

func mustIKEPacket(t *testing.T, header ike.IKEHeader, payloads []ike.Payload) []byte {
	t.Helper()
	wire, err := (ike.IKEPacket{Header: header, Payloads: payloads}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	return wire
}

func mustUnmarshalIKEPacket(t *testing.T, wire []byte) ike.IKEPacket {
	t.Helper()
	var packet ike.IKEPacket
	if err := packet.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	return packet
}
