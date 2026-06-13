package registration

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/damonto/vowifi-go/ims/sip"
)

func TestRegisterSuccessStartsRFC6223KeepAlive(t *testing.T) {
	tests := []struct {
		name       string
		transport  *stubTransport
		assertData func(*testing.T, []byte)
	}{
		{
			name:      "tcp crlf",
			transport: newTCPTransport(5062, 5060),
			assertData: func(t *testing.T, data []byte) {
				t.Helper()
				if string(data) != "\r\n\r\n" {
					t.Fatalf("keepalive packet = %q, want CRLF keepalive", string(data))
				}
			},
		},
		{
			name:      "udp stun binding indication",
			transport: newUDPTransport(5062, 5060),
			assertData: func(t *testing.T, data []byte) {
				t.Helper()
				if len(data) != 20 {
					t.Fatalf("STUN packet length = %d, want 20", len(data))
				}
				if got := binary.BigEndian.Uint16(data[0:2]); got != 0x0011 {
					t.Fatalf("STUN message type = %#x, want Binding Indication", got)
				}
				if got := binary.BigEndian.Uint16(data[2:4]); got != 0 {
					t.Fatalf("STUN message length = %d, want 0", got)
				}
				if got := binary.BigEndian.Uint32(data[4:8]); got != 0x2112a442 {
					t.Fatalf("STUN magic cookie = %#x, want 0x2112a442", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useRegistrationKeepAliveInterval(t, 10*time.Millisecond)
			svc := newTestService(t, Config{}, tt.transport, stubCard{})
			t.Cleanup(func() {
				_ = svc.Close()
			})

			svc.applyRegisterSuccess(registerResponseWithViaKeep(svc, "30"))
			waitForWriteCount(t, tt.transport, 1)
			tt.assertData(t, transportWriteAt(t, tt.transport, 0))
		})
	}
}

func TestRegisterSuccessStopsRFC6223KeepAliveWhenNotRenegotiated(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "refresh response omits keep"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			t.Cleanup(func() {
				_ = svc.Close()
			})

			svc.applyRegisterSuccess(registerResponseWithViaKeep(svc, "30"))
			keepalive := currentRegistrationKeepAlive(t, svc)
			if keepalive == nil {
				t.Fatal("registrationKeepAlive = nil, want active keepalive")
			}

			svc.applyRegisterSuccess(registerResponseWithoutViaKeep(svc))
			if got := currentRegistrationKeepAlive(t, svc); got != nil {
				t.Fatal("registrationKeepAlive is still active after response without keep")
			}
			select {
			case <-keepalive.done():
			default:
				t.Fatal("previous keepalive was not stopped")
			}
		})
	}
}

func TestMaintainReturnsRFC6223KeepAliveFailure(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "tcp write failure"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useRegistrationKeepAliveInterval(t, 10*time.Millisecond)
			transport := newTCPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			t.Cleanup(func() {
				_ = svc.Close()
			})

			want := errors.New("tcp connection reset")
			transport.mu.Lock()
			transport.writeErr = want
			transport.mu.Unlock()

			errCh := make(chan error, 1)
			go func() {
				errCh <- svc.Maintain(context.Background())
			}()

			svc.applyRegisterSuccess(registerResponseWithViaKeep(svc, "30"))

			select {
			case err := <-errCh:
				if !errors.Is(err, want) {
					t.Fatalf("Maintain() error = %v, want wrapped %v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("waiting for Maintain() keepalive failure")
			}
		})
	}
}

func TestDeregisterStopsRFC6223KeepAlive(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "successful deregistration"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			registerService(t, svc, transport)

			svc.applyRegisterSuccess(registerResponseWithViaKeep(svc, "30"))
			keepalive := currentRegistrationKeepAlive(t, svc)
			if keepalive == nil {
				t.Fatal("registrationKeepAlive = nil, want active keepalive")
			}

			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				switch countWrites(transport) {
				case 3:
					transport.queue(newResponse(req, 200, "OK"))
				default:
					t.Fatalf("unexpected write count %d", countWrites(transport))
				}
			}

			if err := svc.Deregister(context.Background()); err != nil {
				t.Fatalf("Deregister() error = %v", err)
			}
			if got := currentRegistrationKeepAlive(t, svc); got != nil {
				t.Fatal("registrationKeepAlive is still active after deregistration")
			}
			select {
			case <-keepalive.done():
			default:
				t.Fatal("previous keepalive was not stopped")
			}
		})
	}
}

func TestCloseStopsRFC6223KeepAlive(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "service close"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})

			svc.applyRegisterSuccess(registerResponseWithViaKeep(svc, "30"))
			keepalive := currentRegistrationKeepAlive(t, svc)
			if keepalive == nil {
				t.Fatal("registrationKeepAlive = nil, want active keepalive")
			}

			if err := svc.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			if got := currentRegistrationKeepAlive(t, svc); got != nil {
				t.Fatal("registrationKeepAlive is still active after close")
			}
			select {
			case <-keepalive.done():
			default:
				t.Fatal("previous keepalive was not stopped")
			}
		})
	}
}

func TestRegisterKeepAliveIntervalFromResponse(t *testing.T) {
	useRegistrationKeepAliveInterval(t, 24*time.Second)

	tests := []struct {
		name string
		via  string
		want time.Duration
		ok   bool
	}{
		{
			name: "positive keep",
			via:  "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-1;keep=30",
			want: 24 * time.Second,
			ok:   true,
		},
		{
			name: "bare keep",
			via:  "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-1;keep",
		},
		{
			name: "zero keep",
			via:  "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-1;keep=0",
		},
		{
			name: "missing keep",
			via:  "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := sip.NewResponse(200, "OK")
			resp.Headers.Set("Via", tt.via)
			got, ok := registerKeepAliveIntervalFromResponse(resp)
			if ok != tt.ok {
				t.Fatalf("registerKeepAliveIntervalFromResponse() ok = %t, want %t", ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("registerKeepAliveIntervalFromResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRandomizedRegistrationKeepAliveIntervalUsesRFC6223Window(t *testing.T) {
	tests := []struct {
		name        string
		recommended time.Duration
		min         time.Duration
		max         time.Duration
	}{
		{
			name:        "thirty seconds",
			recommended: 30 * time.Second,
			min:         24 * time.Second,
			max:         30 * time.Second,
		},
		{
			name:        "one second",
			recommended: time.Second,
			min:         800 * time.Millisecond,
			max:         time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for range 20 {
				got := randomizedRegistrationKeepAliveInterval(tt.recommended)
				if got < tt.min || got > tt.max {
					t.Fatalf("randomizedRegistrationKeepAliveInterval(%v) = %v, want [%v, %v]", tt.recommended, got, tt.min, tt.max)
				}
			}
		})
	}
}

func useRegistrationKeepAliveInterval(t *testing.T, interval time.Duration) {
	t.Helper()
	old := registrationKeepAliveInterval
	registrationKeepAliveInterval = func(time.Duration) time.Duration {
		return interval
	}
	t.Cleanup(func() {
		registrationKeepAliveInterval = old
	})
}

func registerResponseWithViaKeep(svc *Service, keep string) sip.Message {
	req := svc.buildRegister(nil, nil)
	resp := newResponse(req, 200, "OK")
	resp.Headers.Set("Via", strings.Replace(req.Header("Via"), ";keep", ";keep="+keep, 1))
	return resp
}

func registerResponseWithoutViaKeep(svc *Service) sip.Message {
	req := svc.buildRegister(nil, nil)
	resp := newResponse(req, 200, "OK")
	resp.Headers.Set("Via", strings.Replace(req.Header("Via"), ";keep", "", 1))
	return resp
}

func currentRegistrationKeepAlive(t *testing.T, svc *Service) *registrationKeepAlive {
	t.Helper()
	svc.mu.Lock()
	defer svc.mu.Unlock()
	return svc.registrationKeepAlive
}

func transportWriteAt(t *testing.T, transport *stubTransport, index int) []byte {
	t.Helper()
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if index < 0 || index >= len(transport.writes) {
		t.Fatalf("write index %d out of range, len=%d", index, len(transport.writes))
	}
	return append([]byte(nil), transport.writes[index]...)
}
