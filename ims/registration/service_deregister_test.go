package registration

import (
	"context"
	"github.com/damonto/vowifi-go/ims/sip"
	"strings"
	"testing"
)

func TestDeregisterRetriesAfterChallenge(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	registerService(t, svc, transport)

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 3:
			if got := req.Header("Expires"); got != "0" {
				t.Fatalf("Expires = %q, want 0", got)
			}
			if got := req.Header("Contact"); got != "*" {
				t.Fatalf("Contact = %q, want *", got)
			}
			transport.queue(newResponse(req, 401, "Unauthorized", sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="` + testNonce + `",algorithm=AKAv1-MD5,qop="auth"`}))
		case 4:
			transport.queue(newResponse(req, 200, "OK"))
		}
	}

	if err := svc.Deregister(context.Background()); err != nil {
		t.Fatalf("Deregister() error = %v", err)
	}
	if svc.State().Registered {
		t.Fatal("Registered = true, want false")
	}
}

func TestDeregisterAfterRunExitFallsBackToSynchronousExchange(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	registerService(t, svc, transport)

	runCtx, runCancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.sess.Run(runCtx)
	}()
	if err := svc.sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}
	runCancel()
	if err := <-errCh; err != context.Canceled {
		t.Fatalf("Run() error = %v, want %v", err, context.Canceled)
	}

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 3:
			transport.queue(newResponse(req, 401, "Unauthorized", sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="` + testNonce + `",algorithm=AKAv1-MD5,qop="auth"`}))
		case 4:
			transport.queue(newResponse(req, 200, "OK"))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	if err := svc.Deregister(context.Background()); err != nil {
		t.Fatalf("Deregister() error = %v", err)
	}
	if svc.State().Registered {
		t.Fatal("Registered = true, want false")
	}
}

func TestDeregisterHandlesChallenge(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	registerService(t, svc, transport)

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 3:
			if got := req.Header("Expires"); got != "0" {
				t.Fatalf("Expires = %q, want 0", got)
			}
			if got := req.Header("Contact"); got != "*" {
				t.Fatalf("Contact = %q, want *", got)
			}
			transport.queue(newResponse(req, 401, "Unauthorized", sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="` + testNonce + `",algorithm=AKAv1-MD5,qop="auth"`}))
		case 4:
			transport.queue(newResponse(req, 200, "OK"))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	if err := svc.Deregister(context.Background()); err != nil {
		t.Fatalf("Deregister() error = %v", err)
	}
	if svc.State().Registered {
		t.Fatal("Registered = true, want false")
	}
	if got := countWrites(transport); got != 4 {
		t.Fatalf("write count = %d, want 4", got)
	}
}

func TestDeregisterReusesDigestCredential(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	card := &failAfterFirstAKACard{}
	svc := newTestService(t, Config{}, transport, card)
	registerService(t, svc, transport)

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 3:
			if got := req.Header("Authorization"); !strings.Contains(got, `nonce="`+testNonce+`"`) {
				t.Fatalf("Authorization = %q, want cached nonce", got)
			}
			transport.queue(newResponse(req, 200, "OK"))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	if err := svc.Deregister(context.Background()); err != nil {
		t.Fatalf("Deregister() error = %v", err)
	}
	if svc.State().Registered {
		t.Fatal("Registered = true, want false")
	}
	if got := countWrites(transport); got != 3 {
		t.Fatalf("write count = %d, want 3", got)
	}
	card.mu.Lock()
	calls := card.calls
	card.mu.Unlock()
	if calls != 1 {
		t.Fatalf("AKA calls = %d, want 1", calls)
	}
}
