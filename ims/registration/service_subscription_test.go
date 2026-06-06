package registration

import (
	"bytes"
	"context"
	"fmt"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBuildSubscribeUsesSpecDefaultExpires(t *testing.T) {
	svc := newTestService(t, Config{RegisterExpires: 30 * time.Second}, newUDPTransport(5062, 5060), stubCard{})

	msg := svc.buildSubscribe()
	if got := msg.Header("Expires"); got != "600000" {
		t.Fatalf("Expires = %q, want 600000", got)
	}
	if got := msg.Header("Accept"); got != "application/reginfo+xml" {
		t.Fatalf("Accept = %q, want application/reginfo+xml", got)
	}
}

func TestBuildSubscribeUsesSubscriptionIdentity(t *testing.T) {
	tests := []struct {
		name            string
		publicIdentity  string
		defaultPublicID string
		wantIdentity    string
	}{
		{
			name:            "prefers default public identity from registration success",
			publicIdentity:  "sip:530011120348761@ims.mnc001.mcc530.3gppnetwork.org",
			defaultPublicID: "sip:+64210647889@ims.mnc001.mcc530.3gppnetwork.org",
			wantIdentity:    "sip:+64210647889@ims.mnc001.mcc530.3gppnetwork.org",
		},
		{
			name:           "falls back to registration identity when default is absent",
			publicIdentity: "sip:alice@example.com",
			wantIdentity:   "sip:alice@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t, Config{}, newTCPTransport(5062, 5060), stubCard{})
			svc.mu.Lock()
			svc.state.PublicIdentity = tt.publicIdentity
			svc.state.DefaultPublicID = tt.defaultPublicID
			svc.mu.Unlock()

			msg := svc.buildSubscribe()
			if msg.StartLine != fmt.Sprintf("SUBSCRIBE %s SIP/2.0", tt.wantIdentity) {
				t.Fatalf("StartLine = %q, want SUBSCRIBE %s SIP/2.0", msg.StartLine, tt.wantIdentity)
			}
			if got := msg.Header("To"); got != fmt.Sprintf("<%s>", tt.wantIdentity) {
				t.Fatalf("To = %q, want <%s>", got, tt.wantIdentity)
			}
			from := msg.Header("From")
			if !strings.HasPrefix(from, fmt.Sprintf("<%s>;tag=", tt.wantIdentity)) {
				t.Fatalf("From = %q, want prefix <%s>;tag=", from, tt.wantIdentity)
			}
		})
	}
}

func TestSubscribeIgnoresUnsupportedRegistrationEventPackage(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "SUBSCRIBE" {
			t.Fatalf("method = %q, want SUBSCRIBE", req.Method())
		}
		transport.queue(newResponse(req, 489, "Bad Event"))
	}

	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	if !svc.isSubscribeUnsupported() {
		t.Fatal("subscribeUnsupported = false, want true")
	}
}

func TestSubscribeStoresExpires(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "SUBSCRIBE" {
			t.Fatalf("method = %q, want SUBSCRIBE", req.Method())
		}
		transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
	}

	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	if got := svc.currentSubscribeExpires(); got != 2*time.Minute {
		t.Fatalf("currentSubscribeExpires() = %v, want 2m", got)
	}
	if svc.isSubscribeUnsupported() {
		t.Fatal("subscribeUnsupported = true, want false")
	}
}

func TestSubscribeServiceUnavailableCarriesRetryAfter(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "SUBSCRIBE" {
			t.Fatalf("method = %q, want SUBSCRIBE", req.Method())
		}
		transport.queue(newResponse(req, sipStatusServiceUnavailable, "Service Unavailable", sip.Header{Name: "Retry-After", Value: "75"}))
	}

	err := svc.Subscribe(context.Background())
	if err == nil {
		t.Fatal("Subscribe() error = nil, want retry-after error")
	}
	if retryAfter, ok := RetryAfterDelay(err); !ok || retryAfter != 75*time.Second {
		t.Fatalf("RetryAfterDelay() = %v, %v; want 75s, true", retryAfter, ok)
	}
	if _, ok := InitialRegistrationRetryAfter(err); ok {
		t.Fatal("InitialRegistrationRetryAfter() ok = true, want false")
	}
}

func TestSubscribeRefreshUsesEstablishedDialog(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	var callID, fromTag, toTag string
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			callID = req.Header("Call-ID")
			fromTag = sip.HeaderTag(req.Header("From"))
			resp := newResponse(req, 200, "OK",
				sip.Header{Name: "Expires", Value: "120"},
				sip.Header{Name: "Contact", Value: "<sip:scscf.example.com;transport=tcp>"},
				sip.Header{Name: "Record-Route", Value: "<sip:pcscf-1.example.com;lr>"},
				sip.Header{Name: "Record-Route", Value: "<sip:pcscf-2.example.com;lr>"},
			)
			toTag = sip.HeaderTag(resp.Header("To"))
			transport.queue(resp)
		case 2:
			if got := req.Header("Call-ID"); got != callID {
				t.Fatalf("refresh Call-ID = %q, want %q", got, callID)
			}
			if got := sip.HeaderTag(req.Header("From")); got != fromTag {
				t.Fatalf("refresh From tag = %q, want %q", got, fromTag)
			}
			if got := sip.HeaderTag(req.Header("To")); got != toTag {
				t.Fatalf("refresh To tag = %q, want %q", got, toTag)
			}
			if got := req.Header("CSeq"); got != "2 SUBSCRIBE" {
				t.Fatalf("refresh CSeq = %q, want 2 SUBSCRIBE", got)
			}
			if got := sip.RequestURI(req); got != "sip:scscf.example.com;transport=tcp" {
				t.Fatalf("refresh request URI = %q, want remote target", got)
			}
			routes := req.HeadersByName("Route")
			wantRoutes := []string{"<sip:pcscf-2.example.com;lr>", "<sip:pcscf-1.example.com;lr>"}
			if !slices.Equal(routes, wantRoutes) {
				t.Fatalf("refresh Route = %v, want %v", routes, wantRoutes)
			}
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(initial) error = %v", err)
	}
	atomic.StoreInt64(&svc.cseq, 99)
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(refresh) error = %v", err)
	}
}

func TestSubscribeRefreshUsesDialogCSeqAndEmptyRouteSet(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.mu.Lock()
	svc.flow.ServiceRoutes = []string{"<sip:service-route.example.com;lr>"}
	svc.mu.Unlock()

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			transport.queue(newResponse(req, 200, "OK",
				sip.Header{Name: "Expires", Value: "120"},
				sip.Header{Name: "Contact", Value: "<sip:scscf.example.com>"},
			))
		case 2:
			if got := req.Header("CSeq"); got != "2 SUBSCRIBE" {
				t.Fatalf("refresh CSeq = %q, want 2 SUBSCRIBE", got)
			}
			if routes := req.HeadersByName("Route"); len(routes) != 0 {
				t.Fatalf("refresh Route = %v, want empty route set", routes)
			}
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(initial) error = %v", err)
	}
	atomic.StoreInt64(&svc.cseq, 99)
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(refresh) error = %v", err)
	}
}

func TestSubscribeRefreshFailureAdvancesDialogCSeq(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			transport.queue(newResponse(req, 200, "OK",
				sip.Header{Name: "Expires", Value: "120"},
				sip.Header{Name: "Contact", Value: "<sip:scscf.example.com>"},
			))
		case 2:
			if got := req.Header("CSeq"); got != "2 SUBSCRIBE" {
				t.Fatalf("failed refresh CSeq = %q, want 2 SUBSCRIBE", got)
			}
			transport.queue(newResponse(req, 500, "Server Internal Error"))
		case 3:
			if got := req.Header("CSeq"); got != "3 SUBSCRIBE" {
				t.Fatalf("retry refresh CSeq = %q, want 3 SUBSCRIBE", got)
			}
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(initial) error = %v", err)
	}
	if err := svc.Subscribe(context.Background()); err == nil {
		t.Fatal("Subscribe(failed refresh) error = nil, want non-nil")
	}
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(retry refresh) error = %v", err)
	}
}

func TestSubscribeRefreshExchangeErrorStartsNewInitialSubscription(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	var firstCallID string
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			firstCallID = req.Header("Call-ID")
			transport.queue(newResponse(req, 200, "OK",
				sip.Header{Name: "Expires", Value: "120"},
				sip.Header{Name: "Contact", Value: "<sip:scscf.example.com>"},
			))
		case 2:
			if got := req.Header("Call-ID"); got != firstCallID {
				t.Fatalf("dialog refresh Call-ID = %q, want %q", got, firstCallID)
			}
			if got := sip.HeaderTag(req.Header("To")); got == "" {
				t.Fatal("dialog refresh To tag is empty")
			}
			// No response: RFC 3261 treats this as dialog-terminating.
		case 3:
			if got := req.Header("Call-ID"); got == firstCallID {
				t.Fatalf("new initial Call-ID reused old dialog: %q", got)
			}
			if got := sip.HeaderTag(req.Header("To")); got != "" {
				t.Fatalf("new initial To tag = %q, want empty", got)
			}
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(initial) error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := svc.Subscribe(ctx); err == nil {
		t.Fatal("Subscribe(timed out refresh) error = nil, want non-nil")
	}
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(new initial) error = %v", err)
	}
}

func TestSubscribeRefresh481StartsNewInitialSubscription(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	var firstCallID string
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			firstCallID = req.Header("Call-ID")
			transport.queue(newResponse(req, 200, "OK",
				sip.Header{Name: "Expires", Value: "120"},
				sip.Header{Name: "Contact", Value: "<sip:scscf.example.com>"},
			))
		case 2:
			if got := req.Header("Call-ID"); got != firstCallID {
				t.Fatalf("dialog refresh Call-ID = %q, want %q", got, firstCallID)
			}
			if got := sip.HeaderTag(req.Header("To")); got == "" {
				t.Fatal("dialog refresh To tag is empty")
			}
			transport.queue(newResponse(req, 481, "Call/Transaction Does Not Exist"))
		case 3:
			if got := req.Header("Call-ID"); got == firstCallID {
				t.Fatalf("new initial Call-ID reused old dialog: %q", got)
			}
			if got := sip.HeaderTag(req.Header("To")); got != "" {
				t.Fatalf("new initial To tag = %q, want empty", got)
			}
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(initial) error = %v", err)
	}
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(refresh) error = %v", err)
	}
	if got := countWrites(transport); got != 3 {
		t.Fatalf("write count = %d, want 3", got)
	}
}

func TestNotifyStoresSubscriptionStateExpires(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Event", "reg")
	notify.Headers.Add("Subscription-State", "active;expires=90")
	req := session.Request{Message: notify, Transport: transport}

	handled, err := svc.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	if got := svc.currentSubscribeExpires(); got != 90*time.Second {
		t.Fatalf("currentSubscribeExpires() = %v, want 90s", got)
	}
}

func TestSubscriptionStateHeaderText(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		wantState   string
		wantExpires time.Duration
		wantErr     bool
	}{
		{name: "active with expires", value: "active;expires=90", wantState: "active", wantExpires: 90 * time.Second},
		{name: "terminated with reason", value: "terminated;reason=timeout", wantState: "terminated"},
		{name: "empty", value: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got subscriptionStateHeader
			err := got.UnmarshalText([]byte(tt.value))
			if tt.wantErr {
				if err == nil {
					t.Fatal("UnmarshalText() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalText() error = %v", err)
			}
			if got.state != tt.wantState || got.expires != tt.wantExpires {
				t.Fatalf("UnmarshalText() = %+v, want state %q expires %v", got, tt.wantState, tt.wantExpires)
			}
		})
	}
}

func TestNotifyOutsideSubscriptionDialogGets481(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() == "SUBSCRIBE" {
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
		}
	}
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}

	transport.onWrite = nil
	notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Via", "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bKnotify")
	notify.Headers.Add("From", "<sip:server@example.com>;tag=remote")
	notify.Headers.Add("To", sip.WithTag("", svc.State().PublicIdentity, svc.currentSubscription().localTag))
	notify.Headers.Add("Call-ID", "wrong-call-id")
	notify.Headers.Add("CSeq", "1 NOTIFY")
	notify.Headers.Add("Event", "reg")

	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: notify, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	resp := lastWrite(t, transport)
	if got := resp.StatusCode(); got != 481 {
		t.Fatalf("status = %d, want 481", got)
	}
}

func TestNotifyMissingDialogTagGets481(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() == "SUBSCRIBE" {
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
		}
	}
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	subscription := svc.currentSubscription()

	transport.onWrite = nil
	notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Via", "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bKnotify")
	notify.Headers.Add("From", "<sip:server@example.com>")
	notify.Headers.Add("To", subscription.localHeader)
	notify.Headers.Add("Call-ID", subscription.callID)
	notify.Headers.Add("CSeq", "1 NOTIFY")
	notify.Headers.Add("Event", "reg")

	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: notify, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	resp := lastWrite(t, transport)
	if got := resp.StatusCode(); got != 481 {
		t.Fatalf("status = %d, want 481", got)
	}
}

func TestNotifyStaleRemoteCSeqGets500(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() == "SUBSCRIBE" {
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
		}
	}
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	subscription := svc.currentSubscription()

	buildNotify := func(cseq string) sip.Message {
		notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
		notify.Headers.Add("Via", "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bKnotify"+cseq)
		notify.Headers.Add("From", subscription.remoteHeader)
		notify.Headers.Add("To", subscription.localHeader)
		notify.Headers.Add("Call-ID", subscription.callID)
		notify.Headers.Add("CSeq", cseq+" NOTIFY")
		notify.Headers.Add("Event", "reg")
		notify.Headers.Add("Subscription-State", "active;expires=120")
		return notify
	}

	transport.onWrite = nil
	if _, err := svc.HandleRequest(context.Background(), session.Request{Message: buildNotify("2"), Transport: transport}); err != nil {
		t.Fatalf("HandleRequest() first error = %v", err)
	}
	if _, err := svc.HandleRequest(context.Background(), session.Request{Message: buildNotify("1"), Transport: transport}); err != nil {
		t.Fatalf("HandleRequest() second error = %v", err)
	}
	resp := lastWrite(t, transport)
	if got := resp.StatusCode(); got != 500 {
		t.Fatalf("status = %d, want 500", got)
	}
	if !svc.currentSubscription().active {
		t.Fatal("subscription active = false, want stale NOTIFY ignored")
	}
}

func TestNotifySubscriptionStateTerminatedRequestsNewSubscription(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() == "SUBSCRIBE" {
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
		}
	}
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	subscription := svc.currentSubscription()

	transport.onWrite = nil
	notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Via", "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bKnotify")
	notify.Headers.Add("From", subscription.remoteHeader)
	notify.Headers.Add("To", subscription.localHeader)
	notify.Headers.Add("Call-ID", subscription.callID)
	notify.Headers.Add("CSeq", "1 NOTIFY")
	notify.Headers.Add("Event", "reg")
	notify.Headers.Add("Subscription-State", "terminated;reason=timeout")

	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: notify, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	if svc.currentSubscription().active {
		t.Fatal("subscription active = true, want false")
	}
	select {
	case <-svc.subscribeRefreshRequests:
	default:
		t.Fatal("subscription refresh request missing")
	}
	resp := lastWrite(t, transport)
	if got := resp.StatusCode(); got != 200 {
		t.Fatalf("status = %d, want 200", got)
	}
}

func TestNotifyRegInfoRefreshesRegistrationExpires(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.setRegistered(true)

	notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Event", "reg")
	notify.Headers.Add("Content-Type", "application/reginfo+xml")
	notify.Body = []byte(fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="%s" id="reg-1" state="active">
    <contact id="contact-1" state="active" event="refreshed" expires="120">
      <uri>%s</uri>
    </contact>
  </registration>
</reginfo>`, svc.State().PublicIdentity, svc.currentRegisterContactURI()))
	req := session.Request{Message: notify, Transport: transport}

	handled, err := svc.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	state := svc.State()
	if !state.Registered {
		t.Fatal("Registered = false, want true")
	}
	if state.RegisterExpires != 2*time.Minute {
		t.Fatalf("RegisterExpires = %v, want 2m", state.RegisterExpires)
	}
	if got := countWrites(transport); got != 1 {
		t.Fatalf("write count = %d, want NOTIFY 200 response", got)
	}
}

func TestNotifyRegInfoAcceptsContentTypeParameters(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.setRegistered(true)

	notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Event", "reg")
	notify.Headers.Add("Content-Type", `Application/RegInfo+XML; charset="utf-8"`)
	notify.Body = []byte(fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="%s" id="reg-1" state="active">
    <contact id="contact-1" state="active" event="refreshed">
      <uri>%s</uri>
    </contact>
  </registration>
</reginfo>`, svc.State().PublicIdentity, svc.currentRegisterContactURI()))

	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: notify, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	if !svc.regInfoVersionSet {
		t.Fatal("regInfoVersionSet = false, want true")
	}
}

func TestNotifyRegInfoTerminatedContactRequiresInitialRegistration(t *testing.T) {
	tests := []struct {
		name  string
		event string
	}{
		{name: "deactivated", event: "deactivated"},
		{name: "expired", event: "expired"},
		{name: "unregistered", event: "unregistered"},
		{name: "rejected", event: "rejected"},
		{name: "probation", event: "probation"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			svc.setRegistered(true)

			notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
			notify.Headers.Add("Event", "reg")
			notify.Headers.Add("Content-Type", "application/reginfo+xml")
			notify.Body = []byte(fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="2" state="full">
  <registration aor="%s" id="reg-1" state="terminated">
    <contact id="contact-1" state="terminated" event="%s">
      <uri>%s</uri>
    </contact>
  </registration>
</reginfo>`, svc.State().PublicIdentity, tt.event, svc.currentRegisterContactURI()))
			req := session.Request{Message: notify, Transport: transport}

			handled, err := svc.HandleRequest(context.Background(), req)
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			expectRegistrationEvent(t, svc, errNetworkDeregistered)
			if svc.State().Registered {
				t.Fatal("Registered = true, want false")
			}
			if got := countWrites(transport); got != 1 {
				t.Fatalf("write count = %d, want NOTIFY 200 response", got)
			}
		})
	}
}

func TestNotifyRegInfoFullStateWithoutOwnContactRequiresInitialRegistration(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.setRegistered(true)

	notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Event", "reg")
	notify.Headers.Add("Content-Type", "application/reginfo+xml")
	notify.Body = []byte(fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="3" state="full">
  <registration aor="%s" id="reg-1" state="active">
    <contact id="contact-2" state="active" event="registered" expires="300">
      <uri>sip:192.0.2.10:5060</uri>
    </contact>
  </registration>
</reginfo>`, svc.State().PublicIdentity))
	req := session.Request{Message: notify, Transport: transport}

	handled, err := svc.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	expectRegistrationEvent(t, svc, errNetworkDeregistered)
	if svc.State().Registered {
		t.Fatal("Registered = true, want false")
	}
}

func TestNotifyRegInfoFullStateWithoutOwnRegistrationRequiresInitialRegistration(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.setRegistered(true)

	notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Event", "reg")
	notify.Headers.Add("Content-Type", "application/reginfo+xml")
	notify.Body = []byte(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="4" state="full">
  <registration aor="sip:other@example.com" id="reg-2" state="active">
    <contact id="contact-2" state="active" event="registered">
      <uri>sip:192.0.2.10:5060</uri>
    </contact>
  </registration>
</reginfo>`)
	req := session.Request{Message: notify, Transport: transport}

	handled, err := svc.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	expectRegistrationEvent(t, svc, errNetworkDeregistered)
	if svc.State().Registered {
		t.Fatal("Registered = true, want false")
	}
}

func TestNotifyRegInfoEmptyFullStateRequiresInitialRegistration(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "empty reginfo",
			body: `<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="5" state="full">
</reginfo>`,
		},
		{
			name: "foreign namespace registration ignored",
			body: `<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" xmlns:x="urn:example:extension" version="5" state="full">
  <x:registration aor="sip:other@example.com" id="reg-1" state="active">
    <x:contact id="contact-1" state="active" event="registered"><x:uri>sip:other@192.0.2.10</x:uri></x:contact>
  </x:registration>
</reginfo>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			svc.setRegistered(true)

			notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
			notify.Headers.Add("Event", "reg")
			notify.Headers.Add("Content-Type", "application/reginfo+xml")
			notify.Body = []byte(tt.body)

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: notify, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			expectRegistrationEvent(t, svc, errNetworkDeregistered)
			if svc.State().Registered {
				t.Fatal("Registered = true, want false")
			}
		})
	}
}

func TestNotifyRegInfoIgnoresStaleVersion(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.setRegistered(true)

	active := sip.NewRequest("NOTIFY", "sip:user@example.com")
	active.Headers.Add("Event", "reg")
	active.Headers.Add("Content-Type", "application/reginfo+xml")
	active.Body = []byte(fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="2" state="full">
  <registration aor="%s" id="reg-1" state="active">
    <contact id="contact-1" state="active" event="refreshed">
      <uri>%s</uri>
    </contact>
  </registration>
</reginfo>`, svc.State().PublicIdentity, svc.currentRegisterContactURI()))
	if _, err := svc.HandleRequest(context.Background(), session.Request{Message: active, Transport: transport}); err != nil {
		t.Fatalf("HandleRequest(active) error = %v", err)
	}

	stale := sip.NewRequest("NOTIFY", "sip:user@example.com")
	stale.Headers.Add("Event", "reg")
	stale.Headers.Add("Content-Type", "application/reginfo+xml")
	stale.Body = []byte(fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="%s" id="reg-1" state="terminated">
    <contact id="contact-1" state="terminated" event="expired">
      <uri>%s</uri>
    </contact>
  </registration>
</reginfo>`, svc.State().PublicIdentity, svc.currentRegisterContactURI()))

	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: stale, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest(stale) error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest(stale) handled = false, want true")
	}
	if !svc.State().Registered {
		t.Fatal("Registered = false, want stale NOTIFY ignored")
	}
}

func TestNotifyRegInfoRejectsInvalidEnvelope(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing namespace",
			body: `<reginfo version="1" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="active"/>
</reginfo>`,
		},
		{
			name: "wrong namespace",
			body: `<reginfo xmlns="urn:example:wrong" version="1" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="active"/>
</reginfo>`,
		},
		{
			name: "missing version",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="active"/>
</reginfo>`,
		},
		{
			name: "negative version",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="-1" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="active"/>
</reginfo>`,
		},
		{
			name: "overflow version",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="4294967296" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="active"/>
</reginfo>`,
		},
		{
			name: "missing state",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1">
  <registration aor="sip:other@example.com" id="reg-1" state="active"/>
</reginfo>`,
		},
		{
			name: "invalid state",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="delta">
  <registration aor="sip:other@example.com" id="reg-1" state="active"/>
</reginfo>`,
		},
		{
			name: "missing registration id",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="sip:other@example.com" state="active"/>
</reginfo>`,
		},
		{
			name: "missing registration aor",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration id="reg-1" state="active"/>
</reginfo>`,
		},
		{
			name: "invalid registration state",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="bad"/>
</reginfo>`,
		},
		{
			name: "missing contact id",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="active">
    <contact state="active" event="registered"><uri>sip:other@192.0.2.10</uri></contact>
  </registration>
</reginfo>`,
		},
		{
			name: "invalid contact state",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="active">
    <contact id="contact-1" state="bad" event="registered"><uri>sip:other@192.0.2.10</uri></contact>
  </registration>
</reginfo>`,
		},
		{
			name: "invalid contact event",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="active">
    <contact id="contact-1" state="active" event="bad"><uri>sip:other@192.0.2.10</uri></contact>
  </registration>
</reginfo>`,
		},
		{
			name: "missing contact uri",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="active">
    <contact id="contact-1" state="active" event="registered"/>
  </registration>
</reginfo>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			svc.setRegistered(true)

			notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
			notify.Headers.Add("Event", "reg")
			notify.Headers.Add("Content-Type", "application/reginfo+xml")
			notify.Body = []byte(tt.body)

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: notify, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			if !svc.State().Registered {
				t.Fatal("Registered = false, want invalid reginfo ignored")
			}
			if svc.regInfoVersionSet {
				t.Fatal("regInfoVersionSet = true, want false")
			}
		})
	}
}

func TestRegInfoTextAndIO(t *testing.T) {
	tests := []struct {
		name string
		info regInfo
	}{
		{
			name: "full state document",
			info: regInfo{
				Version: "7",
				State:   regInfoStateFull,
				Registration: []regInfoRegistration{{
					ID:    "reg-1",
					AOR:   "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
					State: regInfoRegistrationStateActive,
					Contact: []regInfoContact{{
						ID:          "contact-1",
						State:       regInfoContactStateActive,
						Event:       regInfoContactEventRegistered,
						ExpiresAttr: "600",
						URI:         "sip:001010123456789@192.0.2.10:5060",
					}},
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, err := tt.info.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			if !bytes.Contains(text, []byte(`xmlns="urn:ietf:params:xml:ns:reginfo"`)) {
				t.Fatalf("MarshalText() = %s, want reginfo namespace", text)
			}

			var parsed regInfo
			n, err := parsed.ReadFrom(bytes.NewReader(text))
			if err != nil {
				t.Fatalf("ReadFrom() error = %v", err)
			}
			if n != int64(len(text)) {
				t.Fatalf("ReadFrom() bytes = %d, want %d", n, len(text))
			}
			if parsed.Version != tt.info.Version || parsed.State != tt.info.State || len(parsed.Registration) != 1 {
				t.Fatalf("ReadFrom() parsed = %+v, want %+v", parsed, tt.info)
			}

			var out bytes.Buffer
			n, err = parsed.WriteTo(&out)
			if err != nil {
				t.Fatalf("WriteTo() error = %v", err)
			}
			if n != int64(out.Len()) || !bytes.Equal(out.Bytes(), text) {
				t.Fatalf("WriteTo() bytes = %d body=%s, want %d %s", n, out.Bytes(), len(text), text)
			}
		})
	}
}

func TestNotifyRegInfoVersionGapRequestsSubscriptionRefresh(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.setRegistered(true)

	for _, version := range []string{"1", "3"} {
		notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
		notify.Headers.Add("Event", "reg")
		notify.Headers.Add("Content-Type", "application/reginfo+xml")
		notify.Body = []byte(fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="%s" state="partial">
  <registration aor="%s" id="reg-1" state="active">
    <contact id="contact-1" state="active" event="refreshed">
      <uri>%s</uri>
    </contact>
  </registration>
</reginfo>`, version, svc.State().PublicIdentity, svc.currentRegisterContactURI()))
		if handled, err := svc.HandleRequest(context.Background(), session.Request{Message: notify, Transport: transport}); err != nil {
			t.Fatalf("HandleRequest(version %s) error = %v", version, err)
		} else if !handled {
			t.Fatalf("HandleRequest(version %s) handled = false, want true", version)
		}
	}

	select {
	case <-svc.subscribeRefreshRequests:
	default:
		t.Fatal("subscription refresh request missing after reginfo version gap")
	}
}
