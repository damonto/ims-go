package registration

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/damonto/uicc-go/usim"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
)

const testNonce = "AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI="

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type stubTransport struct {
	local  net.Addr
	remote net.Addr

	mu         sync.Mutex
	writes     [][]byte
	readCh     chan []byte
	onWrite    func([]byte)
	closeCount int
}

type stubCard struct{}

type failAfterFirstAKACard struct {
	stubCard
	mu    sync.Mutex
	calls int
}

type sequenceAKACard struct {
	stubCard
	mu      sync.Mutex
	results []usim.AKAResult
}

type identityStubCard struct {
	stubCard
	homeDomain      string
	privateIdentity string
	publicIdentity  string
}

type twoDigitMNCStubCard struct{}

func (t *stubTransport) LocalAddr() net.Addr { return t.local }

func (t *stubTransport) RemoteAddr() net.Addr { return t.remote }

func (t *stubTransport) WritePacket(ctx context.Context, data []byte) error {
	t.mu.Lock()
	t.writes = append(t.writes, append([]byte(nil), data...))
	onWrite := t.onWrite
	t.mu.Unlock()
	if onWrite != nil {
		onWrite(data)
	}
	return nil
}

func (t *stubTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case pkt := <-t.readCh:
		return pkt, t.remote, nil
	}
}

func (t *stubTransport) Close() error {
	t.mu.Lock()
	t.closeCount++
	t.mu.Unlock()
	return nil
}

func (t *stubTransport) queue(msg sip.Message) {
	t.readCh <- marshalSIPMessageForTest(msg)
}

func marshalSIPMessageForTest(msg sip.Message) []byte {
	data, err := msg.MarshalText()
	if err != nil {
		panic(err)
	}
	return data
}

func (stubCard) IMSI() string { return "001010123456789" }

func (stubCard) MCC() string { return "001" }

func (stubCard) MNC() string { return "001" }

func (stubCard) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	return usim.AKAResult{
		RES: []byte("password"),
		CK:  []byte("client-test-ck"),
		IK:  []byte("client-test-ik"),
	}, nil
}

func (c *failAfterFirstAKACard) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	c.mu.Lock()
	c.calls++
	calls := c.calls
	c.mu.Unlock()
	if calls > 1 {
		return usim.AKAResult{}, errors.New("authentication rejected")
	}
	return c.stubCard.AKA(ctx, rand, autn)
}

func (c *sequenceAKACard) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.results) == 0 {
		return c.stubCard.AKA(ctx, rand, autn)
	}
	result := c.results[0]
	c.results = c.results[1:]
	return result, nil
}

func (twoDigitMNCStubCard) IMSI() string { return "204020123456789" }

func (twoDigitMNCStubCard) MCC() string { return "204" }

func (twoDigitMNCStubCard) MNC() string { return "02" }

func (twoDigitMNCStubCard) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	return stubCard{}.AKA(ctx, rand, autn)
}

func (c identityStubCard) HomeDomain() string { return c.homeDomain }

func (c identityStubCard) PrivateIdentity() string { return c.privateIdentity }

func (c identityStubCard) PublicIdentity() string { return c.publicIdentity }

func newTestService(t *testing.T, cfg Config, transport *stubTransport, card Card) *Service {
	t.Helper()
	cfg.Logger = testLogger()
	if cfg.DialSecureTCP == nil {
		cfg.DialSecureTCP = func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return transport, nil
		}
	}
	if cfg.DialSecureUDP == nil {
		cfg.DialSecureUDP = func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
			return transport, nil
		}
	}
	sess, err := session.Open(session.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	svc, err := New(cfg, sess, card)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return svc
}

func registerService(t *testing.T, svc *Service, transport *stubTransport) {
	t.Helper()
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			transport.queue(newUnauthorizedRegisterResponse(req, testNonce, 0))
		case 2:
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Authentication-Info", Value: `nextnonce="` + testNonce + `"`}))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}
	if err := svc.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
}

func newUDPTransport(localPort, remotePort int) *stubTransport {
	return &stubTransport{
		local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort},
		remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remotePort},
		readCh: make(chan []byte, 16),
	}
}

func newTCPTransport(localPort, remotePort int) *stubTransport {
	return &stubTransport{
		local:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort},
		remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remotePort},
		readCh: make(chan []byte, 16),
	}
}

func mustParseMessage(t *testing.T, data []byte) sip.Message {
	t.Helper()
	msg, err := sip.ParseMessage(data)
	if err != nil {
		t.Fatalf("ParseMessage() error = %v", err)
	}
	return msg
}

func newUnauthorizedRegisterResponse(req sip.Message, nonce string, portC int) sip.Message {
	securityServer := `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=1111;spi-s=2222`
	if portC != 0 {
		securityServer = `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=` + strconv.Itoa(portC) + `;port-s=4060;prot=esp;spi-c=1111;spi-s=2222`
	}
	return newResponse(req, 401, "Unauthorized",
		sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="` + nonce + `",algorithm=AKAv1-MD5,qop="auth"`},
		sip.Header{Name: "Security-Server", Value: securityServer},
	)
}

func newResponse(req sip.Message, code int, reason string, extra ...sip.Header) sip.Message {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req, code)
	resp.Headers = append(resp.Headers, extra...)
	return resp
}

func countWrites(t *stubTransport) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.writes)
}

func waitForWriteCount(t *testing.T, transport *stubTransport, want int) {
	t.Helper()
	deadline := time.After(time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if got := countWrites(transport); got >= want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("write count = %d, want at least %d", countWrites(transport), want)
		case <-tick.C:
		}
	}
}

func closeCount(t *stubTransport) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closeCount
}

func waitForCloseCount(t *testing.T, transport *stubTransport, want int) {
	t.Helper()
	deadline := time.After(time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if got := closeCount(transport); got == want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("closeCount = %d, want %d", closeCount(transport), want)
		case <-tick.C:
		}
	}
}

func lastWrite(t *testing.T, transport *stubTransport) sip.Message {
	t.Helper()
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.writes) == 0 {
		t.Fatal("transport has no writes")
	}
	msg, err := sip.ParseMessage(transport.writes[len(transport.writes)-1])
	if err != nil {
		t.Fatalf("ParseMessage(last write) error = %v", err)
	}
	return msg
}

func expectRegistrationEvent(t *testing.T, svc *Service, want error) {
	t.Helper()
	select {
	case err := <-svc.registrationEvents:
		if !errors.Is(err, want) {
			t.Fatalf("registration event = %v, want %v", err, want)
		}
	default:
		t.Fatalf("registration event missing, want %v", want)
	}
}
