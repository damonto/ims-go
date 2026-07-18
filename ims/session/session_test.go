package session

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/damonto/ims-go/ims/sip"
)

type stubTransport struct {
	local  net.Addr
	remote net.Addr

	mu         sync.Mutex
	writes     [][]byte
	writeAddrs []net.Addr
	onWrite    func([]byte)
	readCh     chan []byte
	closed     chan struct{}
	closeCount int
}

type basicTransport struct{ stub *stubTransport }

type keepAliveDisabledTransport struct{ *stubTransport }

type secureStubTransport struct {
	*stubTransport
	associationID string
	outbound      bool
}

type readErrorTransport struct {
	*stubTransport
	errCh chan error
}

type usableReadError struct {
	err error
}

func (e *usableReadError) Error() string {
	return e.err.Error()
}

func (e *usableReadError) Unwrap() error {
	return e.err
}

func (e *usableReadError) TransportUsable() bool {
	return true
}

type writeErrorTransport struct {
	*stubTransport
	err error
}

type failAfterWritesTransport struct {
	*stubTransport
	failAfter int
	err       error
}

type blockingWriteTransport struct {
	local      net.Addr
	remote     net.Addr
	entered    chan struct{}
	release    chan struct{}
	writeCount atomic.Int32
	active     atomic.Int32
	maxActive  atomic.Int32
}

type requestHandler struct {
	mu       sync.Mutex
	requests []string
	errs     []error
	handle   func(context.Context, Request) (bool, error)
}

type responseCaptureHandler struct {
	responses chan sip.Message
}

func (h *responseCaptureHandler) HandleRequest(context.Context, Request) (bool, error) {
	return false, nil
}

func (h *responseCaptureHandler) HandleResponse(_ context.Context, msg sip.Message) (bool, error) {
	h.responses <- msg
	return true, nil
}

func newStubTransport(localPort, remotePort int) *stubTransport {
	return &stubTransport{
		local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort},
		remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remotePort},
		readCh: make(chan []byte, 16),
		closed: make(chan struct{}),
	}
}

func newBlockingWriteTransport() *blockingWriteTransport {
	return &blockingWriteTransport{
		local:   &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5062},
		remote:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060},
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
}

func newReadErrorTransport(localPort, remotePort int) *readErrorTransport {
	return &readErrorTransport{
		stubTransport: newStubTransport(localPort, remotePort),
		errCh:         make(chan error, 1),
	}
}

func newWriteErrorTransport(err error) *writeErrorTransport {
	transport := newStubTransport(5062, 5060)
	transport.local = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5062}
	transport.remote = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060}
	return &writeErrorTransport{stubTransport: transport, err: err}
}

func newUnreliableWriteErrorTransport(err error) *writeErrorTransport {
	return &writeErrorTransport{stubTransport: newStubTransport(5062, 5060), err: err}
}

func (t *stubTransport) LocalAddr() net.Addr  { return t.local }
func (t *stubTransport) RemoteAddr() net.Addr { return t.remote }

func (t *secureStubTransport) SecureTransport() bool         { return true }
func (t *secureStubTransport) SecurityAssociationID() string { return t.associationID }
func (t *secureStubTransport) OutboundCapable() bool         { return t.outbound }

func (t *stubTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-t.closed:
		return nil, nil, errors.New("transport is closed")
	case pkt := <-t.readCh:
		return pkt, t.remote, nil
	}
}

func (t *stubTransport) WritePacket(ctx context.Context, data []byte) error {
	return t.WritePacketTo(ctx, data, nil)
}

func (t *stubTransport) WritePacketTo(ctx context.Context, data []byte, addr net.Addr) error {
	t.mu.Lock()
	t.writes = append(t.writes, append([]byte(nil), data...))
	t.writeAddrs = append(t.writeAddrs, cloneAddr(addr))
	onWrite := t.onWrite
	t.mu.Unlock()
	if onWrite != nil {
		onWrite(data)
	}
	return nil
}

func (t *stubTransport) writeCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.writes)
}

func (t *stubTransport) snapshotWrites() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	writes := make([][]byte, len(t.writes))
	for i, data := range t.writes {
		writes[i] = append([]byte(nil), data...)
	}
	return writes
}

func (t *stubTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	t.closeCount++
	return nil
}

func (t *stubTransport) queueRead(msg sip.Message) {
	t.readCh <- marshalSIPMessageForTest(msg)
}

func marshalSIPMessageForTest(msg sip.Message) []byte {
	data, err := msg.MarshalText()
	if err != nil {
		panic(err)
	}
	return data
}

func (t *blockingWriteTransport) LocalAddr() net.Addr  { return t.local }
func (t *blockingWriteTransport) RemoteAddr() net.Addr { return t.remote }

func (t *blockingWriteTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	<-ctx.Done()
	return nil, nil, ctx.Err()
}

func (t *blockingWriteTransport) WritePacket(ctx context.Context, data []byte) error {
	return t.waitWrite(ctx)
}

func (t *blockingWriteTransport) waitWrite(ctx context.Context) error {
	active := t.active.Add(1)
	defer t.active.Add(-1)
	for {
		maxActive := t.maxActive.Load()
		if active <= maxActive || t.maxActive.CompareAndSwap(maxActive, active) {
			break
		}
	}
	select {
	case t.entered <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.release:
		t.writeCount.Add(1)
		return nil
	}
}

func (t *blockingWriteTransport) Close() error { return nil }

func (t *basicTransport) LocalAddr() net.Addr  { return t.stub.LocalAddr() }
func (t *basicTransport) RemoteAddr() net.Addr { return t.stub.RemoteAddr() }
func (t *basicTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	return t.stub.ReadPacket(ctx)
}
func (t *basicTransport) WritePacket(ctx context.Context, data []byte) error {
	return t.stub.WritePacket(ctx, data)
}
func (t *basicTransport) Close() error { return t.stub.Close() }

func (t *keepAliveDisabledTransport) SupportsSIPKeepAlive() bool { return false }

func (t *readErrorTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-t.closed:
		return nil, nil, errors.New("transport is closed")
	case err := <-t.errCh:
		return nil, nil, err
	case pkt := <-t.readCh:
		return pkt, t.remote, nil
	}
}

func (t *readErrorTransport) fail(err error) {
	t.errCh <- err
}

func (t *writeErrorTransport) WritePacket(ctx context.Context, data []byte) error {
	return t.err
}

func (t *failAfterWritesTransport) WritePacket(ctx context.Context, data []byte) error {
	if t.writeCount() >= t.failAfter {
		return t.err
	}
	return t.stubTransport.WritePacket(ctx, data)
}

func (h *requestHandler) HandleRequest(ctx context.Context, req Request) (bool, error) {
	h.mu.Lock()
	h.requests = append(h.requests, req.Message.Method())
	h.mu.Unlock()
	if h.handle != nil {
		return h.handle(ctx, req)
	}
	return false, nil
}

func (h *requestHandler) HandleError(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.errs = append(h.errs, err)
}

func (h *requestHandler) requestCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.requests)
}

func (h *requestHandler) requestList() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.requests, ",")
}

func TestSendKeepAliveWritesTransportSpecificPacket(t *testing.T) {
	tests := []struct {
		name       string
		local      net.Addr
		remote     net.Addr
		assertData func(*testing.T, []byte)
	}{
		{
			name:   "tcp crlf",
			local:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5062},
			remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060},
			assertData: func(t *testing.T, data []byte) {
				t.Helper()
				if string(data) != "\r\n\r\n" {
					t.Fatalf("keepalive packet = %q, want CRLF keepalive", string(data))
				}
			},
		},
		{
			name:   "udp stun binding request",
			local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5062},
			remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060},
			assertData: func(t *testing.T, data []byte) {
				t.Helper()
				if len(data) != stunHeaderBytes {
					t.Fatalf("STUN packet length = %d, want %d", len(data), stunHeaderBytes)
				}
				if got := binary.BigEndian.Uint16(data[0:2]); got != stunBindingRequest {
					t.Fatalf("STUN message type = %#x, want Binding Request", got)
				}
				if got := binary.BigEndian.Uint16(data[2:4]); got != 0 {
					t.Fatalf("STUN message length = %d, want 0", got)
				}
				if got := binary.BigEndian.Uint32(data[4:8]); got != stunMagicCookie {
					t.Fatalf("STUN magic cookie = %#x, want %#x", got, stunMagicCookie)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			transport.local = tt.local
			transport.remote = tt.remote
			sess, err := Open(Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			if _, ok := tt.local.(*net.UDPAddr); ok {
				transport.onWrite = func(data []byte) {
					var message stunMessage
					if message.UnmarshalBinary(data) != nil || message.messageType != stunBindingRequest {
						return
					}
					response, responseErr := stunBindingResponse(message.transactionID, transport.local)
					if responseErr == nil {
						transport.readCh <- response
					}
				}
			} else {
				transport.onWrite = func(data []byte) {
					if string(data) == string(sipCRLFKeepAlive) {
						transport.readCh <- []byte("\r\n")
					}
				}
			}
			runCtx, runCancel := context.WithCancel(context.Background())
			errCh := make(chan error, 1)
			go func() { errCh <- sess.Run(runCtx) }()
			if err := sess.WaitStarted(context.Background()); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}

			if err := sess.SendKeepAlive(context.Background()); err != nil {
				t.Fatalf("SendKeepAlive() error = %v", err)
			}
			writes := transport.snapshotWrites()
			if len(writes) != 1 {
				t.Fatalf("write count = %d, want 1", len(writes))
			}
			tt.assertData(t, writes[0])
			runCancel()
			if err := <-errCh; !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestSessionSupportsKeepAlive(t *testing.T) {
	tests := []struct {
		name      string
		transport Transport
		want      bool
	}{
		{"ordinary transport", newStubTransport(5062, 5060), true},
		{"transport disables SIP keepalive", &keepAliveDisabledTransport{newStubTransport(5062, 5060)}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, err := Open(Config{}, tt.transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			if got := sess.SupportsKeepAlive(); got != tt.want {
				t.Fatalf("SupportsKeepAlive() = %t, want %t", got, tt.want)
			}
			if !tt.want {
				if err := sess.SendKeepAlive(context.Background()); err == nil {
					t.Fatal("SendKeepAlive() error = nil, want disabled transport error")
				}
				if transport := extractStubTransport(tt.transport); transport != nil && transport.writeCount() != 0 {
					t.Fatal("SendKeepAlive() wrote to disabled transport")
				}
			}
		})
	}
}

func TestRunTransportReadLoopStagesKeepAlivePackets(t *testing.T) {
	tests := []struct {
		name    string
		packets func(*testing.T) [][]byte
	}{
		{
			name: "crlf and stun",
			packets: func(t *testing.T) [][]byte {
				t.Helper()
				stunPacket, _, err := newSTUNBindingRequest()
				if err != nil {
					t.Fatalf("newSTUNBindingRequest() error = %v", err)
				}
				return [][]byte{[]byte("\r\n\r\n"), stunPacket}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			out := make(chan inboundMessage, 1)
			go runTransportReadLoop(ctx, transport, out, false)

			for _, packet := range tt.packets(t) {
				transport.readCh <- packet
			}
			transport.queueRead(newRequest("MESSAGE", "call-1", "1 MESSAGE"))

			for range len(tt.packets(t)) + 1 {
				select {
				case inbound := <-out:
					if inbound.err != nil {
						t.Fatalf("inbound error = %v", inbound.err)
					}
				case <-time.After(time.Second):
					t.Fatal("waiting for staged packet")
				}
			}
		})
	}
}

func TestExchangeBeforeRunHandlesRequestsAndSkipsProvisionalResponses(t *testing.T) {
	transport := newStubTransport(5062, 5060)
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	handler := &requestHandler{
		handle: func(context.Context, Request) (bool, error) {
			return true, nil
		},
	}
	if _, err := sess.Attach(handler); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}

	req := newRequest("MESSAGE", "call-1", "1 MESSAGE")
	transport.queueRead(newRequest("MESSAGE", "incoming-1", "1 MESSAGE"))
	transport.queueRead(newResponse(req, 100, "Trying"))
	transport.queueRead(newResponse(req, 200, "OK"))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resp, err := sess.Exchange(ctx, req)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Fatalf("StatusCode() = %d, want 200", resp.StatusCode())
	}
	if got := transport.writeCount(); got != 1 {
		t.Fatalf("len(writes) = %d, want 1", got)
	}
	if got := handler.requestCount(); got != 1 {
		t.Fatalf("len(handler.requests) = %d, want 1", got)
	}
}

func TestExchangeBeforeRunIgnoresMismatchedResponses(t *testing.T) {
	tests := []struct {
		name string
		resp sip.Message
	}{
		{
			name: "transaction key mismatch",
			resp: func() sip.Message {
				req := newRequest("MESSAGE", "call-other", "2 MESSAGE")
				req.Headers.Set("Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-other")
				return newResponse(req, 200, "OK")
			}(),
		},
		{
			name: "top via sent-by mismatch",
			resp: func() sip.Message {
				req := newRequest("MESSAGE", "call-1", "1 MESSAGE")
				resp := newResponse(req, 200, "OK")
				resp.Headers.Set("Via", "SIP/2.0/UDP 127.0.0.2:5060;branch=z9hG4bK-1")
				return resp
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			sess, err := Open(Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			req := newRequest("MESSAGE", "call-1", "1 MESSAGE")
			transport.queueRead(tt.resp)
			transport.queueRead(newResponse(req, 200, "OK"))

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			resp, err := sess.Exchange(ctx, req)
			if err != nil {
				t.Fatalf("Exchange() error = %v", err)
			}
			if resp.Header("Call-ID") != "call-1" || resp.StatusCode() != 200 {
				t.Fatalf("response = %s %q, want call-1 200", resp.StartLine, resp.Header("Call-ID"))
			}
		})
	}
}

func TestExchangeBeforeRunCanReceiveFromResponseTransport(t *testing.T) {
	outbound := newStubTransport(5062, 5060)
	inbound := newStubTransport(5063, 45000)
	sess, err := Open(Config{}, outbound)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := sess.AddTransport(inbound); err != nil {
		t.Fatalf("AddTransport(inbound) error = %v", err)
	}

	req := newRequest("REGISTER", "call-1", "1 REGISTER")
	outbound.onWrite = func(_ []byte) {
		inbound.queueRead(newResponse(req, 200, "OK"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := sess.ExchangeWithTransport(ctx, outbound, req, ExchangeOptions{
		AcceptResponseTransport: func(transport Transport) bool {
			return transport == inbound
		},
		ResponseTransports: []Transport{inbound},
	})
	if err != nil {
		t.Fatalf("ExchangeWithTransport() error = %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Fatalf("StatusCode() = %d, want 200", resp.StatusCode())
	}
	if got := outbound.writeCount(); got != 1 {
		t.Fatalf("outbound write count = %d, want 1", got)
	}
}

func TestSameSIPSentBy(t *testing.T) {
	tests := []struct {
		name        string
		left, right string
		want        bool
	}{
		{name: "same hostname", left: "P-CSCF.EXAMPLE:5060", right: "p-cscf.example:5060", want: true},
		{name: "equivalent IPv6", left: "[240e:546:8757:4724::1]:53768", right: "[240E:0546:8757:4724:0:0:0:1]:53768", want: true},
		{name: "different port", left: "[240e:546:8757:4724::1]:53768", right: "[240e:546:8757:4724::1]:5060", want: false},
		{name: "different address", left: "[240e:546:8757:4724::1]:53768", right: "[240e:546:8757:4724::2]:53768", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sameSIPSentBy(tt.left, tt.right); got != tt.want {
				t.Errorf("sameSIPSentBy(%q, %q) = %v, want %v", tt.left, tt.right, got, tt.want)
			}
		})
	}
}

func TestExchangeBeforeRunUsesClientTransactionRetransmission(t *testing.T) {
	tests := []struct {
		name   string
		method string
		cseq   string
	}{
		{name: "non invite", method: "MESSAGE", cseq: "1 MESSAGE"},
		{name: "invite", method: "INVITE", cseq: "1 INVITE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			sess, err := Open(Config{TransactionTimers: TransactionTimers{
				T1: 10 * time.Millisecond,
				T2: 20 * time.Millisecond,
				TB: 200 * time.Millisecond,
				TF: 200 * time.Millisecond,
			}}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}

			req := newRequest(tt.method, "call-1", tt.cseq)
			var writes atomic.Int32
			transport.onWrite = func(_ []byte) {
				if writes.Add(1) == 2 {
					transport.queueRead(newResponse(req, 200, "OK"))
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			resp, err := sess.Exchange(ctx, req)
			if err != nil {
				t.Fatalf("Exchange() error = %v", err)
			}
			if resp.StatusCode() != 200 {
				t.Fatalf("StatusCode() = %d, want 200", resp.StatusCode())
			}
			if got := transport.writeCount(); got < 2 {
				t.Fatalf("write count = %d, want retransmission", got)
			}
		})
	}
}

func TestExchangeAfterRunUsesPendingCorrelation(t *testing.T) {
	transport := newStubTransport(5062, 5060)
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	req := newRequest("MESSAGE", "call-1", "1 MESSAGE")
	transport.onWrite = func(_ []byte) {
		transport.queueRead(newResponse(req, 100, "Trying"))
		transport.queueRead(newResponse(req, 200, "OK"))
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	provisional := make(chan sip.Message, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := sess.ExchangeWithOptions(ctx, req, ExchangeOptions{
		OnProvisional: func(msg sip.Message) {
			provisional <- msg
		},
	})
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Fatalf("StatusCode() = %d, want 200", resp.StatusCode())
	}
	select {
	case msg := <-provisional:
		if msg.StatusCode() != 100 {
			t.Fatalf("provisional status = %d, want 100", msg.StatusCode())
		}
	default:
		t.Fatal("provisional response was not delivered")
	}
	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestWaitStartedReturnsWhenRunBegins(t *testing.T) {
	transport := newStubTransport(5062, 5060)
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sess.WaitStarted(ctx); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}
	if !sess.isRunning() {
		t.Fatal("isRunning() = false, want true")
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestExchangeAfterRunExitFallsBackToSynchronousTransport(t *testing.T) {
	transport := newStubTransport(5062, 5060)
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}
	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}

	req := newRequest("MESSAGE", "call-2", "1 MESSAGE")
	transport.onWrite = func(_ []byte) {
		transport.queueRead(newResponse(req, 200, "OK"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := sess.Exchange(ctx, req)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Fatalf("StatusCode() = %d, want 200", resp.StatusCode())
	}
}

func TestRunFansInMultipleTransports(t *testing.T) {
	primary := newStubTransport(5062, 5060)
	aux := newStubTransport(15062, 15060)
	sess, err := Open(Config{}, primary)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := sess.AddTransport(aux); err != nil {
		t.Fatalf("AddTransport() error = %v", err)
	}

	handledCh := make(chan string, 1)
	handler := &requestHandler{
		handle: func(ctx context.Context, req Request) (bool, error) {
			handledCh <- req.Transport.LocalAddr().String()
			return true, nil
		},
	}
	if _, err := sess.Attach(handler); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()

	aux.queueRead(newInboundRequest("NOTIFY", "fan-in", "1 NOTIFY"))
	select {
	case got := <-handledCh:
		if got != aux.LocalAddr().String() {
			t.Fatalf("handled transport = %q, want %q", got, aux.LocalAddr().String())
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for handled request")
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestRunRemovesFailedAuxTransportWithoutStoppingSession(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "auxiliary transport read failure"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := newStubTransport(5062, 5060)
			aux := newReadErrorTransport(15062, 15060)
			sess, err := Open(Config{}, primary)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			if _, err := sess.AddTransport(aux); err != nil {
				t.Fatalf("AddTransport(aux) error = %v", err)
			}

			handledCh := make(chan string, 1)
			handler := &requestHandler{
				handle: func(ctx context.Context, req Request) (bool, error) {
					handledCh <- req.Transport.LocalAddr().String()
					return true, nil
				},
			}
			if _, err := sess.Attach(handler); err != nil {
				t.Fatalf("Attach() error = %v", err)
			}

			runCtx, runCancel := context.WithCancel(context.Background())
			defer runCancel()
			errCh := make(chan error, 1)
			go func() {
				errCh <- sess.Run(runCtx)
			}()
			if err := sess.WaitStarted(context.Background()); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}

			auxReq := newRequest("MESSAGE", "aux-pending", "1 MESSAGE")
			auxErrCh := make(chan error, 1)
			go func() {
				_, err := sess.ExchangeWithTransport(context.Background(), aux, auxReq, ExchangeOptions{})
				auxErrCh <- err
			}()
			waitForWriteCount(t, aux.stubTransport, 1)

			cause := errors.New("aux transport lost")
			aux.fail(cause)
			waitForTransportInactive(t, sess, aux)
			if err := <-auxErrCh; !errors.Is(err, cause) {
				t.Fatalf("aux ExchangeWithTransport() error = %v, want %v", err, cause)
			}

			primary.queueRead(newInboundRequest("MESSAGE", "primary-after-aux-failure", "1 MESSAGE"))
			select {
			case got := <-handledCh:
				if got != primary.LocalAddr().String() {
					t.Fatalf("handled transport = %q, want %q", got, primary.LocalAddr().String())
				}
			case err := <-errCh:
				t.Fatalf("Run() returned after aux failure: %v", err)
			case <-time.After(time.Second):
				t.Fatal("waiting for primary request after aux failure")
			}

			runCancel()
			if err := <-errCh; !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestRunRestartsReadLoopForUsableTransport(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "auxiliary TCP connection reset"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := newStubTransport(5062, 5060)
			aux := newReadErrorTransport(15062, 15060)
			aux.local = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 15062}
			aux.remote = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 15060}

			sess, err := Open(Config{}, primary)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			if _, err := sess.AddTransport(aux); err != nil {
				t.Fatalf("AddTransport(aux) error = %v", err)
			}

			handledCh := make(chan string, 1)
			handler := &requestHandler{
				handle: func(ctx context.Context, req Request) (bool, error) {
					handledCh <- req.Transport.LocalAddr().String()
					return true, nil
				},
			}
			if _, err := sess.Attach(handler); err != nil {
				t.Fatalf("Attach() error = %v", err)
			}

			runCtx, runCancel := context.WithCancel(context.Background())
			defer runCancel()
			errCh := make(chan error, 1)
			go func() {
				errCh <- sess.Run(runCtx)
			}()
			if err := sess.WaitStarted(context.Background()); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}

			req := newRequest("MESSAGE", "pending-on-reset", "1 MESSAGE")
			exchangeErrCh := make(chan error, 1)
			go func() {
				_, err := sess.ExchangeWithTransport(context.Background(), aux, req, ExchangeOptions{})
				exchangeErrCh <- err
			}()
			waitForWriteCount(t, aux.stubTransport, 1)

			cause := errors.New("peer reset connection")
			aux.fail(&usableReadError{err: cause})
			if err := <-exchangeErrCh; !errors.Is(err, cause) {
				t.Fatalf("ExchangeWithTransport() error = %v, want %v", err, cause)
			}
			if !sess.isTransportActive(aux) {
				t.Fatal("aux transport is inactive after recoverable connection error")
			}
			aux.mu.Lock()
			closeCount := aux.closeCount
			aux.mu.Unlock()
			if closeCount != 0 {
				t.Fatalf("aux close count = %d, want 0", closeCount)
			}

			aux.queueRead(newInboundRequest("MESSAGE", "after-reset", "2 MESSAGE"))
			select {
			case got := <-handledCh:
				if got != aux.LocalAddr().String() {
					t.Fatalf("handled transport = %q, want %q", got, aux.LocalAddr())
				}
			case err := <-errCh:
				t.Fatalf("Run() returned after recoverable connection error: %v", err)
			case <-time.After(time.Second):
				t.Fatal("waiting for request on recovered transport")
			}

			runCancel()
			if err := <-errCh; !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestRunReturnsPrimaryTransportReadError(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "primary transport read failure"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := newReadErrorTransport(5062, 5060)
			sess, err := Open(Config{}, primary)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			runCtx, runCancel := context.WithCancel(context.Background())
			defer runCancel()
			errCh := make(chan error, 1)
			go func() {
				errCh <- sess.Run(runCtx)
			}()
			if err := sess.WaitStarted(context.Background()); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}

			cause := errors.New("primary transport lost")
			primary.fail(cause)
			err = <-errCh
			if !errors.Is(err, cause) {
				t.Fatalf("Run() error = %v, want %v", err, cause)
			}
			if !TransportFailed(err) {
				t.Fatalf("TransportFailed() = false for %v", err)
			}
		})
	}
}

func TestSessionSerializesWrites(t *testing.T) {
	transport := newBlockingWriteTransport()
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	req := newRequest("MESSAGE", "call-1", "1 MESSAGE")
	inbound := Request{Message: newInboundRequest("NOTIFY", "call-2", "1 NOTIFY"), Transport: transport}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	sendErrCh := make(chan error, 1)
	go func() {
		sendErrCh <- sess.Send(ctx, req)
	}()

	select {
	case <-transport.entered:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("first write did not reach transport")
	}

	respErrCh := make(chan error, 1)
	go func() {
		respErrCh <- sess.WriteStatus(ctx, inbound, 200, "OK")
	}()

	select {
	case <-transport.entered:
		t.Fatal("second write entered transport before first completed")
	case <-time.After(50 * time.Millisecond):
	}

	close(transport.release)
	if err := <-sendErrCh; err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := <-respErrCh; err != nil {
		t.Fatalf("WriteStatus() error = %v", err)
	}
	if got := transport.writeCount.Load(); got != 2 {
		t.Fatalf("write count = %d, want 2", got)
	}
	if got := transport.maxActive.Load(); got != 1 {
		t.Fatalf("max concurrent writes = %d, want 1", got)
	}
}

func TestWriteResponseTargetsUDPSourceAndFallsBack(t *testing.T) {
	tests := []struct {
		name      string
		transport Transport
		wantAddr  bool
	}{
		{name: "targeted writer", transport: newStubTransport(5062, 5060), wantAddr: true},
		{name: "fallback writer", transport: &basicTransport{stub: newStubTransport(5062, 5060)}, wantAddr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, err := Open(Config{}, tt.transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			req := Request{Message: newInboundRequest("MESSAGE", "call-1", "1 MESSAGE"), Transport: tt.transport}
			if err := sess.WriteStatus(context.Background(), req, 200, "OK"); err != nil {
				t.Fatalf("WriteStatus() error = %v", err)
			}

			stub := extractStubTransport(tt.transport)
			if len(stub.writeAddrs) != 1 {
				t.Fatalf("len(writeAddrs) = %d, want 1", len(stub.writeAddrs))
			}
			if got := stub.writeAddrs[0] != nil; got != tt.wantAddr {
				t.Fatalf("writeAddrs[0] set = %v, want %v", got, tt.wantAddr)
			}
		})
	}
}

func TestWriteResponseUsesRequestPeerForBareRPort(t *testing.T) {
	transport := newStubTransport(5062, 5060)
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	req := Request{
		Message:   newInboundRequest("MESSAGE", "call-1", "1 MESSAGE"),
		Transport: transport,
		PeerAddr:  &net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 33109},
	}
	req.Message.Headers.Set("Via", "SIP/2.0/UDP 10.0.0.10:5062;branch=z9hG4bK-1;received=198.51.100.10;rport")

	if err := sess.WriteStatus(context.Background(), req, 200, "OK"); err != nil {
		t.Fatalf("WriteStatus() error = %v", err)
	}

	if len(transport.writeAddrs) != 1 {
		t.Fatalf("len(writeAddrs) = %d, want 1", len(transport.writeAddrs))
	}
	got, ok := transport.writeAddrs[0].(*net.UDPAddr)
	if !ok {
		t.Fatalf("writeAddrs[0] = %T, want *net.UDPAddr", transport.writeAddrs[0])
	}
	want := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 33109}
	if !got.IP.Equal(want.IP) || got.Port != want.Port {
		t.Fatalf("response target = %v, want %v", got, want)
	}
}

func TestWriteResponseUsesTransportMatchingResponseTarget(t *testing.T) {
	primary := newStubTransport(10553, 6000)
	primary.local = &net.TCPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 10553}
	primary.remote = &net.TCPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 6000}
	inbound := newStubTransport(28789, 32813)
	inbound.local = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 28789}
	inbound.remote = &net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 32813}
	response := newStubTransport(10553, 6000)
	response.local = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 10553}
	response.remote = &net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 6000}
	sess, err := Open(Config{}, primary)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := sess.AddTransport(inbound); err != nil {
		t.Fatalf("AddTransport(inbound) error = %v", err)
	}
	if _, err := sess.AddTransport(response); err != nil {
		t.Fatalf("AddTransport(response) error = %v", err)
	}
	req := Request{
		Message:   newInboundRequest("MESSAGE", "call-1", "1 MESSAGE"),
		Transport: inbound,
		PeerAddr:  &net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 32813},
	}
	req.Message.Headers.Set("Via", "SIP/2.0/UDP 198.51.100.10:6000;branch=z9hG4bK-1")

	if err := sess.WriteStatus(context.Background(), req, 200, "OK"); err != nil {
		t.Fatalf("WriteStatus() error = %v", err)
	}

	if got := inbound.writeCount(); got != 0 {
		t.Fatalf("inbound write count = %d, want 0", got)
	}
	if got := response.writeCount(); got != 1 {
		t.Fatalf("response write count = %d, want 1", got)
	}
	got, ok := response.writeAddrs[0].(*net.UDPAddr)
	if !ok {
		t.Fatalf("response write addr = %T, want *net.UDPAddr", response.writeAddrs[0])
	}
	want := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 6000}
	if !got.IP.Equal(want.IP) || got.Port != want.Port {
		t.Fatalf("response target = %v, want %v", got, want)
	}
}

func TestWriteResponseUsesExplicitResponseRoute(t *testing.T) {
	primary := newStubTransport(10553, 6000)
	primary.local = &net.TCPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 10553}
	primary.remote = &net.TCPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 6000}
	inbound := newStubTransport(28789, 32813)
	inbound.local = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 28789}
	inbound.remote = &net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 32813}
	oldResponse := newStubTransport(10552, 6000)
	oldResponse.local = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 10552}
	oldResponse.remote = &net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 6000}
	newResponse := newStubTransport(10553, 6000)
	newResponse.local = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 10553}
	newResponse.remote = &net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 6000}
	sess, err := Open(Config{}, primary)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	transports := []struct {
		name      string
		transport Transport
	}{
		{"inbound", inbound},
		{"oldResponse", oldResponse},
		{"newResponse", newResponse},
	}
	for _, item := range transports {
		if _, err := sess.AddTransport(item.transport); err != nil {
			t.Fatalf("AddTransport(%s) error = %v", item.name, err)
		}
	}
	if _, err := sess.RouteResponses(inbound, newResponse); err != nil {
		t.Fatalf("RouteResponses() error = %v", err)
	}
	req := Request{
		Message:   newInboundRequest("MESSAGE", "call-1", "1 MESSAGE"),
		Transport: inbound,
		PeerAddr:  &net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 32813},
	}
	req.Message.Headers.Set("Via", "SIP/2.0/UDP 198.51.100.10:6000;branch=z9hG4bK-1")

	if err := sess.WriteStatus(context.Background(), req, 200, "OK"); err != nil {
		t.Fatalf("WriteStatus() error = %v", err)
	}

	if got := oldResponse.writeCount(); got != 0 {
		t.Fatalf("old response write count = %d, want 0", got)
	}
	if got := newResponse.writeCount(); got != 1 {
		t.Fatalf("new response write count = %d, want 1", got)
	}
}

func TestResponseDestinationUsesTopViaReceivedAndPort(t *testing.T) {
	tests := []struct {
		name   string
		remote *net.UDPAddr
		via    string
		want   *net.UDPAddr
	}{
		{
			name: "uses received and rport",
			via:  "SIP/2.0/UDP 10.0.0.10:5062;branch=z9hG4bK-1;received=198.51.100.10;rport=5070",
			want: &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 5070},
		},
		{
			name: "falls back to sent-by port when rport missing",
			via:  "SIP/2.0/UDP 10.0.0.10:5062;branch=z9hG4bK-1;received=198.51.100.10",
			want: &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 5062},
		},
		{
			name: "uses source port when rport has no value",
			via:  "SIP/2.0/UDP 10.0.0.10:5062;branch=z9hG4bK-1;received=198.51.100.10;rport",
			want: &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 5060},
		},
		{
			name: "uses sent-by host and port without received",
			via:  "SIP/2.0/UDP 10.0.0.10:5062;branch=z9hG4bK-1",
			want: &net.UDPAddr{IP: net.ParseIP("10.0.0.10"), Port: 5062},
		},
		{
			name: "defaults sent-by port without received",
			via:  "SIP/2.0/UDP 10.0.0.10;branch=z9hG4bK-1",
			want: &net.UDPAddr{IP: net.ParseIP("10.0.0.10"), Port: 5060},
		},
		{
			name:   "uses sent-by port for secure udp peer without rport",
			remote: &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 32821},
			via:    "SIP/2.0/UDP 10.0.0.10:6000;branch=z9hG4bK-1",
			want:   &net.UDPAddr{IP: net.ParseIP("10.0.0.10"), Port: 6000},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 5060}
			if tt.remote != nil {
				remote = tt.remote
			}

			gotAddr := responseDestination(remote, tt.via)
			got, ok := gotAddr.(*net.UDPAddr)
			if !ok {
				t.Fatalf("responseDestination() = %T, want *net.UDPAddr", gotAddr)
			}
			if !got.IP.Equal(tt.want.IP) || got.Port != tt.want.Port {
				t.Fatalf("responseDestination() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAttachmentOrderAndUnhandledBehavior(t *testing.T) {
	tests := []struct {
		name       string
		msg        sip.Message
		wantWrites int
		wantStatus int
		wantAllow  string
	}{
		{name: "ack ignored", msg: newInboundRequest("ACK", "ack-1", "1 ACK"), wantWrites: 0},
		{name: "unmatched bye gets 481", msg: newInboundRequest("BYE", "bye-1", "1 BYE"), wantWrites: 1, wantStatus: 481},
		{name: "options gets capabilities", msg: newInboundRequest("OPTIONS", "options-1", "1 OPTIONS"), wantWrites: 1, wantStatus: 200, wantAllow: sip.DefaultClientAllow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(15062, 15060)
			sess, err := Open(Config{}, newStubTransport(5062, 5060))
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}

			first := &requestHandler{}
			second := &requestHandler{
				handle: func(ctx context.Context, req Request) (bool, error) {
					return req.Message.Method() == "NOTIFY", nil
				},
			}
			if _, err := sess.Attach(first); err != nil {
				t.Fatalf("Attach(first) error = %v", err)
			}
			if _, err := sess.Attach(second); err != nil {
				t.Fatalf("Attach(second) error = %v", err)
			}

			err = sess.handleRequest(context.Background(), Request{Message: tt.msg, Transport: transport})
			if err != nil {
				t.Fatalf("handleRequest() error = %v", err)
			}
			if got := len(first.requests); got != 1 {
				t.Fatalf("len(first.requests) = %d, want 1", got)
			}
			if got := len(second.requests); got != 1 {
				t.Fatalf("len(second.requests) = %d, want 1", got)
			}
			stub := extractStubTransport(transport)
			if got := len(stub.writes); got != tt.wantWrites {
				t.Fatalf("len(writes) = %d, want %d", got, tt.wantWrites)
			}
			if tt.wantWrites == 1 {
				resp, err := sip.ParseMessage(stub.writes[0])
				if err != nil {
					t.Fatalf("ParseMessage(response) error = %v", err)
				}
				if got := resp.StatusCode(); got != tt.wantStatus {
					t.Fatalf("StatusCode() = %d, want %d", got, tt.wantStatus)
				}
				if got := resp.Header("Allow"); got != tt.wantAllow {
					t.Fatalf("Allow = %q, want %q", got, tt.wantAllow)
				}
			}
		})
	}
}

func TestHandleInboundRequestRejectsMalformedMessages(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		mutate     func(*sip.Message)
		wantWrites int
	}{
		{
			name:       "mismatched cseq gets 400",
			method:     "MESSAGE",
			mutate:     func(msg *sip.Message) { msg.Headers.Set("CSeq", "1 INVITE") },
			wantWrites: 1,
		},
		{
			name:       "invalid max forwards gets 400",
			method:     "MESSAGE",
			mutate:     func(msg *sip.Message) { msg.Headers.Set("Max-Forwards", "many") },
			wantWrites: 1,
		},
		{
			name:       "duplicate call id gets 400",
			method:     "MESSAGE",
			mutate:     func(msg *sip.Message) { msg.Headers.Add("Call-ID", "duplicate") },
			wantWrites: 1,
		},
		{
			name:   "malformed ack is silently discarded",
			method: "ACK",
			mutate: func(msg *sip.Message) { msg.Headers.Set("CSeq", "bad ACK") },
		},
		{
			name:   "request without via cannot receive response",
			method: "MESSAGE",
			mutate: func(msg *sip.Message) { msg.Headers.Del("Via") },
		},
		{
			name:   "request with malformed via cannot receive response",
			method: "MESSAGE",
			mutate: func(msg *sip.Message) { msg.Headers.Set("Via", "malformed") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			sess, err := Open(Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			handler := &requestHandler{}
			if _, err := sess.Attach(handler); err != nil {
				t.Fatalf("Attach() error = %v", err)
			}
			msg := newInboundRequest(tt.method, "malformed-call", "1 "+tt.method)
			tt.mutate(&msg)
			req := Request{Message: msg, Transport: transport, PeerAddr: transport.remote}
			if err := sess.handleInboundRequest(context.Background(), req); err != nil {
				t.Fatalf("handleInboundRequest() error = %v", err)
			}
			writes := transport.snapshotWrites()
			if len(writes) != tt.wantWrites {
				t.Fatalf("write count = %d, want %d", len(writes), tt.wantWrites)
			}
			if tt.wantWrites != 0 {
				resp, err := sip.ParseMessage(writes[0])
				if err != nil {
					t.Fatalf("ParseMessage() error = %v", err)
				}
				if resp.StatusCode() != sipStatusBadRequest {
					t.Fatalf("status = %d, want %d", resp.StatusCode(), sipStatusBadRequest)
				}
			}
			handler.mu.Lock()
			requestCount := len(handler.requests)
			handler.mu.Unlock()
			if requestCount != 0 {
				t.Fatalf("handler request count = %d, want 0", requestCount)
			}
		})
	}
}

func TestHandleInboundRequestDetectsMergedRequests(t *testing.T) {
	tests := []struct {
		name           string
		toTag          string
		withoutFromTag bool
		wantWrites     int
		wantRequests   int
	}{
		{name: "different branch outside dialog gets retained 482", wantWrites: 2, wantRequests: 1},
		{name: "missing From tags are equal null tags", withoutFromTag: true, wantWrites: 2, wantRequests: 1},
		{name: "in-dialog request is not merged", toTag: "remote", wantRequests: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			sess, err := Open(Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			defer sess.clearServerTransactions()
			handler := &requestHandler{handle: func(context.Context, Request) (bool, error) { return true, nil }}
			if _, err := sess.Attach(handler); err != nil {
				t.Fatalf("Attach() error = %v", err)
			}

			first := newInboundRequestWithBranch("MESSAGE", "merged-call", "1 MESSAGE", "z9hG4bK-first")
			second := newInboundRequestWithBranch("MESSAGE", "merged-call", "1 MESSAGE", "z9hG4bK-second")
			if tt.withoutFromTag {
				first.Headers.Set("From", "<sip:alice@example.com>")
				second.Headers.Set("From", "<sip:alice@example.com>")
			}
			if tt.toTag != "" {
				second.Headers.Set("To", "<sip:bob@example.com>;tag="+tt.toTag)
			}
			messages := []sip.Message{first, second}
			if tt.toTag == "" {
				messages = append(messages, second)
			}
			for _, msg := range messages {
				req := Request{Message: msg, Transport: transport, PeerAddr: transport.remote}
				if err := sess.handleInboundRequest(context.Background(), req); err != nil {
					t.Fatalf("handleInboundRequest() error = %v", err)
				}
			}

			writes := transport.snapshotWrites()
			if len(writes) != tt.wantWrites {
				t.Fatalf("write count = %d, want %d", len(writes), tt.wantWrites)
			}
			if tt.wantWrites != 0 {
				resp, err := sip.ParseMessage(writes[0])
				if err != nil {
					t.Fatalf("ParseMessage() error = %v", err)
				}
				if resp.StatusCode() != sipStatusLoopDetected {
					t.Fatalf("status = %d, want %d", resp.StatusCode(), sipStatusLoopDetected)
				}
			}
			handler.mu.Lock()
			requestCount := len(handler.requests)
			handler.mu.Unlock()
			if requestCount != tt.wantRequests {
				t.Fatalf("handler request count = %d, want %d", requestCount, tt.wantRequests)
			}
		})
	}
}

func TestServerTransactionMatchesEquivalentSentBy(t *testing.T) {
	tests := []struct {
		name       string
		original   string
		retransmit string
	}{
		{name: "hostname case", original: "CLIENT.EXAMPLE.COM:5060", retransmit: "client.example.com:5060"},
		{name: "IPv6 spelling", original: "[2001:0db8::1]:5060", retransmit: "[2001:db8:0:0::1]:5060"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := newInboundRequestWithBranch("MESSAGE", "sent-by-call", "1 MESSAGE", "z9hG4bK-sent-by")
			original.Headers.Set("Via", "SIP/2.0/UDP "+tt.original+";branch=z9hG4bK-sent-by")
			retransmit := cloneSIPMessage(original)
			retransmit.Headers.Set("Via", "SIP/2.0/UDP "+tt.retransmit+";branch=z9hG4bK-sent-by")

			transport := newStubTransport(5062, 5060)
			tx := newServerTransaction(&Session{}, Request{Message: original, Transport: transport, PeerAddr: transport.remote})
			if got, want := serverTransactionKey(retransmit), tx.key; got != want {
				t.Fatalf("serverTransactionKey() = %q, want %q", got, want)
			}
			cancel := cloneSIPMessage(retransmit)
			cancel.StartLine = "CANCEL " + sip.RequestURI(cancel) + " SIP/2.0"
			if !cancelMatchesServerTransaction(cancel, tx) {
				t.Fatal("cancelMatchesServerTransaction() = false, want true")
			}
			tx.method = "INVITE"
			ack := cloneSIPMessage(retransmit)
			ack.StartLine = "ACK " + sip.RequestURI(ack) + " SIP/2.0"
			if !ackMatchesServerTransaction(ack, tx) {
				t.Fatal("ackMatchesServerTransaction() = false, want true")
			}
		})
	}
}

func TestLegacyServerTransactionMatching(t *testing.T) {
	tests := []struct {
		name            string
		change          func(*sip.Message, *sip.Message)
		wantKeyMatch    bool
		wantCancelMatch bool
	}{
		{
			name: "missing From tag is a null tag",
			change: func(original, candidate *sip.Message) {
				original.Headers.Set("From", "<sip:alice@example.com>")
				candidate.Headers.Set("From", "<sip:alice@example.com>")
			},
			wantKeyMatch: true, wantCancelMatch: true,
		},
		{
			name: "different To tag does not match CANCEL",
			change: func(_ *sip.Message, candidate *sip.Message) {
				candidate.Headers.Set("To", "<sip:bob@example.com>;tag=other")
			},
			wantKeyMatch: false, wantCancelMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := newInboundRequestWithBranch("MESSAGE", "legacy-call", "1 MESSAGE", "legacy-branch")
			candidate := cloneSIPMessage(original)
			tt.change(&original, &candidate)
			transport := newStubTransport(5062, 5060)
			tx := newServerTransaction(&Session{}, Request{Message: original, Transport: transport, PeerAddr: transport.remote})
			if got := serverTransactionKey(candidate) == tx.key; got != tt.wantKeyMatch {
				t.Fatalf("server transaction key match = %v, want %v", got, tt.wantKeyMatch)
			}

			cancel := cloneSIPMessage(candidate)
			cancel.StartLine = "CANCEL " + sip.RequestURI(cancel) + " SIP/2.0"
			if got := cancelMatchesServerTransaction(cancel, tx); got != tt.wantCancelMatch {
				t.Fatalf("cancelMatchesServerTransaction() = %v, want %v", got, tt.wantCancelMatch)
			}
		})
	}
}

func TestHandleInboundRequestRejectsUnsupportedRequire(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		require      string
		wantStatus   int
		wantRequests int
		wantHeader   string
	}{
		{"supported option reaches handler", "MESSAGE", "sec-agree", 0, 1, ""},
		{"unknown option gets 420", "MESSAGE", "sec-agree,unknown-extension", sipStatusBadExtension, 0, "unknown-extension"},
		{"duplicates are reported once", "MESSAGE", "unknown,UNKNOWN", sipStatusBadExtension, 0, "unknown"},
		{"ACK ignores Require", "ACK", "unknown-extension", 0, 1, ""},
		{"CANCEL ignores Require", "CANCEL", "unknown-extension", sipStatusCallTransactionDoesNotExist, 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			sess, err := Open(Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			handler := &requestHandler{handle: func(context.Context, Request) (bool, error) { return true, nil }}
			if _, err := sess.Attach(handler); err != nil {
				t.Fatalf("Attach() error = %v", err)
			}
			msg := newInboundRequest(tt.method, "require-call", "1 "+tt.method)
			msg.Headers.Add("Require", tt.require)
			req := Request{Message: msg, Transport: transport, PeerAddr: transport.remote}
			if err := sess.handleInboundRequest(context.Background(), req); err != nil {
				t.Fatalf("handleInboundRequest() error = %v", err)
			}
			if got := handler.requestCount(); got != tt.wantRequests {
				t.Fatalf("handler request count = %d, want %d", got, tt.wantRequests)
			}
			writes := transport.snapshotWrites()
			if tt.wantStatus == 0 {
				if len(writes) != 0 {
					t.Fatalf("write count = %d, want 0", len(writes))
				}
				return
			}
			if len(writes) != 1 {
				t.Fatalf("write count = %d, want 1", len(writes))
			}
			resp, err := sip.ParseMessage(writes[0])
			if err != nil {
				t.Fatalf("ParseMessage() error = %v", err)
			}
			if resp.StatusCode() != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode(), tt.wantStatus)
			}
			if tt.wantHeader != "" && resp.Header("Unsupported") != tt.wantHeader {
				t.Fatalf("Unsupported = %q, want %q", resp.Header("Unsupported"), tt.wantHeader)
			}
		})
	}
}

func TestRunDiscardsMalformedUDPDatagram(t *testing.T) {
	tests := []struct {
		name       string
		malformed  func() []byte
		wantWrites int
	}{
		{"invalid start line", func() []byte { return []byte("not a SIP message\r\n\r\n") }, 0},
		{"truncated body gets 400", func() []byte {
			msg := newInboundRequest("MESSAGE", "truncated", "1 MESSAGE")
			msg.Body = []byte("hi")
			packet := marshalSIPMessageForTest(msg)
			return []byte(strings.Replace(string(packet), "Content-Length: 2", "Content-Length: 5", 1))
		}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			sess, err := Open(Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			handler := &requestHandler{handle: func(context.Context, Request) (bool, error) { return true, nil }}
			if _, err := sess.Attach(handler); err != nil {
				t.Fatalf("Attach() error = %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			errCh := make(chan error, 1)
			go func() { errCh <- sess.Run(ctx) }()
			if err := sess.WaitStarted(context.Background()); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}

			transport.readCh <- tt.malformed()
			transport.queueRead(newInboundRequest("MESSAGE", "after-malformed", "1 MESSAGE"))
			deadline := time.Now().Add(time.Second)
			for handler.requestCount() == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if got := handler.requestCount(); got != 1 {
				t.Fatalf("handled request count = %d, want 1 after malformed datagram", got)
			}
			if got := transport.writeCount(); got != tt.wantWrites {
				t.Fatalf("response write count = %d, want %d", got, tt.wantWrites)
			}
			cancel()
			if err := <-errCh; !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestValidateInboundResponse(t *testing.T) {
	req := newInboundRequest("MESSAGE", "response-validation", "1 MESSAGE")
	valid := newResponse(req, 200, "OK")
	tests := []struct {
		name   string
		mutate func(*sip.Message)
		wantOK bool
	}{
		{name: "valid", mutate: func(*sip.Message) {}, wantOK: true},
		{name: "missing call id", mutate: func(msg *sip.Message) { msg.Headers.Del("Call-ID") }},
		{name: "missing via", mutate: func(msg *sip.Message) { msg.Headers.Del("Via") }},
		{name: "invalid cseq", mutate: func(msg *sip.Message) { msg.Headers.Set("CSeq", "bad MESSAGE") }},
		{name: "duplicate from", mutate: func(msg *sip.Message) { msg.Headers.Add("From", "<sip:other@example.com>;tag=other") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := valid
			msg.Headers = valid.Headers.Clone()
			tt.mutate(&msg)
			err := validateInboundResponse(msg)
			if tt.wantOK && err != nil {
				t.Fatalf("validateInboundResponse() error = %v", err)
			}
			if !tt.wantOK && err == nil {
				t.Fatal("validateInboundResponse() error = nil, want non-nil")
			}
		})
	}
}

func TestBuildInviteErrorACKPreservesSecurityVerify(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{name: "without security agreement"},
		{name: "with security agreement", want: "ipsec-3gpp;alg=hmac-sha-1-96"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newInboundRequest("INVITE", "error-ack", "1 INVITE")
			if tt.want != "" {
				req.Headers.Add("Security-Verify", tt.want)
			}
			resp := newResponse(req, 486, "Busy Here")
			ack := buildInviteErrorACK(req, resp)
			if got := ack.Header("Security-Verify"); got != tt.want {
				t.Fatalf("Security-Verify = %q, want %q", got, tt.want)
			}
			if ack.Headers.Has("Require") || ack.Headers.Has("Proxy-Require") {
				t.Fatalf("ACK contains extension requirements: %#v", ack.Headers)
			}
		})
	}
}

func TestAddTransportCanJoinRunningSession(t *testing.T) {
	primary := newStubTransport(5062, 5060)
	sess, err := Open(Config{}, primary)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	handledCh := make(chan string, 1)
	handler := &requestHandler{
		handle: func(ctx context.Context, req Request) (bool, error) {
			handledCh <- req.Transport.LocalAddr().String()
			return true, nil
		},
	}
	if _, err := sess.Attach(handler); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	aux := newStubTransport(15062, 15060)
	attachment, err := sess.AddTransport(aux)
	if err != nil {
		t.Fatalf("AddTransport() error = %v", err)
	}
	if err := sess.ReplacePrimary(newStubTransport(25062, 25060)); err == nil {
		t.Fatal("ReplacePrimary() error = nil, want non-nil")
	}

	aux.queueRead(newInboundRequest("NOTIFY", "run-add", "1 NOTIFY"))
	select {
	case got := <-handledCh:
		if got != aux.LocalAddr().String() {
			t.Fatalf("handled transport = %q, want %q", got, aux.LocalAddr().String())
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for handled request")
	}
	if err := attachment.Close(); err != nil {
		t.Fatalf("attachment.Close() error = %v", err)
	}
	primary.queueRead(newInboundRequest("MESSAGE", "primary-still-running", "1 MESSAGE"))
	select {
	case got := <-handledCh:
		if got != primary.LocalAddr().String() {
			t.Fatalf("handled transport = %q, want %q", got, primary.LocalAddr().String())
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for handled request after closing aux")
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
	if _, err := sess.AddTransport(newStubTransport(35062, 35060)); err == nil {
		t.Fatal("AddTransport() after Run() error = nil, want non-nil")
	}
	if err := sess.ReplacePrimary(newStubTransport(45062, 45060)); err == nil {
		t.Fatal("ReplacePrimary() after Run() error = nil, want non-nil")
	}
}

func TestPromotePrimaryUsesNewTransportAndKeepsOldTransportActive(t *testing.T) {
	old := newStubTransport(5062, 5060)
	sess, err := Open(Config{}, old)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	handledCh := make(chan string, 1)
	handler := &requestHandler{
		handle: func(ctx context.Context, req Request) (bool, error) {
			handledCh <- req.Transport.LocalAddr().String()
			return true, nil
		},
	}
	if _, err := sess.Attach(handler); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	pending := newRequest("MESSAGE", "old-pending", "1 MESSAGE")
	respCh := make(chan sip.Message, 1)
	exchangeErrCh := make(chan error, 1)
	go func() {
		resp, err := sess.Exchange(context.Background(), pending)
		if err != nil {
			exchangeErrCh <- err
			return
		}
		respCh <- resp
	}()
	waitForWriteCount(t, old, 1)

	next := newStubTransport(15062, 15060)
	if _, err := sess.AddTransport(next); err != nil {
		t.Fatalf("AddTransport() error = %v", err)
	}
	oldAttachment, err := sess.PromotePrimary(next)
	if err != nil {
		t.Fatalf("PromotePrimary() error = %v", err)
	}
	if oldAttachment == nil {
		t.Fatal("PromotePrimary() old attachment = nil, want non-nil")
	}

	if err := sess.Send(context.Background(), newRequest("MESSAGE", "new-outbound", "1 MESSAGE")); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if got := old.writeCount(); got != 1 {
		t.Fatalf("old write count = %d, want 1", got)
	}
	if got := next.writeCount(); got != 1 {
		t.Fatalf("new write count = %d, want 1", got)
	}

	old.queueRead(newResponse(pending, 200, "OK"))
	select {
	case err := <-exchangeErrCh:
		t.Fatalf("Exchange() error = %v", err)
	case resp := <-respCh:
		if resp.StatusCode() != 200 {
			t.Fatalf("StatusCode() = %d, want 200", resp.StatusCode())
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for old pending transaction")
	}

	old.queueRead(newInboundRequestWithBranch("NOTIFY", "old-inbound", "1 NOTIFY", "z9hG4bK-old-inbound"))
	select {
	case got := <-handledCh:
		if got != old.LocalAddr().String() {
			t.Fatalf("handled transport = %q, want %q", got, old.LocalAddr().String())
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for old inbound request")
	}

	if err := oldAttachment.Close(); err != nil {
		t.Fatalf("oldAttachment.Close() error = %v", err)
	}
	if !sess.isTransportActive(next) {
		t.Fatal("new transport inactive after old attachment close")
	}
	next.queueRead(newInboundRequestWithBranch("NOTIFY", "new-inbound", "1 NOTIFY", "z9hG4bK-new-inbound"))
	select {
	case got := <-handledCh:
		if got != next.LocalAddr().String() {
			t.Fatalf("handled transport = %q, want %q", got, next.LocalAddr().String())
		}
	case err := <-errCh:
		t.Fatalf("Run() ended before new inbound request: %v", err)
	case <-time.After(time.Second):
		t.Fatal("waiting for new inbound request")
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestWaitTransportsIdleWaitsForClientTransactions(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "old transport is idle after pending exchange completes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := newStubTransport(5062, 5060)
			sess, err := Open(Config{}, old)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			runCtx, runCancel := context.WithCancel(context.Background())
			defer runCancel()
			errCh := make(chan error, 1)
			go func() {
				errCh <- sess.Run(runCtx)
			}()
			if err := sess.WaitStarted(context.Background()); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}

			req := newRequest("MESSAGE", "wait-idle", "1 MESSAGE")
			respCh := make(chan error, 1)
			go func() {
				_, err := sess.Exchange(context.Background(), req)
				respCh <- err
			}()
			waitForWriteCount(t, old, 1)

			idleCtx, idleCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			if err := sess.WaitTransportsIdle(idleCtx, old); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("WaitTransportsIdle() before response error = %v, want deadline", err)
			}
			idleCancel()

			old.queueRead(newResponse(req, 200, "OK"))
			if err := <-respCh; err != nil {
				t.Fatalf("Exchange() error = %v", err)
			}
			if err := sess.WaitTransportsIdle(context.Background(), old); err != nil {
				t.Fatalf("WaitTransportsIdle() after response error = %v", err)
			}

			runCancel()
			if err := <-errCh; !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestInboundMessageKeyUsesStableTransactionFields(t *testing.T) {
	req := newRequest("REGISTER", "reauth-register", "2 REGISTER")
	tests := []struct {
		name     string
		message  sip.Message
		wantSame bool
	}{
		{
			name: "response Via received and rport parameters",
			message: func() sip.Message {
				resp := newResponse(req, 200, "OK")
				resp.Headers.Set("Via", resp.Header("Via")+";received=2001:db8::1;rport=4600")
				return resp
			}(),
			wantSame: true,
		},
		{
			name: "different branch",
			message: func() sip.Message {
				resp := newResponse(req, 200, "OK")
				resp.Headers.Set("Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-other")
				return resp
			}(),
		},
		{
			name:    "different CSeq",
			message: newRequest("REGISTER", "reauth-register", "3 REGISTER"),
		},
	}

	want := inboundMessageKey(req)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotSame := inboundMessageKey(tt.message) == want; gotSame != tt.wantSame {
				t.Fatalf("matching transaction = %t, want %t", gotSame, tt.wantSame)
			}
		})
	}
}

func TestCloseClosesTransportsAndFansOutErrorOnce(t *testing.T) {
	primary := newStubTransport(5062, 5060)
	aux := newStubTransport(15062, 15060)
	sess, err := Open(Config{}, primary)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := sess.AddTransport(aux); err != nil {
		t.Fatalf("AddTransport() error = %v", err)
	}

	first := &requestHandler{}
	second := &requestHandler{}
	if _, err := sess.Attach(first); err != nil {
		t.Fatalf("Attach(first) error = %v", err)
	}
	if _, err := sess.Attach(second); err != nil {
		t.Fatalf("Attach(second) error = %v", err)
	}

	if err := sess.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if primary.closeCount != 1 {
		t.Fatalf("primary closeCount = %d, want 1", primary.closeCount)
	}
	if aux.closeCount != 1 {
		t.Fatalf("aux closeCount = %d, want 1", aux.closeCount)
	}
	if len(first.errs) != 1 || len(second.errs) != 1 {
		t.Fatalf("fanout counts = %d, %d; want 1, 1", len(first.errs), len(second.errs))
	}
}

func TestRunRetransmitsFinalResponseForRepeatedInboundRequest(t *testing.T) {
	transport := newStubTransport(5062, 5060)
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	handled := make(chan struct{}, 2)
	handler := &requestHandler{
		handle: func(ctx context.Context, req Request) (bool, error) {
			if req.Message.Method() != "MESSAGE" {
				return false, nil
			}
			handled <- struct{}{}
			return true, sess.WriteStatus(ctx, req, 200, "OK")
		},
	}
	if _, err := sess.Attach(handler); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	req := newInboundRequest("MESSAGE", "call-server-retry", "1 MESSAGE")
	transport.queueRead(req)
	transport.queueRead(req)
	waitForWriteCount(t, transport, 2)

	if got := len(handled); got != 1 {
		t.Fatalf("handler count = %d, want 1", got)
	}
	for _, data := range transport.snapshotWrites() {
		resp, err := sip.ParseMessage(data)
		if err != nil {
			t.Fatalf("ParseMessage() error = %v", err)
		}
		if resp.StatusCode() != 200 {
			t.Fatalf("StatusCode() = %d, want 200", resp.StatusCode())
		}
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestRunMatchesCancelToInboundInviteTransaction(t *testing.T) {
	transport := newStubTransport(5062, 5060)
	sess, err := Open(Config{
		ResponseDecorator: func(resp *sip.Message) {
			resp.Headers.Set("Server", "test-agent")
		},
	}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	handled := make(chan string, 2)
	handler := &requestHandler{
		handle: func(ctx context.Context, req Request) (bool, error) {
			if req.Message.Method() != "INVITE" {
				return false, nil
			}
			handled <- req.Message.Method()
			return true, sess.WriteStatus(ctx, req, 100, "Trying")
		},
	}
	if _, err := sess.Attach(handler); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	invite := newInboundRequest("INVITE", "call-cancel", "1 INVITE")
	cancel := newInboundRequest("CANCEL", "call-cancel", "1 CANCEL")
	transport.queueRead(invite)
	waitForWriteCount(t, transport, 1)
	transport.queueRead(cancel)
	waitForWriteCount(t, transport, 3)

	if got := len(handled); got != 1 {
		t.Fatalf("handler count = %d, want 1", got)
	}
	if got, want := handler.requestList(), "INVITE,CANCEL"; got != want {
		t.Fatalf("handler requests = %q, want %q", got, want)
	}
	writes := transport.snapshotWrites()
	if len(writes) != 3 {
		t.Fatalf("len(writes) = %d, want 3", len(writes))
	}
	got := make([]string, 0, len(writes))
	for _, data := range writes {
		resp, err := sip.ParseMessage(data)
		if err != nil {
			t.Fatalf("ParseMessage() error = %v", err)
		}
		got = append(got, resp.StartLine+" "+resp.Header("CSeq"))
	}
	want := []string{
		"SIP/2.0 100 Trying 1 INVITE",
		"SIP/2.0 200 OK 1 CANCEL",
		"SIP/2.0 487 Request Terminated 1 INVITE",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("responses[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	for i, data := range writes[1:] {
		resp, err := sip.ParseMessage(data)
		if err != nil {
			t.Fatalf("ParseMessage(%d) error = %v", i+1, err)
		}
		if got := resp.Header("Server"); got != "test-agent" {
			t.Fatalf("responses[%d] Server = %q, want test-agent", i+1, got)
		}
	}
	cancelOK, err := sip.ParseMessage(writes[1])
	if err != nil {
		t.Fatalf("ParseMessage(CANCEL 200) error = %v", err)
	}
	inviteFinal, err := sip.ParseMessage(writes[2])
	if err != nil {
		t.Fatalf("ParseMessage(INVITE 487) error = %v", err)
	}
	if got, want := sip.HeaderTag(cancelOK.Header("To")), sip.HeaderTag(inviteFinal.Header("To")); got != want {
		t.Fatalf("CANCEL To-tag = %q, want INVITE response To-tag %q", got, want)
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestInviteServerTransactionSendsAutomaticTryingWhenTUIsSlow(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "invite proceeding for more than 200ms"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			sess, err := Open(Config{
				ResponseDecorator: func(resp *sip.Message) {
					resp.Headers.Set("Server", "test-agent")
				},
			}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}

			handled := make(chan Request, 1)
			release := make(chan struct{})
			handler := &requestHandler{
				handle: func(ctx context.Context, req Request) (bool, error) {
					if req.Message.Method() != "INVITE" {
						return false, nil
					}
					handled <- req
					<-release
					return true, sess.WriteStatus(ctx, req, 486, "Busy Here")
				},
			}
			if _, err := sess.Attach(handler); err != nil {
				t.Fatalf("Attach() error = %v", err)
			}

			runCtx, runCancel := context.WithCancel(context.Background())
			defer runCancel()
			errCh := make(chan error, 1)
			go func() {
				errCh <- sess.Run(runCtx)
			}()
			if err := sess.WaitStarted(context.Background()); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}

			invite := newInboundRequest("INVITE", "call-auto-trying", "1 INVITE")
			invite.Headers.Add("Timestamp", "54")
			transport.queueRead(invite)
			select {
			case <-handled:
			case <-time.After(time.Second):
				t.Fatal("handler did not receive INVITE")
			}
			waitForWriteCount(t, transport, 1)

			writes := transport.snapshotWrites()
			trying, err := sip.ParseMessage(writes[0])
			if err != nil {
				t.Fatalf("ParseMessage(trying) error = %v", err)
			}
			if trying.StatusCode() != 100 {
				t.Fatalf("automatic response status = %d, want 100", trying.StatusCode())
			}
			if got := trying.Header("Timestamp"); got != "54" {
				t.Fatalf("automatic response Timestamp = %q, want 54", got)
			}
			if got := trying.Header("Server"); got != "test-agent" {
				t.Fatalf("automatic trying Server = %q, want test-agent", got)
			}
			if strings.Contains(strings.ToLower(trying.Header("To")), ";tag=") {
				t.Fatalf("automatic trying To = %q, want no tag", trying.Header("To"))
			}

			close(release)
			waitForWriteCount(t, transport, 2)
			writes = transport.snapshotWrites()
			final, err := sip.ParseMessage(writes[1])
			if err != nil {
				t.Fatalf("ParseMessage(final) error = %v", err)
			}
			if final.StatusCode() != 486 {
				t.Fatalf("final response status = %d, want 486", final.StatusCode())
			}

			runCancel()
			if err := <-errCh; !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestInviteServerTransactionDoesNotSendAutomaticTryingWhileResponseIsWriting(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "application response is in flight"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newBlockingWriteTransport()
			sess, err := Open(Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}

			req := Request{
				Message:   newInboundRequest("INVITE", "call-writing-trying", "1 INVITE"),
				Transport: transport,
			}
			tx := newServerTransaction(sess, req)
			sess.registerServerTransaction(tx)

			errCh := make(chan error, 1)
			go func() {
				errCh <- sess.WriteStatus(context.Background(), req, 100, "Trying")
			}()

			select {
			case <-transport.entered:
			case <-time.After(time.Second):
				t.Fatal("application response did not reach transport")
			}

			tx.mu.Lock()
			tryingTimer := tx.tryingTimer
			lastStatus := tx.lastResponse.StatusCode()
			tx.mu.Unlock()
			if tryingTimer != nil {
				t.Fatal("automatic Trying timer is still armed")
			}
			if lastStatus != sipStatusTrying {
				t.Fatalf("recorded response status = %d, want %d", lastStatus, sipStatusTrying)
			}

			tx.sendAutomaticTrying()
			select {
			case <-transport.entered:
				t.Fatal("automatic Trying raced the application response")
			default:
			}

			close(transport.release)
			if err := <-errCh; err != nil {
				t.Fatalf("WriteStatus() error = %v", err)
			}
			if got := transport.writeCount.Load(); got != 1 {
				t.Fatalf("write count = %d, want 1", got)
			}
		})
	}
}

func TestWriteResponseTerminatesServerTransactionOnTransportError(t *testing.T) {
	tests := []struct {
		name   string
		status int
		reason string
	}{
		{name: "provisional response", status: sipStatusTrying, reason: "Trying"},
		{name: "final response", status: 486, reason: "Busy Here"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cause := errors.New("writing tcp response")
			transport := newWriteErrorTransport(cause)
			sess, err := Open(Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}

			req := Request{
				Message:   newInboundRequest("INVITE", "call-response-error", "1 INVITE"),
				Transport: transport,
			}
			tx := newServerTransaction(sess, req)
			sess.registerServerTransaction(tx)

			err = sess.WriteStatus(context.Background(), req, tt.status, tt.reason)
			if !errors.Is(err, cause) {
				t.Fatalf("WriteStatus() error = %v, want %v", err, cause)
			}
			if got := sess.lookupServerTransaction(req.Message); got != nil {
				t.Fatalf("lookupServerTransaction() = %p, want nil", got)
			}

			tx.mu.Lock()
			state := tx.state
			tx.mu.Unlock()
			if state != serverTransactionTerminated {
				t.Fatalf("transaction state = %d, want terminated", state)
			}
		})
	}
}

func TestReliableInviteErrorACKIsConsumedByServerTransaction(t *testing.T) {
	transport := newStubTransport(5062, 5060)
	transport.local = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5062}
	transport.remote = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060}
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	handler := &requestHandler{
		handle: func(ctx context.Context, req Request) (bool, error) {
			if req.Message.Method() != "INVITE" {
				return false, nil
			}
			return true, sess.WriteStatus(ctx, req, 100, "Trying")
		},
	}
	if _, err := sess.Attach(handler); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	invite := newInboundRequest("INVITE", "call-cancel-tcp", "1 INVITE")
	cancel := newInboundRequest("CANCEL", "call-cancel-tcp", "1 CANCEL")
	ack := newInboundRequest("ACK", "call-cancel-tcp", "1 ACK")
	options := newInboundRequest("OPTIONS", "after-ack", "1 OPTIONS")
	transport.queueRead(invite)
	waitForWriteCount(t, transport, 1)
	transport.queueRead(cancel)
	waitForWriteCount(t, transport, 3)
	transport.queueRead(ack)
	transport.queueRead(options)
	waitForWriteCount(t, transport, 4)

	if got, want := handler.requestList(), "INVITE,CANCEL,OPTIONS"; got != want {
		t.Fatalf("handler requests = %q, want %q", got, want)
	}
	if writes := transport.snapshotWrites(); len(writes) != 4 {
		t.Fatalf("len(writes) = %d, want 4", len(writes))
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestInviteServerTransactionRetransmitsFinalResponseOverUDP(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "timer g retransmits 3xx-6xx final response"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useTransactionTimers(t, TransactionTimers{
				T1: 10 * time.Millisecond,
				T2: 20 * time.Millisecond,
				T4: 10 * time.Millisecond,
				TH: 80 * time.Millisecond,
			})

			transport := newStubTransport(5062, 5060)
			sess, err := Open(Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}

			handled := make(chan string, 2)
			handler := &requestHandler{
				handle: func(ctx context.Context, req Request) (bool, error) {
					handled <- req.Message.Method()
					if req.Message.Method() != "INVITE" {
						return false, nil
					}
					return true, sess.WriteStatus(ctx, req, 486, "Busy Here")
				},
			}
			if _, err := sess.Attach(handler); err != nil {
				t.Fatalf("Attach() error = %v", err)
			}

			runCtx, runCancel := context.WithCancel(context.Background())
			defer runCancel()
			errCh := make(chan error, 1)
			go func() {
				errCh <- sess.Run(runCtx)
			}()
			if err := sess.WaitStarted(context.Background()); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}

			transport.queueRead(newInboundRequest("INVITE", "call-server-final-retry", "1 INVITE"))
			waitForWriteCount(t, transport, 2)

			if got := <-handled; got != "INVITE" {
				t.Fatalf("handled request = %q, want INVITE", got)
			}
			if got := len(handled); got != 0 {
				t.Fatalf("extra handled requests = %d, want 0", got)
			}
			for _, data := range transport.snapshotWrites() {
				resp, err := sip.ParseMessage(data)
				if err != nil {
					t.Fatalf("ParseMessage() error = %v", err)
				}
				if resp.StatusCode() != 486 {
					t.Fatalf("StatusCode() = %d, want 486", resp.StatusCode())
				}
			}

			runCancel()
			if err := <-errCh; !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestInviteServerTransactionAbsorbsDuplicateACKDuringTimerI(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "duplicate ack is consumed until timer i fires"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useTransactionTimers(t, TransactionTimers{
				T1: 100 * time.Millisecond,
				T2: 100 * time.Millisecond,
				T4: 50 * time.Millisecond,
				TH: 200 * time.Millisecond,
			})

			transport := newStubTransport(5062, 5060)
			sess, err := Open(Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}

			handled := make(chan string, 4)
			handler := &requestHandler{
				handle: func(ctx context.Context, req Request) (bool, error) {
					handled <- req.Message.Method()
					if req.Message.Method() != "INVITE" {
						return false, nil
					}
					return true, sess.WriteStatus(ctx, req, 486, "Busy Here")
				},
			}
			if _, err := sess.Attach(handler); err != nil {
				t.Fatalf("Attach() error = %v", err)
			}

			runCtx, runCancel := context.WithCancel(context.Background())
			defer runCancel()
			errCh := make(chan error, 1)
			go func() {
				errCh <- sess.Run(runCtx)
			}()
			if err := sess.WaitStarted(context.Background()); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}

			transport.queueRead(newInboundRequest("INVITE", "call-server-ack-drain", "1 INVITE"))
			waitForWriteCount(t, transport, 1)

			for _, method := range []string{"ACK", "ACK", "OPTIONS"} {
				transport.queueRead(newInboundRequest(method, "call-server-ack-drain", "1 "+method))
			}

			got := collectHandledMethods(t, handled, "OPTIONS")
			if want := "INVITE,OPTIONS"; strings.Join(got, ",") != want {
				t.Fatalf("handled requests = %q, want %q", strings.Join(got, ","), want)
			}

			runCancel()
			if err := <-errCh; !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestInviteServerTransactionMatchesLegacyACK(t *testing.T) {
	tests := []struct {
		name   string
		branch string
	}{
		{name: "RFC2543 branch uses response To tag", branch: "legacy-branch"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			sess, err := Open(Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}

			handled := make(chan string, 4)
			handler := &requestHandler{
				handle: func(ctx context.Context, req Request) (bool, error) {
					handled <- req.Message.Method()
					if req.Message.Method() != "INVITE" {
						return false, nil
					}
					return true, sess.WriteStatus(ctx, req, 486, "Busy Here")
				},
			}
			if _, err := sess.Attach(handler); err != nil {
				t.Fatalf("Attach() error = %v", err)
			}

			runCtx, runCancel := context.WithCancel(context.Background())
			defer runCancel()
			errCh := make(chan error, 1)
			go func() {
				errCh <- sess.Run(runCtx)
			}()
			if err := sess.WaitStarted(context.Background()); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}

			invite := newInboundRequestWithBranch("INVITE", "call-legacy-ack", "1 INVITE", tt.branch)
			transport.queueRead(invite)
			waitForWriteCount(t, transport, 1)
			final, err := sip.ParseMessage(transport.snapshotWrites()[0])
			if err != nil {
				t.Fatalf("ParseMessage(final) error = %v", err)
			}

			ack := newInboundRequestWithBranch("ACK", "call-legacy-ack", "1 ACK", tt.branch)
			ack.Headers.Set("To", final.Header("To"))
			transport.queueRead(ack)
			transport.queueRead(newInboundRequest("OPTIONS", "after-legacy-ack", "1 OPTIONS"))

			got := collectHandledMethods(t, handled, "OPTIONS")
			if want := "INVITE,OPTIONS"; strings.Join(got, ",") != want {
				t.Fatalf("handled requests = %q, want %q", strings.Join(got, ","), want)
			}

			runCancel()
			if err := <-errCh; !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestInviteServerTransactionRetains2xxUntilTimerL(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "duplicate INVITE reaches TU while accepted"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			sess, err := Open(Config{TransactionTimers: TransactionTimers{TL: 100 * time.Millisecond}}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}

			handled := make(chan string, 2)
			handler := &requestHandler{
				handle: func(ctx context.Context, req Request) (bool, error) {
					handled <- req.Message.Method()
					if req.Message.Method() != "INVITE" {
						return false, nil
					}
					return true, sess.WriteStatus(ctx, req, 200, "OK")
				},
			}
			if _, err := sess.Attach(handler); err != nil {
				t.Fatalf("Attach() error = %v", err)
			}

			runCtx, runCancel := context.WithCancel(context.Background())
			defer runCancel()
			errCh := make(chan error, 1)
			go func() {
				errCh <- sess.Run(runCtx)
			}()
			if err := sess.WaitStarted(context.Background()); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}

			invite := newInboundRequest("INVITE", "call-server-2xx", "1 INVITE")
			transport.queueRead(invite)
			waitForWriteCount(t, transport, 1)
			transport.queueRead(invite)
			waitForWriteCount(t, transport, 2)

			for range 2 {
				select {
				case got := <-handled:
					if got != "INVITE" {
						t.Fatalf("handled request = %q, want INVITE", got)
					}
				case <-time.After(time.Second):
					t.Fatal("waiting for INVITE to reach TU")
				}
			}
			if tx := sess.lookupServerTransaction(invite); tx == nil {
				t.Fatal("server transaction was removed before Timer L")
			}
			deadline := time.Now().Add(time.Second)
			for sess.lookupServerTransaction(invite) != nil {
				if time.Now().After(deadline) {
					t.Fatal("server transaction remains registered after Timer L")
				}
				time.Sleep(time.Millisecond)
			}

			runCancel()
			if err := <-errCh; !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestInviteServerTransactionReportsTimerH(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "missing ACK notifies TU"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			sess, err := Open(Config{TransactionTimers: TransactionTimers{TH: 10 * time.Millisecond}}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			handler := &requestHandler{}
			if _, err := sess.Attach(handler); err != nil {
				t.Fatalf("Attach() error = %v", err)
			}
			req := Request{Message: newInboundRequest("INVITE", "call-timer-h", "1 INVITE"), Transport: transport, PeerAddr: transport.remote}
			tx := newServerTransaction(sess, req)
			sess.registerServerTransaction(tx)
			resp := sip.NewResponse(486, "Busy Here")
			resp.Headers = sip.ResponseHeaders(req.Message, 486)
			tx.recordResponse(resp)

			deadline := time.Now().Add(time.Second)
			for {
				handler.mu.Lock()
				errs := append([]error(nil), handler.errs...)
				handler.mu.Unlock()
				if len(errs) != 0 {
					if !TransactionTimerExpired(errs[0], "H") {
						t.Fatalf("HandleError() error = %v, want Timer H timeout", errs[0])
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("waiting for Timer H notification")
				}
				time.Sleep(time.Millisecond)
			}
			if tx := sess.lookupServerTransaction(req.Message); tx != nil {
				t.Fatal("server transaction remains registered after Timer H")
			}
		})
	}
}

func newRequest(method, callID, cseq string) sip.Message {
	msg := sip.NewRequest(method, "sip:test@example.com")
	msg.Headers = sip.Headers{
		{Name: "Via", Value: "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1"},
		{Name: "From", Value: "<sip:alice@example.com>;tag=local"},
		{Name: "To", Value: "<sip:bob@example.com>"},
		{Name: "Call-ID", Value: callID},
		{Name: "CSeq", Value: cseq},
		{Name: "Max-Forwards", Value: "70"},
		{Name: "Content-Length", Value: "0"},
	}
	return msg
}

func TestPrepareRequestTransportRejectsOversizedUDPWithoutReliableFlow(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "opener is absent"},
		{
			name: "opener returns nil",
			cfg: Config{OpenReliableTransport: func(context.Context) (Transport, error) {
				return nil, nil
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			sess, err := Open(tt.cfg, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			defer sess.Close()

			req := newRequest("MESSAGE", "call-large", "1 MESSAGE")
			req.Body = make([]byte, sipDatagramRequestLimit)
			req.Headers.Set("Content-Length", fmt.Sprint(len(req.Body)))
			if err := sess.Send(context.Background(), req); err == nil {
				t.Fatal("Send() error = nil, want reliable transport error")
			}
			if got := transport.writeCount(); got != 0 {
				t.Fatalf("UDP write count = %d, want 0", got)
			}
		})
	}
}

func TestActiveReliableTransportMatchesSecurityAssociation(t *testing.T) {
	newSecureTransport := func(network, associationID string) *secureStubTransport {
		stub := newStubTransport(5062, 5060)
		if network == "tcp" {
			stub.local = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5062}
			stub.remote = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060}
		}
		return &secureStubTransport{stubTransport: stub, associationID: associationID, outbound: true}
	}

	tests := []struct {
		name               string
		preferredID        string
		candidateIDs       []string
		wantCandidateIndex int
	}{
		{name: "skip old security association", preferredID: "new", candidateIDs: []string{"old", "new"}, wantCandidateIndex: 1},
		{name: "association identity unavailable", candidateIDs: []string{""}, wantCandidateIndex: -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			preferred := newSecureTransport("udp", tt.preferredID)
			sess, err := Open(Config{}, preferred)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			defer sess.Close()

			candidates := make([]*secureStubTransport, 0, len(tt.candidateIDs))
			for _, associationID := range tt.candidateIDs {
				candidate := newSecureTransport("tcp", associationID)
				if _, err := sess.AddTransport(candidate); err != nil {
					t.Fatalf("AddTransport() error = %v", err)
				}
				candidates = append(candidates, candidate)
			}

			got := sess.activeReliableTransport(preferred)
			if tt.wantCandidateIndex < 0 {
				if got != nil {
					t.Fatalf("activeReliableTransport() = %T, want nil", got)
				}
				return
			}
			if got != candidates[tt.wantCandidateIndex] {
				t.Fatalf("activeReliableTransport() = %p, want candidate %d (%p)", got, tt.wantCandidateIndex, candidates[tt.wantCandidateIndex])
			}
		})
	}
}

func TestSetRequestViaTransportPreservesRemainingViaValues(t *testing.T) {
	tcp := newStubTransport(6062, 5060)
	tcp.local = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6062}
	tcp.remote = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060}

	tests := []struct {
		name    string
		headers sip.Headers
		want    []string
		wantErr bool
	}{
		{
			name:    "single Via",
			headers: sip.Headers{{Name: "Via", Value: "SIP/2.0/UDP 127.0.0.1:5062;branch=first"}},
			want:    []string{"SIP/2.0/TCP 127.0.0.1:6062;branch=first"},
		},
		{
			name: "repeated Via fields",
			headers: sip.Headers{
				{Name: "Via", Value: "SIP/2.0/UDP 127.0.0.1:5062;branch=first"},
				{Name: "Via", Value: "SIP/2.0/UDP 192.0.2.10:5060;branch=second"},
			},
			want: []string{
				"SIP/2.0/TCP 127.0.0.1:6062;branch=first",
				"SIP/2.0/UDP 192.0.2.10:5060;branch=second",
			},
		},
		{
			name:    "comma separated Via values",
			headers: sip.Headers{{Name: "Via", Value: "SIP/2.0/UDP 127.0.0.1:5062;branch=first, SIP/2.0/UDP 192.0.2.10:5060;branch=second"}},
			want:    []string{"SIP/2.0/TCP 127.0.0.1:6062;branch=first, SIP/2.0/UDP 192.0.2.10:5060;branch=second"},
		},
		{name: "missing Via", wantErr: true},
		{name: "malformed Via", headers: sip.Headers{{Name: "Via", Value: "malformed"}}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := sip.NewRequest("MESSAGE", "sip:test@example.com")
			req.Headers = tt.headers.Clone()
			err := setRequestViaTransport(&req, tcp)
			if tt.wantErr {
				if err == nil {
					t.Fatal("setRequestViaTransport() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("setRequestViaTransport() error = %v", err)
			}
			got := req.Headers.Values("Via")
			if !slices.Equal(got, tt.want) {
				t.Fatalf("Via headers = %q, want %q", got, tt.want)
			}
		})
	}
}

func newInboundRequest(method, callID, cseq string) sip.Message {
	return newRequest(method, callID, cseq)
}

func newInboundRequestWithBranch(method, callID, cseq, branch string) sip.Message {
	msg := newInboundRequest(method, callID, cseq)
	msg.Headers.Set("Via", "SIP/2.0/UDP 127.0.0.1:5060;branch="+branch)
	return msg
}

func newResponse(req sip.Message, code int, reason string) sip.Message {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req, code)
	return resp
}

func waitForWriteCount(t *testing.T, transport *stubTransport, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		if transport.writeCount() >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waiting for writes: got %d, want at least %d", transport.writeCount(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForTransportInactive(t *testing.T, sess *Session, transport Transport) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		if !sess.isTransportActive(transport) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("transport is still active")
		}
		time.Sleep(time.Millisecond)
	}
}

func collectHandledMethods(t *testing.T, ch <-chan string, until string) []string {
	t.Helper()
	deadline := time.After(time.Second)
	var got []string
	for {
		select {
		case method := <-ch:
			got = append(got, method)
			if method == until {
				return got
			}
		case <-deadline:
			t.Fatalf("waiting for %s: got %q", until, strings.Join(got, ","))
		}
	}
}

func cloneAddr(addr net.Addr) net.Addr {
	switch v := addr.(type) {
	case *net.UDPAddr:
		return &net.UDPAddr{IP: append(net.IP(nil), v.IP...), Port: v.Port, Zone: v.Zone}
	case *net.TCPAddr:
		return &net.TCPAddr{IP: append(net.IP(nil), v.IP...), Port: v.Port, Zone: v.Zone}
	default:
		return addr
	}
}

func extractStubTransport(t Transport) *stubTransport {
	switch v := t.(type) {
	case *stubTransport:
		return v
	case *basicTransport:
		return v.stub
	case *keepAliveDisabledTransport:
		return v.stubTransport
	default:
		return nil
	}
}

func useTransactionTimers(t *testing.T, timers TransactionTimers) {
	t.Helper()
	previous := defaultTransactionTimers
	defaultTransactionTimers = timers
	t.Cleanup(func() {
		defaultTransactionTimers = previous
	})
}

func TestTransactionTimersNormalizeDefaults(t *testing.T) {
	tests := []struct {
		name  string
		input TransactionTimers
		want  TransactionTimers
	}{
		{
			name:  "empty uses IMS defaults",
			input: TransactionTimers{},
			want:  TransactionTimers{T1: 500 * time.Millisecond, T2: 4 * time.Second, T4: 5 * time.Second, TB: 32 * time.Second, TD: 32 * time.Second, TF: 32 * time.Second, TH: 32 * time.Second, TJ: 32 * time.Second, TL: 32 * time.Second, TM: 32 * time.Second},
		},
		{
			name:  "derived SIP timers scale from custom T1",
			input: TransactionTimers{T1: 100 * time.Millisecond, T2: 800 * time.Millisecond, T4: 900 * time.Millisecond, TD: 32 * time.Second},
			want:  TransactionTimers{T1: 100 * time.Millisecond, T2: 800 * time.Millisecond, T4: 900 * time.Millisecond, TB: 6400 * time.Millisecond, TD: 32 * time.Second, TF: 6400 * time.Millisecond, TH: 6400 * time.Millisecond, TJ: 6400 * time.Millisecond, TL: 6400 * time.Millisecond, TM: 6400 * time.Millisecond},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.input.Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("Normalized() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestExchangeAfterRunRetransmitsNonInviteOverUDP(t *testing.T) {
	useTransactionTimers(t, TransactionTimers{
		T1: 10 * time.Millisecond,
		T2: 20 * time.Millisecond,
		T4: 10 * time.Millisecond,
	})

	transport := newStubTransport(5062, 5060)
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	req := newRequest("MESSAGE", "call-retry", "1 MESSAGE")
	transport.onWrite = func(_ []byte) {
		if transport.writeCount() < 2 {
			return
		}
		transport.queueRead(newResponse(req, 200, "OK"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := sess.Exchange(ctx, req)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Fatalf("StatusCode() = %d, want 200", resp.StatusCode())
	}
	if got := transport.writeCount(); got < 2 {
		t.Fatalf("len(writes) = %d, want at least 2", got)
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestExchangeAfterRunTimesOutTransaction(t *testing.T) {
	useTransactionTimers(t, TransactionTimers{
		T1: 10 * time.Millisecond,
		T2: 20 * time.Millisecond,
		T4: 10 * time.Millisecond,
	})

	transport := newStubTransport(5062, 5060)
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = sess.Exchange(ctx, newRequest("MESSAGE", "call-timeout", "1 MESSAGE"))
	if err == nil {
		t.Fatal("Exchange() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "transaction timeout") {
		t.Fatalf("Exchange() error = %v, want transaction timeout", err)
	}
	if !TransactionTimerExpired(err, "F") {
		t.Fatalf("TransactionTimerExpired(F) = false for %v", err)
	}

	if runErr := <-errCh; !TransactionTimerExpired(runErr, "F") {
		t.Fatalf("Run() error = %v, want Timer F expiration", runErr)
	}
}

func TestTimerFInProceedingDoesNotFailSession(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "non-INVITE received provisional response"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			transport.local = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5062}
			transport.remote = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060}
			sess, err := Open(Config{TransactionTimers: TransactionTimers{TF: 50 * time.Millisecond}}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}

			runCtx, runCancel := context.WithCancel(context.Background())
			defer runCancel()
			runErrCh := make(chan error, 1)
			go func() {
				runErrCh <- sess.Run(runCtx)
			}()
			if err := sess.WaitStarted(context.Background()); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}

			req := newRequest("MESSAGE", "timer-f-proceeding", "1 MESSAGE")
			transport.onWrite = func([]byte) {
				transport.queueRead(newResponse(req, 100, "Trying"))
			}
			provisional := make(chan struct{}, 1)
			exchangeErrCh := make(chan error, 1)
			go func() {
				_, err := sess.ExchangeWithOptions(context.Background(), req, ExchangeOptions{
					OnProvisional: func(sip.Message) {
						provisional <- struct{}{}
					},
				})
				exchangeErrCh <- err
			}()

			select {
			case <-provisional:
			case <-time.After(time.Second):
				t.Fatal("waiting for provisional response")
			}
			if err := <-exchangeErrCh; !TransactionTimerExpired(err, "F") {
				t.Fatalf("Exchange() error = %v, want Timer F expiration", err)
			}
			select {
			case err := <-runErrCh:
				t.Fatalf("Run() returned for Timer F in Proceeding: %v", err)
			default:
			}

			runCancel()
			if err := <-runErrCh; !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestReportedTransportFailuresAreNotDropped(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "primary failure queued behind auxiliary failure"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := newStubTransport(5062, 5060)
			aux := newStubTransport(15062, 15060)
			sess, err := Open(Config{}, primary)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			if _, err := sess.AddTransport(aux); err != nil {
				t.Fatalf("AddTransport() error = %v", err)
			}

			sess.mu.Lock()
			sess.running = true
			sess.mu.Unlock()
			sess.reportTransportFailure(aux, errors.New("auxiliary transaction failed"))
			cause := errors.New("primary transaction failed")
			sess.reportTransportFailure(primary, cause)

			runCtx, runCancel := context.WithCancel(context.Background())
			defer runCancel()
			errCh := make(chan error, 1)
			go func() {
				errCh <- sess.Run(runCtx)
			}()

			select {
			case err := <-errCh:
				if !errors.Is(err, cause) {
					t.Fatalf("Run() error = %v, want %v", err, cause)
				}
			case <-time.After(time.Second):
				t.Fatal("waiting for queued primary transport failure")
			}
		})
	}
}

func TestExchangeTimerStartsBeforeTransportSend(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		wantTimer string
		occupy    bool
	}{
		{name: "non-INVITE blocked in TCP write", method: "MESSAGE", wantTimer: "F"},
		{name: "INVITE blocked in TCP write", method: "INVITE", wantTimer: "B"},
		{name: "non-INVITE waiting for send slot", method: "MESSAGE", wantTimer: "F", occupy: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newBlockingWriteTransport()
			sess, err := Open(Config{TransactionTimers: TransactionTimers{
				TB: 40 * time.Millisecond,
				TF: 40 * time.Millisecond,
			}}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}

			runCtx, runCancel := context.WithCancel(context.Background())
			defer runCancel()
			errCh := make(chan error, 1)
			go func() {
				errCh <- sess.Run(runCtx)
			}()
			if err := sess.WaitStarted(context.Background()); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}

			firstSendErr := make(chan error, 1)
			if tt.occupy {
				go func() {
					firstSendErr <- sess.Send(context.Background(), newRequest("MESSAGE", "blocking-send", "1 MESSAGE"))
				}()
				select {
				case <-transport.entered:
				case <-time.After(time.Second):
					t.Fatal("waiting for blocking write")
				}
			}

			exchangeErr := make(chan error, 1)
			go func() {
				_, err := sess.Exchange(context.Background(), newRequest(tt.method, "timer-start", "1 "+tt.method))
				exchangeErr <- err
			}()

			var got error
			select {
			case got = <-exchangeErr:
			case <-time.After(time.Second):
				t.Fatal("waiting for transaction timeout")
			}
			if !TransactionTimerExpired(got, tt.wantTimer) {
				t.Fatalf("Exchange() error = %v, want Timer %s expiration", got, tt.wantTimer)
			}

			select {
			case runErr := <-errCh:
				if !TransactionTimerExpired(runErr, tt.wantTimer) {
					t.Fatalf("Run() error = %v, want Timer %s expiration", runErr, tt.wantTimer)
				}
			case <-time.After(time.Second):
				t.Fatal("waiting for session failure")
			}

			if tt.occupy {
				close(transport.release)
				if err := <-firstSendErr; err != nil {
					t.Fatalf("first Send() error = %v", err)
				}
			}
		})
	}
}

func TestExchangeReturnsReliableTransportSendError(t *testing.T) {
	cause := errors.New("writing tcp packet: waiting for ack 42")
	transport := newWriteErrorTransport(cause)
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	resp, err := sess.Exchange(context.Background(), newRequest("INVITE", "call-transport-failure", "1 INVITE"))
	if !errors.Is(err, cause) {
		t.Fatalf("Exchange() error = %v, want %v", err, cause)
	}
	if !TransportFailed(err) {
		t.Fatalf("TransportFailed() = false for %v", err)
	}
	if resp.StartLine != "" {
		t.Fatalf("Exchange() response = %v, want zero response", resp)
	}
}

func TestExchangeReturnsUnreliableTransportSendError(t *testing.T) {
	cause := errors.New("writing secure udp packet: tunnel is closed")
	transport := newUnreliableWriteErrorTransport(cause)
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	resp, err := sess.Exchange(context.Background(), newRequest("INVITE", "udp-transport-failure", "1 INVITE"))
	if !errors.Is(err, cause) {
		t.Fatalf("Exchange() error = %v, want %v", err, cause)
	}
	if !TransportFailed(err) {
		t.Fatalf("TransportFailed() = false for %v", err)
	}
	if resp.StartLine != "" {
		t.Fatalf("Exchange() response = %v, want zero response", resp)
	}
}

func TestInviteTransactionSendsACKForNon2xx(t *testing.T) {
	useTransactionTimers(t, TransactionTimers{
		T1: 10 * time.Millisecond,
		T2: 20 * time.Millisecond,
		T4: 10 * time.Millisecond,
		TD: 30 * time.Millisecond,
	})

	transport := newStubTransport(5062, 5060)
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	req := newRequest("INVITE", "call-invite", "1 INVITE")
	transport.onWrite = func(data []byte) {
		msg, err := sip.ParseMessage(data)
		if err != nil {
			t.Fatalf("ParseMessage() error = %v", err)
		}
		if msg.Method() == "INVITE" {
			transport.queueRead(newResponse(req, 404, "Not Found"))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := sess.Exchange(ctx, req)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if resp.StatusCode() != 404 {
		t.Fatalf("StatusCode() = %d, want 404", resp.StatusCode())
	}
	waitForWriteCount(t, transport, 2)
	writes := transport.snapshotWrites()
	if len(writes) < 2 {
		t.Fatalf("len(writes) = %d, want at least 2", len(writes))
	}
	ack, err := sip.ParseMessage(writes[len(writes)-1])
	if err != nil {
		t.Fatalf("ParseMessage(ACK) error = %v", err)
	}
	if ack.Method() != "ACK" {
		t.Fatalf("ack.Method() = %q, want ACK", ack.Method())
	}
	if got := ack.Header("CSeq"); got != "1 ACK" {
		t.Fatalf("ACK CSeq = %q, want 1 ACK", got)
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestInviteTransactionReportsACKTransportFailure(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "non-2xx ACK write failure terminates transaction"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cause := errors.New("ACK transport lost")
			transport := &failAfterWritesTransport{stubTransport: newStubTransport(5062, 5060), failAfter: 1, err: cause}
			sess, err := Open(Config{TransactionTimers: TransactionTimers{T1: 10 * time.Millisecond, TD: time.Second}}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			handler := &requestHandler{}
			if _, err := sess.Attach(handler); err != nil {
				t.Fatalf("Attach() error = %v", err)
			}
			req := newRequest("INVITE", "ack-write-failure", "1 INVITE")
			tx := newClientTransaction(sess, transport, req, ExchangeOptions{})
			if err := tx.start(context.Background()); err != nil {
				t.Fatalf("start() error = %v", err)
			}
			tx.handleResponse(inboundMessage{msg: newResponse(req, 486, "Busy Here"), transport: transport})
			resp, err := tx.await(context.Background())
			if err != nil {
				t.Fatalf("await() error = %v", err)
			}
			if resp.StatusCode() != 486 {
				t.Fatalf("response status = %d, want 486", resp.StatusCode())
			}
			deadline := time.Now().Add(time.Second)
			for {
				handler.mu.Lock()
				errs := append([]error(nil), handler.errs...)
				handler.mu.Unlock()
				if len(errs) != 0 {
					if !errors.Is(errs[0], cause) {
						t.Fatalf("HandleError() error = %v, want %v", errs[0], cause)
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("waiting for ACK transport failure notification")
				}
				time.Sleep(time.Millisecond)
			}
			sess.mu.Lock()
			current := sess.transactions[tx.key]
			sess.mu.Unlock()
			if current != nil {
				t.Fatal("transaction remains registered after ACK transport failure")
			}
		})
	}
}

func TestInviteTransactionRetransmitsACKForRepeatedNon2xx(t *testing.T) {
	useTransactionTimers(t, TransactionTimers{
		T1: 10 * time.Millisecond,
		T2: 20 * time.Millisecond,
		T4: 10 * time.Millisecond,
		TD: 40 * time.Millisecond,
	})

	transport := newStubTransport(5062, 5060)
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	req := newRequest("INVITE", "call-repeat-ack", "1 INVITE")
	transport.onWrite = func(data []byte) {
		msg, err := sip.ParseMessage(data)
		if err != nil {
			t.Fatalf("ParseMessage() error = %v", err)
		}
		switch msg.Method() {
		case "INVITE":
			transport.queueRead(newResponse(req, 486, "Busy Here"))
		case "ACK":
			if transport.writeCount() == 2 {
				transport.queueRead(newResponse(req, 486, "Busy Here"))
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := sess.Exchange(ctx, req)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if resp.StatusCode() != 486 {
		t.Fatalf("StatusCode() = %d, want 486", resp.StatusCode())
	}

	time.Sleep(20 * time.Millisecond)

	ackCount := 0
	for _, data := range transport.snapshotWrites() {
		msg, err := sip.ParseMessage(data)
		if err != nil {
			t.Fatalf("ParseMessage() error = %v", err)
		}
		if msg.Method() == "ACK" {
			ackCount++
		}
	}
	if ackCount < 2 {
		t.Fatalf("ACK count = %d, want at least 2", ackCount)
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestInviteTransactionPassesLate2xxToCore(t *testing.T) {
	tests := []struct {
		name               string
		firstLateTransport bool
		wantBeforeAccepted bool
	}{
		{name: "late 2xx during Timer D reaches core", firstLateTransport: true, wantBeforeAccepted: true},
		{name: "disallowed response transport is ignored", firstLateTransport: false, wantBeforeAccepted: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			other := newStubTransport(5064, 5060)
			sess, err := Open(Config{TransactionTimers: TransactionTimers{T1: 10 * time.Millisecond, TD: time.Second}}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			capture := &responseCaptureHandler{responses: make(chan sip.Message, 1)}
			if _, err := sess.Attach(capture); err != nil {
				t.Fatalf("Attach() error = %v", err)
			}
			req := newRequest("INVITE", "late-success", "1 INVITE")
			tx := newClientTransaction(sess, transport, req, ExchangeOptions{
				AcceptResponseTransport: func(got Transport) bool { return got == transport },
			})
			if err := tx.start(context.Background()); err != nil {
				t.Fatalf("start() error = %v", err)
			}
			tx.handleResponse(inboundMessage{msg: newResponse(req, 486, "Busy Here"), transport: transport})
			resp, err := tx.await(context.Background())
			if err != nil {
				t.Fatalf("await() error = %v", err)
			}
			if resp.StatusCode() != 486 {
				t.Fatalf("first response status = %d, want 486", resp.StatusCode())
			}

			lateTransport := Transport(other)
			if tt.firstLateTransport {
				lateTransport = transport
			}
			tx.handleResponse(inboundMessage{msg: newResponse(req, 200, "OK"), transport: lateTransport})
			select {
			case got := <-capture.responses:
				if !tt.wantBeforeAccepted || got.StatusCode() != 200 {
					t.Fatalf("unexpected core response status %d", got.StatusCode())
				}
			case <-time.After(20 * time.Millisecond):
				if tt.wantBeforeAccepted {
					t.Fatal("late 2xx was not passed to core")
				}
			}
			if !tt.firstLateTransport {
				tx.handleResponse(inboundMessage{msg: newResponse(req, 200, "OK"), transport: transport})
				select {
				case got := <-capture.responses:
					if got.StatusCode() != 200 {
						t.Fatalf("core response status = %d, want 200", got.StatusCode())
					}
				case <-time.After(time.Second):
					t.Fatal("accepted late 2xx was not passed to core")
				}
			}
			sess.mu.Lock()
			current := sess.transactions[tx.key]
			sess.mu.Unlock()
			if current != nil {
				t.Fatal("INVITE transaction remains registered after late 2xx")
			}
		})
	}
}

func TestInviteTransactionRetainsAcceptedResponsesUntilTimerM(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "additional 2xx reaches core before Timer M"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			other := newStubTransport(5064, 5060)
			sess, err := Open(Config{TransactionTimers: TransactionTimers{TM: 100 * time.Millisecond}}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			capture := &responseCaptureHandler{responses: make(chan sip.Message, 1)}
			if _, err := sess.Attach(capture); err != nil {
				t.Fatalf("Attach() error = %v", err)
			}
			req := newRequest("INVITE", "accepted-timer-m", "1 INVITE")
			tx := newClientTransaction(sess, transport, req, ExchangeOptions{
				AcceptResponseTransport: func(got Transport) bool { return got == transport },
			})
			if err := tx.start(context.Background()); err != nil {
				t.Fatalf("start() error = %v", err)
			}
			tx.handleResponse(inboundMessage{msg: newResponse(req, 200, "OK"), transport: transport})
			resp, err := tx.await(context.Background())
			if err != nil {
				t.Fatalf("await() error = %v", err)
			}
			if resp.StatusCode() != 200 {
				t.Fatalf("first response status = %d, want 200", resp.StatusCode())
			}
			sess.mu.Lock()
			current := sess.transactions[tx.key]
			sess.mu.Unlock()
			if current != tx {
				t.Fatal("client transaction was removed before Timer M")
			}

			tx.handleResponse(inboundMessage{msg: newResponse(req, 200, "OK"), transport: other})
			tx.handleResponse(inboundMessage{msg: newResponse(req, 200, "OK"), transport: transport})
			select {
			case got := <-capture.responses:
				if got.StatusCode() != 200 {
					t.Fatalf("additional response status = %d, want 200", got.StatusCode())
				}
			case <-time.After(time.Second):
				t.Fatal("additional 2xx did not reach core")
			}
			select {
			case <-capture.responses:
				t.Fatal("response from disallowed transport reached core")
			case <-time.After(20 * time.Millisecond):
			}

			deadline := time.Now().Add(time.Second)
			for {
				sess.mu.Lock()
				current := sess.transactions[tx.key]
				sess.mu.Unlock()
				if current == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("client transaction remains registered after Timer M")
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

func TestInviteTransactionDoesNotDropForked2xxBurst(t *testing.T) {
	tests := []struct {
		name  string
		count int
	}{
		{name: "burst exceeds former response buffer", count: 12},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(5062, 5060)
			sess, err := Open(Config{TransactionTimers: TransactionTimers{TM: time.Second}}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			capture := &responseCaptureHandler{responses: make(chan sip.Message, tt.count)}
			if _, err := sess.Attach(capture); err != nil {
				t.Fatalf("Attach() error = %v", err)
			}
			req := newRequest("INVITE", "forked-2xx-burst", "1 INVITE")
			tx := newClientTransaction(sess, transport, req, ExchangeOptions{})
			if err := tx.start(context.Background()); err != nil {
				t.Fatalf("start() error = %v", err)
			}
			tx.handleResponse(inboundMessage{msg: newResponse(req, 200, "OK"), transport: transport})
			if _, err := tx.await(context.Background()); err != nil {
				t.Fatalf("await() error = %v", err)
			}

			for i := range tt.count {
				resp := newResponse(req, 200, "OK")
				resp.Headers.Set("To", fmt.Sprintf("<sip:bob@example.com>;tag=fork-%d", i))
				tx.handleResponse(inboundMessage{msg: resp, transport: transport})
			}
			for i := range tt.count {
				select {
				case <-capture.responses:
				case <-time.After(time.Second):
					t.Fatalf("received %d additional 2xx responses, want %d", i, tt.count)
				}
			}
			tx.terminate()
		})
	}
}

func TestInviteTransactionTimerBStopsAfterProvisional(t *testing.T) {
	timers := TransactionTimers{
		T1: 10 * time.Millisecond,
		T2: 20 * time.Millisecond,
		T4: 10 * time.Millisecond,
		TB: 30 * time.Millisecond,
		TD: 30 * time.Millisecond,
	}

	transport := newStubTransport(5062, 5060)
	sess, err := Open(Config{TransactionTimers: timers}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	req := newRequest("INVITE", "call-proceeding", "1 INVITE")
	transport.onWrite = func(data []byte) {
		msg, err := sip.ParseMessage(data)
		if err != nil {
			t.Fatalf("ParseMessage() error = %v", err)
		}
		if msg.Method() != "INVITE" {
			return
		}
		transport.queueRead(newResponse(req, 180, "Ringing"))
		time.AfterFunc(2*timers.TB, func() {
			transport.queueRead(newResponse(req, 200, "OK"))
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := sess.Exchange(ctx, req)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Fatalf("StatusCode() = %d, want 200", resp.StatusCode())
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestInviteTransactionDefaultTimerDUsesIMSProfile(t *testing.T) {
	transport := newStubTransport(5062, 5060)
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	tx := newClientTransaction(sess, transport, newRequest("INVITE", "call-d", "1 INVITE"), ExchangeOptions{})
	if got := tx.timerD(); got != 32*time.Second {
		t.Fatalf("timerD() = %v, want 32s", got)
	}
}
