package vowifi

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/damonto/vowifi-go/ims/registration"
	imssession "github.com/damonto/vowifi-go/ims/session"
	imssip "github.com/damonto/vowifi-go/ims/sip"
	imssms "github.com/damonto/vowifi-go/ims/sms"
	imsussd "github.com/damonto/vowifi-go/ims/ussd"
	swutunnel "github.com/damonto/vowifi-go/swu/tunnel"
	"github.com/damonto/vowifi-go/usim"
	usimreader "github.com/damonto/vowifi-go/usim/reader"
)

type stubCard struct{}

type plmnTestCard struct {
	stubCard
	mcc string
	mnc string
}

func (c plmnTestCard) MCC() string { return c.mcc }
func (c plmnTestCard) MNC() string { return c.mnc }

type testTunnelBackoffError struct {
	delay       time.Duration
	deactivated bool
	scope       swutunnel.BackoffScope
}

type testTunnelBackoffDeactivatedError struct{}

func (e testTunnelBackoffError) Error() string {
	return "ePDG backoff"
}

func (e testTunnelBackoffError) BackoffDelay() time.Duration {
	return e.delay
}

func (e testTunnelBackoffError) BackoffDeactivated() bool {
	return e.deactivated
}

func (e testTunnelBackoffError) BackoffPolicy() swutunnel.BackoffPolicy {
	return swutunnel.BackoffPolicy{
		Delay:       e.delay,
		Deactivated: e.deactivated,
		Scope:       e.scope,
	}
}

func (testTunnelBackoffDeactivatedError) Error() string {
	return "ePDG backoff deactivated"
}

func (testTunnelBackoffDeactivatedError) BackoffDeactivated() bool {
	return true
}

func (testTunnelBackoffDeactivatedError) BackoffPolicy() swutunnel.BackoffPolicy {
	return swutunnel.BackoffPolicy{
		Deactivated: true,
		Scope:       swutunnel.BackoffScopeEPDG,
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testRegistrationConfig(transport imssession.Transport) registration.Config {
	return registration.Config{
		Logger: testLogger(),
		DialSecureUDP: func(ctx context.Context, cfg imssession.SecureUDPConfig) (imssession.Transport, error) {
			return transport, nil
		},
		DialSecureTCP: func(ctx context.Context, cfg imssession.SecureTCPConfig) (imssession.Transport, error) {
			return transport, nil
		},
	}
}

func (stubCard) ICCID() string { return "8986000000000000000" }
func (stubCard) IMSI() string  { return "001010123456789" }
func (stubCard) MCC() string   { return "001" }
func (stubCard) MNC() string   { return "001" }
func (stubCard) SMSC() string  { return "+8613800000000" }
func (stubCard) AKA(_ context.Context, _, _ []byte) (usim.AKAResult, error) {
	return usim.AKAResult{
		RES: []byte("12345678"),
		CK:  []byte("client-test-ck"),
		IK:  []byte("client-test-ik"),
	}, nil
}

type readerStub struct {
	closeCalls        int
	closeErr          error
	listApplications  func(context.Context) ([]usimreader.Application, error)
	getFileAttributes func(context.Context, usimreader.FileRef) (usimreader.FileAttributes, error)
	readTransparent   func(context.Context, usimreader.TransparentRead) ([]byte, error)
	readRecord        func(context.Context, usimreader.RecordRead) ([]byte, error)
	authenticate3G    func(context.Context, usimreader.AuthenticateRequest) ([]byte, error)
	smsPPDownload     func(context.Context, usimreader.SMSPPDownloadRequest) (usimreader.SMSPPDownloadResponse, error)
}

func (r *readerStub) ListApplications(ctx context.Context) ([]usimreader.Application, error) {
	if r.listApplications == nil {
		return nil, errors.New("ListApplications was not expected")
	}
	return r.listApplications(ctx)
}

func (r *readerStub) GetFileAttributes(ctx context.Context, file usimreader.FileRef) (usimreader.FileAttributes, error) {
	if r.getFileAttributes == nil {
		return usimreader.FileAttributes{}, errors.New("GetFileAttributes was not expected")
	}
	return r.getFileAttributes(ctx, file)
}

func (r *readerStub) ReadTransparent(ctx context.Context, req usimreader.TransparentRead) ([]byte, error) {
	if r.readTransparent == nil {
		return nil, errors.New("ReadTransparent was not expected")
	}
	return r.readTransparent(ctx, req)
}

func (r *readerStub) ReadRecord(ctx context.Context, req usimreader.RecordRead) ([]byte, error) {
	if r.readRecord == nil {
		return nil, errors.New("ReadRecord was not expected")
	}
	return r.readRecord(ctx, req)
}

func (r *readerStub) Authenticate3G(ctx context.Context, req usimreader.AuthenticateRequest) ([]byte, error) {
	if r.authenticate3G == nil {
		return nil, errors.New("Authenticate3G was not expected")
	}
	return r.authenticate3G(ctx, req)
}

func (r *readerStub) SMSPPDownload(ctx context.Context, req usimreader.SMSPPDownloadRequest) (usimreader.SMSPPDownloadResponse, error) {
	if r.smsPPDownload == nil {
		return usimreader.SMSPPDownloadResponse{}, errors.New("SMSPPDownload was not expected")
	}
	return r.smsPPDownload(ctx, req)
}

func (r *readerStub) Close() error {
	r.closeCalls++
	return r.closeErr
}

type gatedCancelTransport struct {
	local  net.Addr
	remote net.Addr

	mu                sync.Mutex
	writes            [][]byte
	onWrite           func([]byte)
	readCh            chan []byte
	readErrCh         chan error
	cancelReadRelease chan struct{}
	closed            bool
}

func newGatedCancelTransport(localPort, remotePort int) *gatedCancelTransport {
	return &gatedCancelTransport{
		local:             &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort},
		remote:            &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remotePort},
		readCh:            make(chan []byte, 16),
		readErrCh:         make(chan error, 1),
		cancelReadRelease: make(chan struct{}),
	}
}

func (t *gatedCancelTransport) LocalAddr() net.Addr  { return t.local }
func (t *gatedCancelTransport) RemoteAddr() net.Addr { return t.remote }

func (t *gatedCancelTransport) WritePacket(_ context.Context, data []byte) error {
	t.mu.Lock()
	closed := t.closed
	if !closed {
		t.writes = append(t.writes, append([]byte(nil), data...))
	}
	onWrite := t.onWrite
	t.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if onWrite != nil {
		onWrite(data)
	}
	return nil
}

func (t *gatedCancelTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case pkt := <-t.readCh:
		return pkt, t.remote, nil
	case err := <-t.readErrCh:
		return nil, nil, err
	case <-ctx.Done():
		<-t.cancelReadRelease
		return nil, nil, ctx.Err()
	}
}

func (t *gatedCancelTransport) Close() error {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	select {
	case <-t.cancelReadRelease:
	default:
		close(t.cancelReadRelease)
	}
	return nil
}

func (t *gatedCancelTransport) queueRead(msg imssip.Message) {
	t.readCh <- msg.Bytes()
}

func (t *gatedCancelTransport) failRead(err error) {
	t.readErrCh <- err
}

func (t *gatedCancelTransport) writeCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.writes)
}

const (
	testIMEI              = "356789012345678"
	fakeIMSSecurityServer = "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=5062;port-s=5060;prot=esp;spi-c=310;spi-s=320"
)

func newStandaloneClient(t *testing.T) *Client {
	t.Helper()
	return newReadyClient(t, Config{
		Terminal: TerminalInfo{ID: testIMEI},
		IMS: IMSConfig{
			RegisterExpires: time.Minute,
		},
	})
}

func newReadyClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	client := newClient(cfg)
	normalized, err := cfg.normalized(stubCard{})
	if err != nil {
		t.Fatalf("Config.normalized() error = %v", err)
	}
	client.card = stubCard{}
	client.cfg = normalized
	client.logger = normalized.Logger.With("component", "vowifi-go")
	return client
}

func testNonce() string {
	return base64.StdEncoding.EncodeToString(append(bytesOf(0x01, 16), bytesOf(0x02, 16)...))
}

func newIMSResponse(req imssip.Message, code int, reason string) imssip.Message {
	res := imssip.NewResponse(code, reason)
	res.Headers = responseHeaders(req)
	return res
}

func newUnauthorizedRegisterResponse(req imssip.Message, nonce string) imssip.Message {
	res := newIMSResponse(req, 401, "Unauthorized")
	res.Headers.Add("WWW-Authenticate", fmt.Sprintf(`Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="%s",algorithm=AKAv1-MD5`, nonce))
	res.Headers.Add("Security-Server", fakeIMSSecurityServer)
	return res
}

func newRegisteredIMSRuntime(t *testing.T, transport *gatedCancelTransport, registerExpires time.Duration) (*imssession.Session, *registration.Service) {
	t.Helper()
	sess, err := imssession.Open(imssession.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	cfg := testRegistrationConfig(transport)
	cfg.RegisterExpires = registerExpires
	reg, err := registration.New(cfg, sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	return sess, reg
}

func TestSMSEventsFanOutAndSubscribeError(t *testing.T) {
	client := newStandaloneClient(t)
	clientEvents := client.Events()
	defer clientEvents.Close()

	smsEventsA := client.SMS().Events()
	defer smsEventsA.Close()
	smsEventsB := client.SMS().Events()
	defer smsEventsB.Close()

	stop := client.SMS().Subscribe(func(msg SMS) error {
		if msg.Text != "hello" {
			t.Fatalf("msg.Text = %q, want hello", msg.Text)
		}
		return errors.New("boom")
	})
	defer stop()

	client.handleSMS(imssms.IncomingSMS{CallID: "sms-call-id", From: "+1", FromURI: "sip:+1@example.net", To: "+2", ServiceCenter: "+3", Text: "hello"})

	for i, events := range []*SMSEvents{smsEventsA, smsEventsB} {
		select {
		case msg := <-events.Incoming:
			if msg.Text != "hello" {
				t.Fatalf("subscriber %d msg = %+v", i, msg)
			}
			if msg.CallID != "sms-call-id" {
				t.Fatalf("subscriber %d msg.CallID = %q, want sms-call-id", i, msg.CallID)
			}
			if msg.From != "+1" || msg.FromURI != "sip:+1@example.net" {
				t.Fatalf("subscriber %d sender = %q/%q, want +1/sip:+1@example.net", i, msg.From, msg.FromURI)
			}
		case <-time.After(time.Second):
			t.Fatalf("waiting for sms subscriber %d", i)
		}
	}

	select {
	case err := <-clientEvents.Errors:
		if !strings.Contains(err.Error(), "sms subscriber") {
			t.Fatalf("client error = %v, want sms subscriber callback error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for callback error")
	}
}

func TestBroadcasterConcurrentPublishAndClose(t *testing.T) {
	for range 100 {
		b := newBroadcaster[int]()
		subs := make([]broadcastSubscription[int], 64)
		for i := range subs {
			subs[i] = b.subscribe(1)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				<-start
				for n := range 50 {
					b.publish(n, nil)
				}
			})
		}
		for _, sub := range subs[:len(subs)/2] {
			wg.Add(1)
			go func(sub broadcastSubscription[int]) {
				defer wg.Done()
				<-start
				sub.close()
			}(sub)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			b.close()
		}()

		close(start)
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("waiting for concurrent broadcaster close")
		}
	}
}

func TestHandleUSSDEventFanOutUsesWrapper(t *testing.T) {
	client := newStandaloneClient(t)

	eventsA := client.USSD().Events()
	defer eventsA.Close()
	eventsB := client.USSD().Events()
	defer eventsB.Close()

	low := &imsussd.Session{}
	client.handleUSSD(low, imsussd.Message{Text: "Enter PIN", Language: "en", Request: true})

	var first *IncomingUSSD
	for i, events := range []*USSDEvents{eventsA, eventsB} {
		select {
		case event := <-events.Incoming:
			if event.Message.Text != "Enter PIN" || !event.Message.Request {
				t.Fatalf("event.Message = %+v", event.Message)
			}
			if event.Session == nil {
				t.Fatalf("subscriber %d session = nil", i)
			}
			if first == nil {
				first = &event
				continue
			}
			if event.Session != first.Session {
				t.Fatal("subscribers received different session wrappers")
			}
		case <-time.After(time.Second):
			t.Fatalf("waiting for ussd subscriber %d", i)
		}
	}

	client.handleUSSD(low, imsussd.Message{Text: "Next", Language: "en", Request: true})
	select {
	case event := <-eventsA.Incoming:
		if event.Session != first.Session {
			t.Fatal("reused low session did not reuse wrapper")
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for second ussd event")
	}
}

func TestHandleSMSStatusReportEvent(t *testing.T) {
	client := newStandaloneClient(t)
	events := client.SMS().Events()
	defer events.Close()
	client.trackSMSSubmission(SMSSubmission{
		ID:           "sms-7",
		SegmentCount: 2,
		Segments: []SMSSubmissionSegment{
			{Index: 0, Recipient: "+15550000006", ServiceCenter: "+15550000000", TPReference: 6},
			{Index: 1, Recipient: "+15551234567", ServiceCenter: "+15550000000", TPReference: 7},
		},
	})

	report := imssms.StatusReport{
		ServiceCenter:    "+15550000000",
		Recipient:        "+15551234567",
		MessageReference: 7,
		Status:           0x00,
	}
	client.handleSMSStatusReport(report)

	select {
	case event := <-events.Reports:
		if event.SubmissionID != "sms-7" {
			t.Fatalf("event.SubmissionID = %q, want sms-7", event.SubmissionID)
		}
		if event.SegmentIndex != 1 {
			t.Fatalf("event.SegmentIndex = %d, want 1", event.SegmentIndex)
		}
		if event.SegmentCount != 2 {
			t.Fatalf("event.SegmentCount = %d, want 2", event.SegmentCount)
		}
		if event.ServiceCenter != report.ServiceCenter {
			t.Fatalf("event.ServiceCenter = %q, want %q", event.ServiceCenter, report.ServiceCenter)
		}
		if event.Recipient != report.Recipient {
			t.Fatalf("event.Recipient = %q, want %q", event.Recipient, report.Recipient)
		}
		if event.MessageReference != report.MessageReference {
			t.Fatalf("event.MessageReference = %d, want %d", event.MessageReference, report.MessageReference)
		}
		if event.Status != report.Status {
			t.Fatalf("event.Status = 0x%02X, want 0x%02X", event.Status, report.Status)
		}
		if !event.Status.Delivered() {
			t.Fatalf("event.Status.Delivered() = false, want true")
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for SMS status report event")
	}
}

func TestSMSStatusReportLinkKeepsRetryingReports(t *testing.T) {
	tests := []struct {
		name       string
		status     SMSReportStatus
		wantLinked bool
	}{
		{
			name:       "temporary retrying keeps link",
			status:     SMSReportStatusRetryingSMEBusy,
			wantLinked: true,
		},
		{
			name:       "final delivered removes link after report",
			status:     SMSReportStatusReceivedBySME,
			wantLinked: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newStandaloneClient(t)
			client.trackSMSSubmission(SMSSubmission{
				ID:           "sms-1",
				SegmentCount: 1,
				Segments:     []SMSSubmissionSegment{{Index: 0, Recipient: "+15551234567", ServiceCenter: "+15550000000", TPReference: 8}},
			})
			report := imssms.StatusReport{
				ServiceCenter:    "+15550000000",
				Recipient:        "+15551234567",
				MessageReference: 8,
				Status:           tt.status,
			}
			client.handleSMSStatusReport(report)
			_, gotLinked := client.smsReportLink(report)
			if gotLinked != tt.wantLinked {
				t.Fatalf("smsReportLink() = %t, want %t", gotLinked, tt.wantLinked)
			}
		})
	}
}

func TestSMSStatusReportLinkMatchesReferenceCollisionsByRoute(t *testing.T) {
	client := newStandaloneClient(t)
	client.trackSMSSubmission(SMSSubmission{
		ID:           "sms-1",
		SegmentCount: 1,
		Segments:     []SMSSubmissionSegment{{Index: 0, Recipient: "+15550000001", ServiceCenter: "+15550000000", TPReference: 9}},
	})
	client.trackSMSSubmission(SMSSubmission{
		ID:           "sms-2",
		SegmentCount: 1,
		Segments:     []SMSSubmissionSegment{{Index: 0, Recipient: "+15550000002", ServiceCenter: "+15550000000", TPReference: 9}},
	})

	link, ok := client.smsReportLink(imssms.StatusReport{
		ServiceCenter:    "+15550000000",
		Recipient:        "+15550000002",
		MessageReference: 9,
	})
	if !ok {
		t.Fatal("smsReportLink() ok = false")
	}
	if link.submissionID != "sms-2" {
		t.Fatalf("submissionID = %q, want sms-2", link.submissionID)
	}
}

func TestSMSStatusReportLinkSkipsAmbiguousReferenceCollision(t *testing.T) {
	client := newStandaloneClient(t)
	client.trackSMSSubmission(SMSSubmission{
		ID:           "sms-1",
		SegmentCount: 1,
		Segments:     []SMSSubmissionSegment{{Index: 0, Recipient: "+15550000001", ServiceCenter: "+15550000000", TPReference: 9}},
	})
	client.trackSMSSubmission(SMSSubmission{
		ID:           "sms-2",
		SegmentCount: 1,
		Segments:     []SMSSubmissionSegment{{Index: 0, Recipient: "+15550000002", ServiceCenter: "+15550000000", TPReference: 9}},
	})

	_, ok := client.smsReportLink(imssms.StatusReport{
		ServiceCenter:    "+15550000000",
		MessageReference: 9,
	})
	if ok {
		t.Fatal("smsReportLink() ok = true, want false for ambiguous TP-MR collision")
	}
}

func TestUSSDSessionStateErrors(t *testing.T) {
	client := newStandaloneClient(t)
	session := newSession(client)

	replyResult, err := session.Reply(context.Background(), "1")
	if err == nil || !errors.Is(err, ErrUSSDNotStarted) {
		t.Fatalf("Reply() error = %v, want ErrUSSDNotStarted", err)
	}
	if replyResult != (USSDResult{}) {
		t.Fatalf("Reply() result = %+v, want zero value", replyResult)
	}

	closeResult, err := session.Close(context.Background())
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !closeResult.Closed || closeResult.HasMessage {
		t.Fatalf("Close() result = %+v", closeResult)
	}

	if _, err := session.Send(context.Background(), "*100#"); err == nil || !errors.Is(err, ErrUSSDClosed) {
		t.Fatalf("Send(after Close) error = %v, want ErrUSSDClosed", err)
	}

	started := newSession(client)
	if err := started.attachLowSession(&imsussd.Session{}, false); err != nil {
		t.Fatalf("attachLowSession() error = %v", err)
	}
	if _, err := started.Send(context.Background(), "*100#"); err == nil || !errors.Is(err, ErrUSSDAlreadyStarted) {
		t.Fatalf("second Send() error = %v, want ErrUSSDAlreadyStarted", err)
	}

	busy := newSession(client)
	busy.busy = true
	if _, err := busy.Reply(context.Background(), "1"); err == nil || !errors.Is(err, ErrUSSDInProgress) {
		t.Fatalf("Reply(busy) error = %v, want ErrUSSDInProgress", err)
	}
}

func responseHeaders(req imssip.Message) imssip.Headers {
	return imssip.Headers{
		{Name: "Via", Value: req.Header("Via")},
		{Name: "From", Value: req.Header("From")},
		{Name: "To", Value: req.Header("To")},
		{Name: "Call-ID", Value: req.Header("Call-ID")},
		{Name: "CSeq", Value: req.Header("CSeq")},
	}
}

func bytesOf(value byte, count int) []byte {
	out := make([]byte, count)
	for i := range count {
		out[i] = value
	}
	return out
}

func TestNewNilDriver(t *testing.T) {
	_, err := New(nil, nil)
	if err == nil {
		t.Fatal("New() error = nil, want non-nil")
	}
}

func TestConnectReportsUSIMLoadError(t *testing.T) {
	reader := &readerStub{
		listApplications: func(context.Context) ([]usimreader.Application, error) {
			return nil, errors.New("boom")
		},
	}

	client, err := New(reader, &Config{Terminal: TerminalInfo{ID: testIMEI}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = client.Connect(context.Background())
	if err == nil {
		t.Fatal("Connect() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Connect() error = %v, want load error text", err)
	}
	if reader.closeCalls != 0 {
		t.Fatalf("reader Close() calls = %d, want 0 before Close", reader.closeCalls)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if reader.closeCalls != 1 {
		t.Fatalf("reader Close() calls = %d, want 1 after Close", reader.closeCalls)
	}
}

func TestConnectUsesContextForUSIMLoad(t *testing.T) {
	tests := []struct {
		name string
		ctx  func() context.Context
	}{
		{
			name: "canceled before connect",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &readerStub{
				listApplications: func(ctx context.Context) ([]usimreader.Application, error) {
					return nil, ctx.Err()
				},
			}
			client, err := New(reader, &Config{Terminal: TerminalInfo{ID: testIMEI}})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer client.Close()
			err = client.Connect(tt.ctx())
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Connect() error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestCloseCancelsUSIMLoadDuringConnect(t *testing.T) {
	started := make(chan struct{})
	reader := &readerStub{
		listApplications: func(ctx context.Context) ([]usimreader.Application, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	client, err := New(reader, &Config{Terminal: TerminalInfo{ID: testIMEI}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	connectErr := make(chan error, 1)
	go func() {
		connectErr <- client.Connect(context.Background())
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("waiting for USIM load to start")
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.CloseContext(closeCtx); err != nil {
		t.Fatalf("CloseContext() error = %v", err)
	}

	select {
	case err := <-connectErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Connect() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for Connect to exit")
	}
	if reader.closeCalls != 1 {
		t.Fatalf("reader Close() calls = %d, want 1", reader.closeCalls)
	}
}

func TestCloseContextReturnsWhenCloseTaskDoesNotExit(t *testing.T) {
	client := newStandaloneClient(t)
	reader := &readerStub{}
	client.reader = reader

	done, ok := client.reserveCloseTask()
	if !ok {
		t.Fatal("reserveCloseTask() = false, want true")
	}
	defer done()

	closeCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := client.CloseContext(closeCtx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CloseContext() error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("CloseContext() took %s, want bounded by context", elapsed)
	}
	if reader.closeCalls != 1 {
		t.Fatalf("reader Close() calls = %d, want 1", reader.closeCalls)
	}
}

func TestConnectLeavesReaderOwnedAfterUSIMLoadError(t *testing.T) {
	reader := &readerStub{
		closeErr: errors.New("close boom"),
		listApplications: func(context.Context) ([]usimreader.Application, error) {
			return nil, errors.New("load boom")
		},
	}

	client, err := New(reader, &Config{Terminal: TerminalInfo{ID: testIMEI}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = client.Connect(context.Background())
	if err == nil {
		t.Fatal("Connect() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "load boom") {
		t.Fatalf("Connect() error = %v, want load error text", err)
	}
	if err := client.Close(); err == nil || !strings.Contains(err.Error(), "close boom") {
		t.Fatalf("Close() error = %v, want close boom", err)
	}
}

func TestNewClosesReaderOnConfigError(t *testing.T) {
	reader := newReaderStubForUSIMLoad()

	_, err := New(reader, &Config{})
	if err == nil {
		t.Fatal("New() error = nil, want non-nil")
	}
	if reader.closeCalls != 1 {
		t.Fatalf("reader Close() calls = %d, want 1", reader.closeCalls)
	}
}

func TestClientCloseClosesOwnedReaderOnce(t *testing.T) {
	client := newStandaloneClient(t)
	reader := &readerStub{}
	client.reader = reader

	if err := client.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if reader.closeCalls != 1 {
		t.Fatalf("reader Close() calls = %d, want 1", reader.closeCalls)
	}
}

func TestAbortConnectStartWaitsForIMSLoopExitBeforeDeregister(t *testing.T) {
	transport := newGatedCancelTransport(5062, 5060)
	nonce := testNonce()
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch transport.writeCount() {
		case 1:
			transport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
		case 2:
			transport.queueRead(newIMSResponse(req, 200, "OK"))
		case 3:
			if got := req.Header("Expires"); got != "0" {
				t.Errorf("Expires = %q, want 0", got)
			}
			if got := req.Header("Contact"); got != "*" {
				t.Errorf("Contact = %q, want *", got)
			}
			resp := newIMSResponse(req, 401, "Unauthorized")
			resp.Headers.Add("WWW-Authenticate", fmt.Sprintf(`Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="%s",algorithm=AKAv1-MD5,qop="auth"`, nonce))
			transport.queueRead(resp)
		case 4:
			transport.queueRead(newIMSResponse(req, 200, "OK"))
		}
	}

	sess, err := imssession.Open(imssession.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(testRegistrationConfig(transport), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	client := newReadyClient(t, Config{
		Terminal: TerminalInfo{ID: testIMEI},
		IMS: IMSConfig{
			RegisterExpires: time.Minute,
		},
	})
	defer client.Close()

	runCtx, cancelRun := context.WithCancel(context.Background())
	active := &activeConn{
		runCtx:     runCtx,
		cancel:     cancelRun,
		imsSession: sess,
		reg:        reg,
	}

	client.mu.Lock()
	client.active = active
	client.mu.Unlock()

	done, ok := client.reserveCloseTask()
	if !ok {
		t.Fatal("reserveCloseTask() = false, want true")
	}
	runDone := client.startIMSRunner(active, done)
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	cleanupDone := make(chan struct{})
	go func() {
		client.abortConnectStart(active, runDone)
		close(cleanupDone)
	}()

	close(transport.cancelReadRelease)

	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("abortConnectStart() did not finish after IMS loop exit")
	}
	if got := transport.writeCount(); got != 4 {
		t.Fatalf("write count after cleanup = %d, want 4", got)
	}
	if reg.State().Registered {
		t.Fatal("Registered = true, want false")
	}
}

func TestCloseActiveRuntimeSkipsDeregister(t *testing.T) {
	transport := newGatedCancelTransport(5062, 5060)
	nonce := testNonce()
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch transport.writeCount() {
		case 1:
			transport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
		case 2:
			transport.queueRead(newIMSResponse(req, 200, "OK"))
		default:
			t.Fatalf("unexpected write during runtime cleanup: %s", req.StartLine)
		}
	}

	sess, err := imssession.Open(imssession.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(testRegistrationConfig(transport), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	ussdSvc, err := imsussd.New(imsussd.Config{Logger: testLogger()}, sess, reg)
	if err != nil {
		t.Fatalf("ussd.New() error = %v", err)
	}

	client := newReadyClient(t, Config{Terminal: TerminalInfo{ID: testIMEI}})
	active := &activeConn{imsSession: sess, reg: reg, ussd: ussdSvc}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.closeActiveRuntime(ctx, active); err != nil {
		t.Fatalf("closeActiveRuntime() error = %v", err)
	}
	if got := transport.writeCount(); got != 2 {
		t.Fatalf("write count = %d, want registration only", got)
	}
	if reg.State().Registered {
		t.Fatal("Registered = true, want local registration state cleared")
	}
}

func TestIMSRunnerMaintainsRegistration(t *testing.T) {
	transport := newGatedCancelTransport(5062, 5060)
	nonce := testNonce()
	refreshed := make(chan struct{}, 1)
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch transport.writeCount() {
		case 1:
			transport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
		default:
			if req.Method() == "REGISTER" && req.Header("Expires") != "0" && transport.writeCount() >= 3 {
				select {
				case refreshed <- struct{}{}:
				default:
				}
			}
			transport.queueRead(newIMSResponse(req, 200, "OK"))
		}
	}

	sess, err := imssession.Open(imssession.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(func() registration.Config {
		cfg := testRegistrationConfig(transport)
		cfg.RegisterExpires = 2 * time.Second
		return cfg
	}(), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	client := newReadyClient(t, Config{Terminal: TerminalInfo{ID: testIMEI}})
	defer client.Close()

	runCtx, cancelRun := context.WithCancel(context.Background())
	active := &activeConn{
		runCtx:     runCtx,
		cancel:     cancelRun,
		imsSession: sess,
		reg:        reg,
	}
	client.mu.Lock()
	client.active = active
	client.mu.Unlock()

	done, ok := client.reserveCloseTask()
	if !ok {
		t.Fatal("reserveCloseTask() = false, want true")
	}
	runDone := client.startIMSRunner(active, done)
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	select {
	case <-refreshed:
	case <-time.After(2 * time.Second):
		t.Fatal("waiting for registration refresh")
	}

	cancelRun()
	close(transport.cancelReadRelease)
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("IMS runner did not stop")
	}
}

func TestIMSRunnerReconnectsAfterPrimaryTransportFailure(t *testing.T) {
	oldTransport := newGatedCancelTransport(5062, 5060)
	nonce := testNonce()
	oldTransport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch oldTransport.writeCount() {
		case 1:
			oldTransport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
		case 2:
			oldTransport.queueRead(newIMSResponse(req, 200, "OK"))
		default:
			t.Fatalf("unexpected old transport write after failure: %s", req.StartLine)
		}
	}
	oldSess, oldReg := newRegisteredIMSRuntime(t, oldTransport, time.Minute)

	newTransport := newGatedCancelTransport(5072, 5060)
	newTransport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch newTransport.writeCount() {
		case 1:
			newTransport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
		case 2:
			newTransport.queueRead(newIMSResponse(req, 200, "OK"))
		default:
			newTransport.queueRead(newIMSResponse(req, 200, "OK"))
		}
	}
	newSess, newReg := newRegisteredIMSRuntime(t, newTransport, time.Minute)

	client := newReadyClient(t, Config{Terminal: TerminalInfo{ID: testIMEI}})
	defer client.Close()
	events := client.Events()
	defer events.Close()

	oldRunCtx, oldCancel := context.WithCancel(context.Background())
	oldActive := &activeConn{runCtx: oldRunCtx, cancel: oldCancel, imsSession: oldSess, reg: oldReg}
	newRunCtx, newCancel := context.WithCancel(context.Background())
	newActive := &activeConn{runCtx: newRunCtx, cancel: newCancel, imsSession: newSess, reg: newReg}
	defer newCancel()

	reconnected := make(chan struct{})
	client.reconnectFn = func(error) (*activeConn, error) {
		client.mu.Lock()
		client.active = newActive
		client.mu.Unlock()
		close(reconnected)
		return newActive, nil
	}
	client.mu.Lock()
	client.active = oldActive
	client.mu.Unlock()

	done, ok := client.reserveCloseTask()
	if !ok {
		t.Fatal("reserveCloseTask() = false, want true")
	}
	runDone := client.startIMSRunner(oldActive, done)
	if err := oldSess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("old WaitStarted() error = %v", err)
	}

	readErr := errors.New("primary transport read failed")
	oldTransport.failRead(readErr)

	select {
	case err := <-events.Errors:
		if !strings.Contains(err.Error(), "running IMS loop") || !errors.Is(err, readErr) {
			t.Fatalf("error event = %v, want IMS loop wrapping read failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for IMS loop error event")
	}
	select {
	case state := <-events.State:
		if state != StateFailed {
			t.Fatalf("state event = %s, want %s", state, StateFailed)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for failed state event")
	}
	select {
	case <-reconnected:
	case <-time.After(time.Second):
		t.Fatal("waiting for reconnect")
	}
	if err := newSess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("new WaitStarted() error = %v", err)
	}
	client.mu.Lock()
	active := client.active
	client.mu.Unlock()
	if active != newActive {
		t.Fatal("client active connection was not replaced after reconnect")
	}
	if oldReg.State().Registered {
		t.Fatal("old registration state still registered after runtime abort")
	}

	newCancel()
	close(newTransport.cancelReadRelease)
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("IMS runner did not stop after replacement context cancellation")
	}
}

func TestIMSRunnerPassesRetryAfterToReconnect(t *testing.T) {
	transport := newGatedCancelTransport(5062, 5060)
	nonce := testNonce()
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch transport.writeCount() {
		case 1:
			transport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
		case 2:
			transport.queueRead(newIMSResponse(req, 200, "OK"))
		case 3:
			resp := newIMSResponse(req, 500, "Server Internal Error")
			resp.Headers.Add("Retry-After", "45")
			transport.queueRead(resp)
		default:
			t.Fatalf("unexpected transport write: %s", req.StartLine)
		}
	}
	sess, reg := newRegisteredIMSRuntime(t, transport, 2*time.Second)

	client := newReadyClient(t, Config{
		Terminal:       TerminalInfo{ID: testIMEI},
		ReconnectDelay: 3 * time.Second,
		IMS: IMSConfig{
			RegistrationRetryBase: 20 * time.Second,
			RegistrationRetryMax:  80 * time.Second,
		},
	})
	defer client.Close()
	delayCh := make(chan time.Duration, 1)
	client.reconnectFn = func(cause error) (*activeConn, error) {
		delay := client.reconnectDelay(
			cause,
			newReconnectBackoff(client.cfg.ReconnectDelay, client.cfg.ReconnectMaxDelay),
			newReconnectBackoff(client.cfg.IMS.RegistrationRetryBase, client.cfg.IMS.RegistrationRetryMax),
		)
		delayCh <- delay
		return nil, context.Canceled
	}

	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	active := &activeConn{runCtx: runCtx, cancel: cancelRun, imsSession: sess, reg: reg}
	client.mu.Lock()
	client.active = active
	client.mu.Unlock()

	done, ok := client.reserveCloseTask()
	if !ok {
		t.Fatal("reserveCloseTask() = false, want true")
	}
	runDone := client.startIMSRunner(active, done)
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	select {
	case delay := <-delayCh:
		if delay != 45*time.Second {
			t.Fatalf("reconnect delay = %v, want Retry-After", delay)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waiting for reconnect delay")
	}
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("IMS runner did not stop after reconnect cancellation")
	}
}

func TestCloseCancelsIMSRunnerReconnect(t *testing.T) {
	transport := newGatedCancelTransport(5062, 5060)
	nonce := testNonce()
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch transport.writeCount() {
		case 1:
			transport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
		case 2:
			transport.queueRead(newIMSResponse(req, 200, "OK"))
		default:
			t.Fatalf("unexpected transport write after failure: %s", req.StartLine)
		}
	}
	sess, reg := newRegisteredIMSRuntime(t, transport, time.Minute)

	client := newReadyClient(t, Config{Terminal: TerminalInfo{ID: testIMEI}})
	reconnectStarted := make(chan struct{})
	client.reconnectFn = func(error) (*activeConn, error) {
		close(reconnectStarted)
		<-client.lifecycleCtx.Done()
		return nil, client.lifecycleCtx.Err()
	}

	runCtx, cancelRun := context.WithCancel(context.Background())
	active := &activeConn{runCtx: runCtx, cancel: cancelRun, imsSession: sess, reg: reg}
	client.mu.Lock()
	client.active = active
	client.mu.Unlock()

	done, ok := client.reserveCloseTask()
	if !ok {
		t.Fatal("reserveCloseTask() = false, want true")
	}
	client.startIMSRunner(active, done)
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	transport.failRead(errors.New("primary transport read failed"))
	select {
	case <-reconnectStarted:
	case <-time.After(time.Second):
		t.Fatal("waiting for reconnect to start")
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.CloseContext(closeCtx); err != nil {
		t.Fatalf("CloseContext() error = %v", err)
	}
}

func TestReconnectBackoff(t *testing.T) {
	tests := []struct {
		name  string
		first time.Duration
		max   time.Duration
		steps int
		want  []time.Duration
	}{
		{
			name:  "doubles until capped",
			first: 3 * time.Second,
			max:   20 * time.Second,
			steps: 5,
			want:  []time.Duration{3 * time.Second, 6 * time.Second, 12 * time.Second, 20 * time.Second, 20 * time.Second},
		},
		{
			name:  "zero delay stays immediate",
			first: 0,
			max:   time.Minute,
			steps: 3,
			want:  []time.Duration{0, 0, 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backoff := newReconnectBackoff(tt.first, tt.max)
			got := make([]time.Duration, 0, tt.steps)
			for range tt.steps {
				got = append(got, backoff.Next())
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("backoff sequence = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReconnectDelayHonorsIMSRegistrationRetryPolicy(t *testing.T) {
	transport := newGatedCancelTransport(5062, 5060)
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		resp := newIMSResponse(req, 500, "Server Internal Error")
		resp.Headers.Add("Retry-After", "45")
		transport.queueRead(resp)
	}

	sess, err := imssession.Open(imssession.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(testRegistrationConfig(transport), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	registerErr := reg.Register(context.Background())
	if registerErr == nil {
		t.Fatal("Register() error = nil, want Retry-After registration error")
	}
	if retryAfter, ok := registration.InitialRegistrationRetryAfter(registerErr); !ok || retryAfter != 45*time.Second {
		t.Fatalf("InitialRegistrationRetryAfter() = %v, %v; want 45s, true", retryAfter, ok)
	}

	client := newReadyClient(t, Config{
		Terminal:       TerminalInfo{ID: testIMEI},
		ReconnectDelay: 3 * time.Second,
		IMS: IMSConfig{
			RegistrationRetryBase: 20 * time.Second,
			RegistrationRetryMax:  80 * time.Second,
		},
	})
	defer client.Close()
	got := client.reconnectDelay(
		fmt.Errorf("running IMS loop: %w", registerErr),
		newReconnectBackoff(client.cfg.ReconnectDelay, client.cfg.ReconnectMaxDelay),
		newReconnectBackoff(client.cfg.IMS.RegistrationRetryBase, client.cfg.IMS.RegistrationRetryMax),
	)
	if got != 45*time.Second {
		t.Fatalf("reconnectDelay() = %v, want Retry-After", got)
	}

	registrationErr := fmt.Errorf("running IMS loop: %w", registrationTestInitialRequiredError(t))
	registrationBackoff := newReconnectBackoff(client.cfg.IMS.RegistrationRetryBase, client.cfg.IMS.RegistrationRetryMax)
	got = client.reconnectDelay(
		registrationErr,
		newReconnectBackoff(client.cfg.ReconnectDelay, client.cfg.ReconnectMaxDelay),
		registrationBackoff,
	)
	if got != 20*time.Second {
		t.Fatalf("first registration reconnect delay = %v, want IMS retry base", got)
	}
	got = client.reconnectDelay(
		registrationErr,
		newReconnectBackoff(client.cfg.ReconnectDelay, client.cfg.ReconnectMaxDelay),
		registrationBackoff,
	)
	if got != 40*time.Second {
		t.Fatalf("second registration reconnect delay = %v, want IMS retry backoff", got)
	}

	genericBackoff := newReconnectBackoff(client.cfg.ReconnectDelay, client.cfg.ReconnectMaxDelay)
	got = client.reconnectDelay(
		errors.New("tcp transport closed"),
		genericBackoff,
		newReconnectBackoff(client.cfg.IMS.RegistrationRetryBase, client.cfg.IMS.RegistrationRetryMax),
	)
	if got != 3*time.Second {
		t.Fatalf("generic reconnect delay = %v, want generic base", got)
	}
	got = client.reconnectDelay(
		errors.New("tcp transport closed"),
		genericBackoff,
		newReconnectBackoff(client.cfg.IMS.RegistrationRetryBase, client.cfg.IMS.RegistrationRetryMax),
	)
	if got != 6*time.Second {
		t.Fatalf("second generic reconnect delay = %v, want generic backoff", got)
	}

	tunnelBackoffErr := fmt.Errorf("connecting swu: %w", testTunnelBackoffError{delay: 2 * time.Minute})
	if delay, ok := swutunnel.BackoffDelay(tunnelBackoffErr); !ok || delay != 2*time.Minute {
		t.Fatalf("swutunnel.BackoffDelay() = %v, %v; want 2m, true", delay, ok)
	}
	got = client.reconnectDelay(
		tunnelBackoffErr,
		newReconnectBackoff(client.cfg.ReconnectDelay, client.cfg.ReconnectMaxDelay),
		newReconnectBackoff(client.cfg.IMS.RegistrationRetryBase, client.cfg.IMS.RegistrationRetryMax),
	)
	if got != 2*time.Minute {
		t.Fatalf("tunnel backoff reconnect delay = %v, want ePDG backoff timer", got)
	}

	reactivationErr := fmt.Errorf("running IMS loop: %w", swutunnel.ErrReactivationRequested)
	if !swutunnel.ReactivationRequested(reactivationErr) {
		t.Fatalf("swutunnel.ReactivationRequested() = false for %v", reactivationErr)
	}
	got = client.reconnectDelay(
		reactivationErr,
		newReconnectBackoff(client.cfg.ReconnectDelay, client.cfg.ReconnectMaxDelay),
		newReconnectBackoff(client.cfg.IMS.RegistrationRetryBase, client.cfg.IMS.RegistrationRetryMax),
	)
	if got != 0 {
		t.Fatalf("reactivation reconnect delay = %v, want immediate retry", got)
	}

	pcscfReselectionErr := fmt.Errorf("running IMS loop: %w", swutunnel.ErrPCSCFReselectionRequested)
	if !swutunnel.PCSCFReselectionRequested(pcscfReselectionErr) {
		t.Fatalf("swutunnel.PCSCFReselectionRequested() = false for %v", pcscfReselectionErr)
	}
	got = client.reconnectDelay(
		pcscfReselectionErr,
		newReconnectBackoff(client.cfg.ReconnectDelay, client.cfg.ReconnectMaxDelay),
		newReconnectBackoff(client.cfg.IMS.RegistrationRetryBase, client.cfg.IMS.RegistrationRetryMax),
	)
	if got != 0 {
		t.Fatalf("p-cscf reselection reconnect delay = %v, want immediate retry", got)
	}
}

func TestReconnectDelayHonorsIMSSubscribeRetryAfter(t *testing.T) {
	transport := newGatedCancelTransport(5062, 5060)
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		if req.Method() != "SUBSCRIBE" {
			t.Fatalf("method = %q, want SUBSCRIBE", req.Method())
		}
		resp := newIMSResponse(req, 503, "Service Unavailable")
		resp.Headers.Add("Retry-After", "75")
		transport.queueRead(resp)
	}

	sess, err := imssession.Open(imssession.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(testRegistrationConfig(transport), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	subscribeErr := reg.Subscribe(context.Background())
	if subscribeErr == nil {
		t.Fatal("Subscribe() error = nil, want Retry-After subscription error")
	}
	if retryAfter, ok := registration.RetryAfterDelay(subscribeErr); !ok || retryAfter != 75*time.Second {
		t.Fatalf("RetryAfterDelay() = %v, %v; want 75s, true", retryAfter, ok)
	}

	client := newReadyClient(t, Config{
		Terminal:       TerminalInfo{ID: testIMEI},
		ReconnectDelay: 3 * time.Second,
		IMS: IMSConfig{
			RegistrationRetryBase: 20 * time.Second,
			RegistrationRetryMax:  80 * time.Second,
		},
	})
	defer client.Close()
	got := client.reconnectDelay(
		fmt.Errorf("starting IMS runtime: %w", subscribeErr),
		newReconnectBackoff(client.cfg.ReconnectDelay, client.cfg.ReconnectMaxDelay),
		newReconnectBackoff(client.cfg.IMS.RegistrationRetryBase, client.cfg.IMS.RegistrationRetryMax),
	)
	if got != 75*time.Second {
		t.Fatalf("reconnectDelay() = %v, want Subscribe Retry-After", got)
	}
}

func TestReconnectStopsOnAccessRejectedCause(t *testing.T) {
	client := newReadyClient(t, Config{
		Terminal:       TerminalInfo{ID: testIMEI},
		ReconnectDelay: time.Hour,
	})
	defer client.Close()

	cause := fmt.Errorf("connecting swu: %w", swutunnel.ErrAccessRejected)
	done := make(chan error, 1)
	go func() {
		_, err := client.reconnect(cause)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, swutunnel.ErrAccessRejected) {
			t.Fatalf("reconnect() error = %v, want access rejected", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("reconnect() slept or retried after access rejection")
	}
}

func TestSWUBackoffGateScopesPolicy(t *testing.T) {
	now := time.Unix(100, 0)
	tests := []struct {
		name      string
		recordErr error
		cfg       Config
		card      Card
		wantDelay time.Duration
		wantBlock bool
	}{
		{
			name:      "network failure blocks same epdg",
			recordErr: testTunnelBackoffError{delay: 2 * time.Minute, scope: swutunnel.BackoffScopeEPDG},
			cfg:       Config{EPDG: "epdg.example"},
			card:      stubCard{},
			wantDelay: 2 * time.Minute,
		},
		{
			name:      "network failure does not block different epdg",
			recordErr: testTunnelBackoffError{delay: 2 * time.Minute, scope: swutunnel.BackoffScopeEPDG},
			cfg:       Config{EPDG: "other.example"},
			card:      stubCard{},
		},
		{
			name:      "no apn subscription blocks same plmn apn across epdgs",
			recordErr: testTunnelBackoffError{delay: 3 * time.Minute, scope: swutunnel.BackoffScopePLMNAPN},
			cfg:       Config{EPDG: "other.example"},
			card:      stubCard{},
			wantDelay: 3 * time.Minute,
		},
		{
			name:      "no apn subscription does not block different plmn",
			recordErr: testTunnelBackoffError{delay: 3 * time.Minute, scope: swutunnel.BackoffScopePLMNAPN},
			cfg:       Config{EPDG: "epdg.example"},
			card:      plmnTestCard{mcc: "002", mnc: "001"},
		},
		{
			name:      "no apn subscription does not block different apn",
			recordErr: testTunnelBackoffError{delay: 3 * time.Minute, scope: swutunnel.BackoffScopePLMNAPN},
			cfg:       Config{EPDG: "other.example", Tunnel: swutunnel.Config{APN: "internet"}},
			card:      stubCard{},
		},
		{
			name:      "deactivated blocks terminally",
			recordErr: testTunnelBackoffError{deactivated: true, scope: swutunnel.BackoffScopeEPDG},
			cfg:       Config{EPDG: "epdg.example"},
			card:      stubCard{},
			wantBlock: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newReadyClient(t, Config{
				EPDG:     "epdg.example",
				Terminal: TerminalInfo{ID: testIMEI},
			})
			defer client.Close()
			client.recordSWUBackoff(tt.recordErr, now)
			client.cfg.EPDG = tt.cfg.EPDG
			client.cfg.Tunnel.APN = tt.cfg.Tunnel.APN
			client.card = tt.card

			gotDelay, gotBlock, gotActive := client.swuBackoffDelay(now)
			if gotActive != (tt.wantDelay > 0 || tt.wantBlock) {
				t.Fatalf("swuBackoffDelay() active = %t, want %t", gotActive, tt.wantDelay > 0 || tt.wantBlock)
			}
			if gotBlock != tt.wantBlock {
				t.Fatalf("swuBackoffDelay() deactivated = %t, want %t", gotBlock, tt.wantBlock)
			}
			if gotDelay != tt.wantDelay {
				t.Fatalf("swuBackoffDelay() delay = %v, want %v", gotDelay, tt.wantDelay)
			}
		})
	}
}

func TestSWUBackoffGateRecordsImplementationSpecificPolicy(t *testing.T) {
	now := time.Unix(100, 0)
	tests := []struct {
		name      string
		err       error
		cfg       Config
		card      Card
		wantDelay time.Duration
	}{
		{
			name:      "network failure without timer blocks same epdg",
			err:       fmt.Errorf("connecting swu: %w", swutunnel.ErrNetworkFailure),
			cfg:       Config{EPDG: "epdg.example"},
			card:      stubCard{},
			wantDelay: 5 * time.Second,
		},
		{
			name: "network failure without timer does not block different epdg",
			err:  fmt.Errorf("connecting swu: %w", swutunnel.ErrNetworkFailure),
			cfg:  Config{EPDG: "other.example"},
			card: stubCard{},
		},
		{
			name:      "no apn subscription without timer blocks same plmn apn",
			err:       fmt.Errorf("connecting swu: %w", swutunnel.ErrNoAPNSubscription),
			cfg:       Config{EPDG: "other.example"},
			card:      stubCard{},
			wantDelay: 5 * time.Second,
		},
		{
			name: "no apn subscription without timer does not block different apn",
			err:  fmt.Errorf("connecting swu: %w", swutunnel.ErrNoAPNSubscription),
			cfg: Config{
				EPDG:   "other.example",
				Tunnel: swutunnel.Config{APN: "internet"},
			},
			card: stubCard{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newReadyClient(t, Config{
				EPDG:           "epdg.example",
				ReconnectDelay: 5 * time.Second,
				Terminal:       TerminalInfo{ID: testIMEI},
			})
			defer client.Close()
			client.recordSWUBackoff(tt.err, now)
			client.cfg.EPDG = tt.cfg.EPDG
			client.cfg.Tunnel.APN = tt.cfg.Tunnel.APN
			client.card = tt.card

			gotDelay, gotBlock, gotActive := client.swuBackoffDelay(now)
			if gotActive != (tt.wantDelay > 0) {
				t.Fatalf("swuBackoffDelay() active = %t, want %t", gotActive, tt.wantDelay > 0)
			}
			if gotBlock {
				t.Fatal("swuBackoffDelay() deactivated = true, want false")
			}
			if gotDelay != tt.wantDelay {
				t.Fatalf("swuBackoffDelay() delay = %v, want %v", gotDelay, tt.wantDelay)
			}
		})
	}
}

func TestSWUBackoffGateClearsExplicitZeroPolicy(t *testing.T) {
	client := newReadyClient(t, Config{
		EPDG:           "epdg.example",
		ReconnectDelay: 5 * time.Second,
		Terminal:       TerminalInfo{ID: testIMEI},
	})
	defer client.Close()

	now := time.Unix(100, 0)
	client.recordSWUBackoff(testTunnelBackoffError{delay: time.Minute, scope: swutunnel.BackoffScopeEPDG}, now)
	if delay, deactivated, active := client.swuBackoffDelay(now); !active || deactivated || delay != time.Minute {
		t.Fatalf("swuBackoffDelay(before zero) = %v, %t, %t; want 1m, false, true", delay, deactivated, active)
	}

	client.recordSWUBackoff(testTunnelBackoffError{scope: swutunnel.BackoffScopeEPDG}, now)
	if delay, deactivated, active := client.swuBackoffDelay(now); active || deactivated || delay != 0 {
		t.Fatalf("swuBackoffDelay(after zero) = %v, %t, %t; want inactive", delay, deactivated, active)
	}
}

func TestSWUBackoffGateExpiresAndClears(t *testing.T) {
	client := newReadyClient(t, Config{
		EPDG:     "epdg.example",
		Terminal: TerminalInfo{ID: testIMEI},
	})
	defer client.Close()

	now := time.Unix(100, 0)
	client.recordSWUBackoff(testTunnelBackoffError{delay: time.Minute, scope: swutunnel.BackoffScopeEPDG}, now)

	if delay, deactivated, active := client.swuBackoffDelay(now.Add(30 * time.Second)); !active || deactivated || delay != 30*time.Second {
		t.Fatalf("swuBackoffDelay(before expiry) = %v, %t, %t; want 30s, false, true", delay, deactivated, active)
	}
	if delay, deactivated, active := client.swuBackoffDelay(now.Add(time.Minute)); active || deactivated || delay != 0 {
		t.Fatalf("swuBackoffDelay(after expiry) = %v, %t, %t; want inactive", delay, deactivated, active)
	}

	client.recordSWUBackoff(testTunnelBackoffError{delay: time.Minute, scope: swutunnel.BackoffScopeEPDG}, now)
	client.clearCurrentSWUBackoff()
	if delay, deactivated, active := client.swuBackoffDelay(now); active || deactivated || delay != 0 {
		t.Fatalf("swuBackoffDelay(after clear) = %v, %t, %t; want inactive", delay, deactivated, active)
	}
}

func TestTerminalReconnectError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "access rejected", err: fmt.Errorf("connecting swu: %w", swutunnel.ErrAccessRejected), want: true},
		{name: "backoff deactivated", err: fmt.Errorf("connecting swu: %w", testTunnelBackoffDeactivatedError{}), want: true},
		{name: "swu backoff deactivated", err: fmt.Errorf("preparing connect: %w", errSWUBackoffDeactivated), want: true},
		{name: "transport closed", err: errors.New("tcp transport closed")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := terminalReconnectError(tt.err); got != tt.want {
				t.Fatalf("terminalReconnectError() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestPCSCFCandidateIPs(t *testing.T) {
	tests := []struct {
		name string
		info swutunnel.Info
		want []net.IP
	}{
		{
			name: "ordered list deduplicated",
			info: swutunnel.Info{
				PCSCFIP: net.IPv4(10, 0, 0, 1),
				PCSCFIPs: []net.IP{
					net.IPv4(10, 0, 0, 1),
					net.IPv4(10, 0, 0, 2),
					net.IPv4(10, 0, 0, 1),
				},
			},
			want: []net.IP{net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)},
		},
		{
			name: "legacy preferred address fallback",
			info: swutunnel.Info{PCSCFIP: net.IPv4(10, 0, 0, 9)},
			want: []net.IP{net.IPv4(10, 0, 0, 9)},
		},
		{
			name: "empty",
			info: swutunnel.Info{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pcscfCandidateIPs(tt.info)
			if len(got) != len(tt.want) {
				t.Fatalf("candidate count = %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if !got[i].Equal(tt.want[i]) {
					t.Fatalf("candidate[%d] = %s, want %s", i, got[i], tt.want[i])
				}
			}
			if len(got) != 0 && &got[0][0] == &tt.want[0][0] {
				t.Fatal("candidate IP aliases input")
			}
		})
	}
}

func registrationTestInitialRequiredError(t *testing.T) error {
	t.Helper()

	transport := newGatedCancelTransport(5062, 5060)
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		transport.queueRead(newIMSResponse(req, 500, "Server Internal Error"))
	}

	sess, err := imssession.Open(imssession.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(testRegistrationConfig(transport), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	err = reg.Register(context.Background())
	if err == nil {
		t.Fatal("Register() error = nil, want initial registration required")
	}
	if !registration.InitialRegistrationRequired(err) {
		t.Fatalf("InitialRegistrationRequired() = false for %v", err)
	}
	return err
}

func TestRunActiveIMSKeepsParentContextOnRegistrationRefreshError(t *testing.T) {
	transport := newGatedCancelTransport(5062, 5060)
	nonce := testNonce()
	released := make(chan struct{})
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch transport.writeCount() {
		case 1:
			transport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
		case 2:
			transport.queueRead(newIMSResponse(req, 200, "OK"))
		default:
			transport.queueRead(newIMSResponse(req, 500, "Server Internal Error"))
			select {
			case <-released:
			default:
				close(released)
				close(transport.cancelReadRelease)
			}
		}
	}

	sess, err := imssession.Open(imssession.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(func() registration.Config {
		cfg := testRegistrationConfig(transport)
		cfg.RegisterExpires = 2 * time.Second
		return cfg
	}(), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	active := &activeConn{
		runCtx:     runCtx,
		cancel:     cancelRun,
		imsSession: sess,
		reg:        reg,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- runActiveIMS(active)
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("runActiveIMS() error = nil, want refresh error")
		}
		if !strings.Contains(err.Error(), "maintaining IMS registration") {
			t.Fatalf("runActiveIMS() error = %v, want maintaining IMS registration", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waiting for runActiveIMS refresh error")
	}
	if runCtx.Err() != nil {
		t.Fatalf("runCtx.Err() = %v, want nil", runCtx.Err())
	}
}

func TestRunActiveIMSReturnsRegistrationEventTermination(t *testing.T) {
	transport := newGatedCancelTransport(5062, 5060)
	nonce := testNonce()
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		if !req.IsRequest() || req.Method() != "REGISTER" {
			return
		}
		switch transport.writeCount() {
		case 1:
			transport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
		case 2:
			transport.queueRead(newIMSResponse(req, 200, "OK"))
		}
	}

	sess, err := imssession.Open(imssession.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(testRegistrationConfig(transport), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	active := &activeConn{
		runCtx:     runCtx,
		cancel:     cancelRun,
		imsSession: sess,
		reg:        reg,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- runActiveIMS(active)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	state := reg.State()
	contactURI := "sip:" + net.JoinHostPort(state.ContactHost, strconv.Itoa(state.MessagePort))
	notify := imssip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Event", "reg")
	notify.Headers.Add("Content-Type", "application/reginfo+xml")
	notify.Body = []byte(fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="%s" id="reg-1" state="terminated">
    <contact id="contact-1" state="terminated" event="deactivated">
      <uri>%s</uri>
    </contact>
  </registration>
</reginfo>`, state.PublicIdentity, contactURI))
	transport.queueRead(notify)

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("runActiveIMS() error = nil, want registration event termination")
		}
		if !strings.Contains(err.Error(), "ims registration terminated by network") {
			t.Fatalf("runActiveIMS() error = %v, want network deregistration", err)
		}
	case <-time.After(time.Second):
		cancelRun()
		close(transport.cancelReadRelease)
		t.Fatal("waiting for runActiveIMS registration event termination")
	}
	if runCtx.Err() != nil {
		t.Fatalf("runCtx.Err() = %v, want nil", runCtx.Err())
	}
	if reg.State().Registered {
		t.Fatal("Registered = true, want false")
	}
}

func newReaderStubForUSIMLoad() *readerStub {
	const (
		fileStructureTransparent byte = 0x01
		fileStructureLinearFixed byte = 0x02
	)

	usimAID := []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}

	return &readerStub{
		listApplications: func(context.Context) ([]usimreader.Application, error) {
			return []usimreader.Application{{
				AID:   append([]byte(nil), usimAID...),
				Label: "USIM",
			}}, nil
		},
		getFileAttributes: func(_ context.Context, file usimreader.FileRef) (usimreader.FileAttributes, error) {
			switch {
			case len(file.AID) == 0 && slices.Equal(file.Path, []byte{0x2F, 0xE2}):
				return usimreader.FileAttributes{FileStructure: fileStructureTransparent, FileSize: 10}, nil
			case slices.Equal(file.AID, usimAID) && slices.Equal(file.Path, []byte{0x6F, 0x07}):
				return usimreader.FileAttributes{FileStructure: fileStructureTransparent, FileSize: 9}, nil
			case slices.Equal(file.AID, usimAID) && slices.Equal(file.Path, []byte{0x6F, 0xAD}):
				return usimreader.FileAttributes{FileStructure: fileStructureTransparent, FileSize: 4}, nil
			case slices.Equal(file.AID, usimAID) && slices.Equal(file.Path, []byte{0x6F, 0x42}):
				return usimreader.FileAttributes{FileStructure: fileStructureLinearFixed, RecordSize: 32, RecordCount: 0}, nil
			default:
				return usimreader.FileAttributes{}, errors.New("file not found")
			}
		},
		readTransparent: func(_ context.Context, req usimreader.TransparentRead) ([]byte, error) {
			switch {
			case len(req.File.AID) == 0 && slices.Equal(req.File.Path, []byte{0x2F, 0xE2}):
				return []byte{0x98, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0}, nil
			case slices.Equal(req.File.AID, usimAID) && slices.Equal(req.File.Path, []byte{0x6F, 0x07}):
				return []byte{0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98}, nil
			case slices.Equal(req.File.AID, usimAID) && slices.Equal(req.File.Path, []byte{0x6F, 0xAD}):
				return []byte{0x00, 0x00, 0x00, 0x02}, nil
			default:
				return nil, errors.New("transparent file not found")
			}
		},
	}
}
