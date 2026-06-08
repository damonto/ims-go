package sms

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net"
	"net/textproto"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/damonto/uicc-go/usim"
	usimcard "github.com/damonto/uicc-go/usim/card"
	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
)

type serviceStubTransport struct {
	local   net.Addr
	remote  net.Addr
	readCh  chan []byte
	writes  [][]byte
	onWrite func([]byte)
}

type serviceStubCard struct{}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type serviceCenterStubCard struct {
	serviceStubCard
	center usim.ServiceCenter
}
type smsppDownloadStubCard struct {
	serviceStubCard
	req  usimcard.SMSPPDownloadRequest
	resp usimcard.SMSPPDownloadResponse
}

func TestNormalizeConfigSubmitReportTimeout(t *testing.T) {
	tests := []struct {
		name               string
		cfg                Config
		wantSubmitReport   time.Duration
		wantDeliveryReport time.Duration
		wantErr            bool
	}{
		{
			name:               "ims rp timer defaults",
			wantSubmitReport:   40 * time.Second,
			wantDeliveryReport: 15 * time.Second,
		},
		{
			name:               "explicit timeouts",
			cfg:                Config{SubmitReportTimeout: 45 * time.Second, DeliveryReportTimeout: 17 * time.Second},
			wantSubmitReport:   45 * time.Second,
			wantDeliveryReport: 17 * time.Second,
		},
		{
			name:    "negative submit report timeout",
			cfg:     Config{SubmitReportTimeout: -time.Second},
			wantErr: true,
		},
		{
			name:    "negative delivery report timeout",
			cfg:     Config{DeliveryReportTimeout: -time.Second},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := normalizeConfig(tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("normalizeConfig() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeConfig() error = %v", err)
			}
			if cfg.SubmitReportTimeout != tt.wantSubmitReport {
				t.Fatalf("SubmitReportTimeout = %v, want %v", cfg.SubmitReportTimeout, tt.wantSubmitReport)
			}
			if cfg.DeliveryReportTimeout != tt.wantDeliveryReport {
				t.Fatalf("DeliveryReportTimeout = %v, want %v", cfg.DeliveryReportTimeout, tt.wantDeliveryReport)
			}
		})
	}
}

func (t *serviceStubTransport) LocalAddr() net.Addr  { return t.local }
func (t *serviceStubTransport) RemoteAddr() net.Addr { return t.remote }
func (t *serviceStubTransport) WritePacket(ctx context.Context, data []byte) error {
	t.writes = append(t.writes, append([]byte(nil), data...))
	if t.onWrite != nil {
		t.onWrite(data)
	}
	return nil
}
func (t *serviceStubTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case pkt := <-t.readCh:
		return pkt, t.remote, nil
	}
}
func (t *serviceStubTransport) Close() error { return nil }
func (t *serviceStubTransport) queue(msg sip.Message) {
	t.readCh <- marshalSIPMessageForTest(msg)
}

func marshalSIPMessageForTest(msg sip.Message) []byte {
	data, err := msg.MarshalText()
	if err != nil {
		panic(err)
	}
	return data
}

func (serviceStubCard) IMSI() string { return "001010123456789" }
func (serviceStubCard) MCC() string  { return "001" }
func (serviceStubCard) MNC() string  { return "001" }
func (serviceStubCard) SMSC() string { return "+15550000000" }
func (serviceStubCard) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	return usim.AKAResult{
		RES: []byte("password"),
		CK:  []byte("client-test-ck"),
		IK:  []byte("client-test-ik"),
	}, nil
}

func (c serviceCenterStubCard) SMSC() string {
	return c.center.Address
}

func (c serviceCenterStubCard) ServiceCenter() usim.ServiceCenter {
	return c.center
}

func (c *smsppDownloadStubCard) SMSPPDownload(ctx context.Context, req usimcard.SMSPPDownloadRequest) (usimcard.SMSPPDownloadResponse, error) {
	c.req = usimcard.SMSPPDownloadRequest{
		ServiceCenterAddress: req.ServiceCenterAddress,
		TPDU:                 append([]byte(nil), req.TPDU...),
	}
	return usimcard.SMSPPDownloadResponse{
		SW1:  c.resp.SW1,
		SW2:  c.resp.SW2,
		Data: append([]byte(nil), c.resp.Data...),
	}, nil
}

func TestSendBuildsMESSAGEFromRegistrationState(t *testing.T) {
	const wantSecurityVerify = "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=1111;spi-s=2222"

	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{Logger: testLogger()}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "MESSAGE" {
			return
		}
		if got := req.HeadersByName("Route"); len(got) != 2 || got[0] != "<sip:127.0.0.1:4060;lr>" || got[1] != "<sip:pcscf.example.com;lr>" {
			t.Fatalf("Route = %v", got)
		}
		if got := req.Header("P-Preferred-Identity"); got != "<tel:+15551234567>" {
			t.Fatalf("P-Preferred-Identity = %q", got)
		}
		if got := req.Header("Accept-Contact"); got != acceptContact {
			t.Fatalf("Accept-Contact = %q, want %q", got, acceptContact)
		}
		if got := req.Header("User-Agent"); got == "" {
			t.Fatal("User-Agent = empty")
		}
		if got := req.Header("P-Access-Network-Info"); got == "" {
			t.Fatal("P-Access-Network-Info = empty")
		}
		if got := req.Header("Security-Verify"); got != wantSecurityVerify {
			t.Fatalf("Security-Verify = %q, want %q", got, wantSecurityVerify)
		}
		if got := req.Header("Require"); got != "sec-agree" {
			t.Fatalf("Require = %q, want sec-agree", got)
		}
		if got := req.Header("Proxy-Require"); got != "sec-agree" {
			t.Fatalf("Proxy-Require = %q, want sec-agree", got)
		}
		transport.queue(newResponse(req, 202, "Accepted"))
		ackMOSubmit(t, svc, req)
	}

	got, err := svc.Send(context.Background(), "777", "BAL")
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if len(got.Segments) != 1 {
		t.Fatalf("len(Send().Segments) = %d, want 1", len(got.Segments))
	}
	if got.Segments[0].CallID == "" {
		t.Fatal("Send().Segments[0].CallID = empty")
	}
}

func TestSendUsesIndependentRPAndTPReferences(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{Logger: testLogger()}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	svc.tpRef = 41

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "MESSAGE" {
			return
		}
		var rp rpMessage
		if err := rp.UnmarshalBinary(req.Body); err != nil {
			t.Fatalf("RP unmarshal error = %v", err)
		}
		if len(rp.TPDU) < 2 {
			t.Fatalf("len(TPDU) = %d, want >= 2", len(rp.TPDU))
		}
		tpRef := rp.TPDU[1]
		if rp.Reference == tpRef {
			t.Fatalf("RP reference = TP-MR = %d, want independent references", rp.Reference)
		}
		transport.queue(newResponse(req, 202, "Accepted"))
		ackMOSubmit(t, svc, req)
	}

	submission, err := svc.Send(context.Background(), "777", "BAL")
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if len(submission.Segments) != 1 {
		t.Fatalf("len(submission.Segments) = %d, want 1", len(submission.Segments))
	}
	if submission.Segments[0].RPReference == submission.Segments[0].TPReference {
		t.Fatalf("Submission references both = %d, want independent references", submission.Segments[0].RPReference)
	}
}

func TestSendUsesServiceCenterPSIForSIPTargetAndAddressForRP(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	card := serviceCenterStubCard{center: usim.ServiceCenter{
		Address: "+15550000000",
		PSI:     "sip:smsc@example.com",
	}}
	svc, err := New(Config{Logger: testLogger()}, sess, reg, card)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "MESSAGE" {
			return
		}
		if got := sip.RequestURI(req); got != "sip:smsc@example.com" {
			t.Fatalf("Request-URI = %q, want sip:smsc@example.com", got)
		}
		var rp rpMessage
		if err := rp.UnmarshalBinary(req.Body); err != nil {
			t.Fatalf("RP unmarshal error = %v", err)
		}
		if rp.Destination != "+15550000000" {
			t.Fatalf("RP Destination = %q, want +15550000000", rp.Destination)
		}
		transport.queue(newResponse(req, 202, "Accepted"))
		ackMOSubmit(t, svc, req)
	}

	if _, err := svc.Send(context.Background(), "777", "BAL"); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}

func TestSendRequestsStatusReportWhenConfigured(t *testing.T) {
	tests := []struct {
		name           string
		cfg            Config
		wantFirstOctet byte
	}{
		{
			name:           "disabled by default",
			wantFirstOctet: tpduMTISubmit,
		},
		{
			name:           "enabled",
			cfg:            Config{RequestStatusReport: true},
			wantFirstOctet: tpduMTISubmit | tpduStatusReportRequestFlag,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newServiceTransport()
			sess, reg := registeredService(t, transport)
			tt.cfg.Logger = testLogger()
			svc, err := New(tt.cfg, sess, reg, serviceStubCard{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				if req.Method() != "MESSAGE" {
					return
				}
				var rp rpMessage
				if err := rp.UnmarshalBinary(req.Body); err != nil {
					t.Fatalf("RP unmarshal error = %v", err)
				}
				if len(rp.TPDU) == 0 {
					t.Fatal("RP TPDU = empty")
				}
				if got := rp.TPDU[0]; got != tt.wantFirstOctet {
					t.Fatalf("SMS-SUBMIT first octet = 0x%02X, want 0x%02X", got, tt.wantFirstOctet)
				}
				transport.queue(newResponse(req, 202, "Accepted"))
				ackMOSubmit(t, svc, req)
			}

			if _, err := svc.Send(context.Background(), "777", "BAL"); err != nil {
				t.Fatalf("Send() error = %v", err)
			}
		})
	}
}

func TestNotifyMemoryAvailableSendsRPSMMA(t *testing.T) {
	tests := []struct {
		name        string
		reportType  byte
		reportCause byte
		wantErr     string
	}{
		{name: "rp-ack", reportType: rpAckNetworkToMS},
		{name: "rp-error", reportType: rpErrorNetworkToMS, reportCause: rpCauseMemoryCapacityExceeded, wantErr: "memory capacity exceeded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newServiceTransport()
			sess, reg := registeredService(t, transport)
			svc, err := New(Config{Logger: testLogger(), SubmitReportTimeout: time.Second}, sess, reg, serviceStubCard{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				if req.Method() != "MESSAGE" {
					return
				}
				if got := sip.RequestURI(req); got != "sip:ipsmgw.example.net" {
					t.Fatalf("Request-URI = %q, want sip:ipsmgw.example.net", got)
				}
				var rp rpMessage
				if err := rp.UnmarshalBinary(req.Body); err != nil {
					t.Fatalf("RP unmarshal error = %v", err)
				}
				if rp.Type != rpSMMAMSToNetwork {
					t.Fatalf("RP type = 0x%02X, want RP-SMMA", rp.Type)
				}
				transport.queue(newResponse(req, 202, "Accepted"))

				report := rpMessage{Type: tt.reportType, Reference: rp.Reference, Cause: tt.reportCause, HasCause: tt.reportType == rpErrorNetworkToMS}
				reportBody, err := report.MarshalBinary()
				if err != nil {
					t.Fatalf("report MarshalBinary() error = %v", err)
				}
				go func() {
					msg := newInboundRequest("smma-report", "2 MESSAGE", reportBody)
					msg.Headers.Add("In-Reply-To", req.Header("Call-ID"))
					if _, err := svc.HandleRequest(context.Background(), session.Request{Message: msg, Transport: transport}); err != nil {
						t.Errorf("HandleRequest(report) error = %v", err)
					}
				}()
			}

			err = svc.NotifyMemoryAvailable(context.Background(), "sip:ipsmgw.example.net")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("NotifyMemoryAvailable() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("NotifyMemoryAvailable() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestSendSIPURIUsesMSISDNLessMultipart(t *testing.T) {
	tests := []struct {
		name string
		to   string
	}{
		{name: "sip uri", to: "sip:bob@example.net"},
		{name: "sips uri", to: "sips:bob@example.net"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newServiceTransport()
			sess, reg := registeredService(t, transport)
			svc, err := New(Config{Logger: testLogger()}, sess, reg, serviceStubCard{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				if req.Method() != "MESSAGE" {
					return
				}
				if got := req.Header("Content-Transfer-Encoding"); got != "" {
					t.Fatalf("Content-Transfer-Encoding = %q, want empty for multipart", got)
				}
				info, rpdu := multipartSMSReport(t, req)
				if info.To != tt.to {
					t.Fatalf("SMS XML To = %q, want %q", info.To, tt.to)
				}
				var rp rpMessage
				if err := rp.UnmarshalBinary(rpdu); err != nil {
					t.Fatalf("RP unmarshal error = %v", err)
				}
				if rp.Destination != "+15550000000" {
					t.Fatalf("RP Destination = %q, want +15550000000", rp.Destination)
				}
				gotTPDA, _, err := decodeTPAddress(rp.TPDU[2:])
				if err != nil {
					t.Fatalf("decode TP-DA error = %v", err)
				}
				if gotTPDA != dummyMSISDN {
					t.Fatalf("TP-DA = %q, want %q", gotTPDA, dummyMSISDN)
				}
				transport.queue(newResponse(req, 202, "Accepted"))
				ackMOSubmit(t, svc, req)
			}

			if _, err := svc.Send(context.Background(), tt.to, "BAL"); err != nil {
				t.Fatalf("Send() error = %v", err)
			}
		})
	}
}

func TestSendPrefersDefaultPublicIdentityWhenNoTelURI(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredServiceWithAssociatedURIs(t, transport, "<sip:alice@example.com>", "<sip:alias@example.com>")
	svc, err := New(Config{Logger: testLogger()}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "MESSAGE" {
			return
		}
		if got := req.Header("P-Preferred-Identity"); got != "<sip:alice@example.com>" {
			t.Fatalf("P-Preferred-Identity = %q, want <sip:alice@example.com>", got)
		}
		if got := req.Header("From"); !strings.Contains(got, "<sip:alice@example.com>;") {
			t.Fatalf("From = %q, want default public identity", got)
		}
		transport.queue(newResponse(req, 202, "Accepted"))
		ackMOSubmit(t, svc, req)
	}

	if _, err := svc.Send(context.Background(), "777", "BAL"); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}

func TestHandleMalformedInboundSMSReturns200(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{Logger: testLogger()}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	inboundTransport := newServiceTransport()
	req := session.Request{Message: newInboundRequest("call-1", "1 MESSAGE", []byte{0x03}), Transport: inboundTransport}
	handled, err := svc.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	if len(inboundTransport.writes) != 1 {
		t.Fatalf("len(writes) = %d, want 1", len(inboundTransport.writes))
	}
	resp := mustParseMessage(t, inboundTransport.writes[0])
	if got := resp.StatusCode(); got != 200 {
		t.Fatalf("StatusCode() = %d, want 200", got)
	}
}

func TestHandleInboundSMSCallsOnIncoming(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	gotCh := make(chan Incoming, 1)
	svc, err := New(Config{Logger: testLogger(), OnIncoming: func(in Incoming) { gotCh <- in }}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ackReports(t, transport)

	inboundTransport := newServiceTransport()
	tpdu, err := buildDeliver("+15551234567", "hello")
	if err != nil {
		t.Fatalf("buildDeliver() error = %v", err)
	}
	rpdu, err := (rpMessage{
		Type:       rpDataNetworkToMS,
		Reference:  0x01,
		Originator: "+15550000000",
		TPDU:       tpdu,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	msg := newInboundRequest("call-1", "1 MESSAGE", rpdu)
	msg.Headers.Set("To", "<sip:+19293101226@one.att.net>")
	req := session.Request{Message: msg, Transport: inboundTransport}
	handled, err := svc.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	select {
	case got := <-gotCh:
		if got.Text != "hello" || got.From != "+15551234567" || got.ServiceCenter != "+15550000000" {
			t.Fatalf("Incoming = %+v", got)
		}
		if got.To != "+19293101226" || got.ToURI != "sip:+19293101226@one.att.net" {
			t.Fatalf("Incoming recipient = %q/%q, want +19293101226/sip:+19293101226@one.att.net", got.To, got.ToURI)
		}
		if !bytes.Equal(got.RawTPDU, tpdu) {
			t.Fatalf("Incoming.RawTPDU = % X, want original % X", got.RawTPDU, tpdu)
		}
		if got.ReservedMTI {
			t.Fatal("Incoming.ReservedMTI = true, want false")
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for incoming sms callback")
	}
}

func TestHandleInboundReservedMTISMSPreservesRawTPDU(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	gotCh := make(chan Incoming, 1)
	svc, err := New(Config{Logger: testLogger(), OnIncoming: func(in Incoming) { gotCh <- in }}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ackReports(t, transport)

	inboundTransport := newServiceTransport()
	tpdu, err := buildDeliver("+15551234567", "hello")
	if err != nil {
		t.Fatalf("buildDeliver() error = %v", err)
	}
	tpdu[0] = tpdu[0]&^tpduMTIMask | tpduMTIReserved
	rpdu, err := (rpMessage{
		Type:       rpDataNetworkToMS,
		Reference:  0x01,
		Originator: "+15550000000",
		TPDU:       tpdu,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: newInboundRequest("call-1", "1 MESSAGE", rpdu), Transport: inboundTransport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	select {
	case got := <-gotCh:
		if got.Text != "hello" || got.From != "+15551234567" {
			t.Fatalf("Incoming = %+v, want decoded reserved-MTI deliver", got)
		}
		if !got.ReservedMTI {
			t.Fatal("Incoming.ReservedMTI = false, want true")
		}
		if !bytes.Equal(got.RawTPDU, tpdu) {
			t.Fatalf("Incoming.RawTPDU = % X, want original % X", got.RawTPDU, tpdu)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for incoming sms callback")
	}
}

func TestHandleInboundMSISDNLessSMSUsesXMLFromAndReportsMultipart(t *testing.T) {
	tests := []struct {
		name        string
		xmlFrom     string
		tpFrom      string
		wantFrom    string
		wantFromURI string
	}{
		{
			name:        "sip phone uri is split from display number",
			xmlFrom:     "sip:+64210647889@ims.mnc001.mcc530.3gppnetwork.org",
			tpFrom:      dummyMSISDN,
			wantFrom:    "+64210647889",
			wantFromURI: "sip:+64210647889@ims.mnc001.mcc530.3gppnetwork.org",
		},
		{
			name:        "non dialable sip uri stays in FromURI",
			xmlFrom:     "sip:sender@example.net",
			tpFrom:      dummyMSISDN,
			wantFromURI: "sip:sender@example.net",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newServiceTransport()
			sess, reg := registeredService(t, transport)
			gotCh := make(chan Incoming, 1)
			reportCh := make(chan sip.Message, 1)
			svc, err := New(Config{Logger: testLogger(), OnIncoming: func(in Incoming) { gotCh <- in }}, sess, reg, serviceStubCard{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				if req.Method() != "MESSAGE" {
					return
				}
				reportCh <- req
				transport.queue(newResponse(req, 202, "Accepted"))
			}

			tpdu, err := buildDeliver(tt.tpFrom, "hello")
			if err != nil {
				t.Fatalf("buildDeliver() error = %v", err)
			}
			rpdu, err := (rpMessage{
				Type:       rpDataNetworkToMS,
				Reference:  0x34,
				Originator: "+15550000000",
				TPDU:       tpdu,
			}).MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			body, contentType := multipartSMSBody(t, `<short-message-info><From>`+tt.xmlFrom+`</From></short-message-info>`, rpdu)

			inboundTransport := newServiceTransport()
			msg := newInboundRequest("call-1", "1 MESSAGE", body)
			msg.Headers.Set("Content-Type", contentType)
			msg.Headers.Add("Feature-Caps", "*;+g.3gpp.smsip-msisdn-less")
			req := session.Request{Message: msg, Transport: inboundTransport}
			handled, err := svc.HandleRequest(context.Background(), req)
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			select {
			case got := <-gotCh:
				if got.From != tt.wantFrom || got.FromURI != tt.wantFromURI || got.Text != "hello" {
					t.Fatalf("Incoming = %+v, want From %q FromURI %q text hello", got, tt.wantFrom, tt.wantFromURI)
				}
			case <-time.After(time.Second):
				t.Fatal("waiting for incoming sms callback")
			}

			select {
			case report := <-reportCh:
				if sip.RequestURI(report) != "sip:ipsmgw.example.net" {
					t.Fatalf("delivery report Request-URI = %q, want sip:ipsmgw.example.net", sip.RequestURI(report))
				}
				info, reportRPDU := multipartSMSReport(t, report)
				if info.To != tt.xmlFrom {
					t.Fatalf("delivery report XML To = %q, want %q", info.To, tt.xmlFrom)
				}
				var got rpMessage
				if err := got.UnmarshalBinary(reportRPDU); err != nil {
					t.Fatalf("report RP unmarshal error = %v", err)
				}
				if got.Type != rpAckMSToNetwork || got.Reference != 0x34 {
					t.Fatalf("report RP = %+v, want RP-ACK ref 0x34", got)
				}
			case <-time.After(time.Second):
				t.Fatal("waiting for multipart delivery report")
			}
		})
	}
}

func TestHandleInboundMSISDNLessSMSRequiresFeatureCaps(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	gotCh := make(chan Incoming, 1)
	reportCh := make(chan sip.Message, 1)
	svc, err := New(Config{Logger: testLogger(), OnIncoming: func(in Incoming) { gotCh <- in }}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() == "MESSAGE" {
			reportCh <- req
		}
	}

	tpdu, err := buildDeliver(dummyMSISDN, "hello")
	if err != nil {
		t.Fatalf("buildDeliver() error = %v", err)
	}
	rpdu, err := (rpMessage{
		Type:       rpDataNetworkToMS,
		Reference:  0x35,
		Originator: "+15550000000",
		TPDU:       tpdu,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	body, contentType := multipartSMSBody(t, `<short-message-info><From>sip:sender@example.net</From></short-message-info>`, rpdu)

	inboundTransport := newServiceTransport()
	msg := newInboundRequest("call-1", "1 MESSAGE", body)
	msg.Headers.Set("Content-Type", contentType)
	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: msg, Transport: inboundTransport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	select {
	case got := <-gotCh:
		t.Fatalf("unexpected incoming sms without Feature-Caps: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case report := <-reportCh:
		t.Fatalf("unexpected delivery report without Feature-Caps: %s", report.StartLine)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestHandleInboundNonDummyMultipartSMSIgnoresXMLFrom(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	gotCh := make(chan Incoming, 1)
	reportCh := make(chan sip.Message, 1)
	svc, err := New(Config{Logger: testLogger(), OnIncoming: func(in Incoming) { gotCh <- in }}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "MESSAGE" {
			return
		}
		reportCh <- req
		transport.queue(newResponse(req, 202, "Accepted"))
	}

	tpdu, err := buildDeliver("+15551234567", "hello")
	if err != nil {
		t.Fatalf("buildDeliver() error = %v", err)
	}
	rpdu, err := (rpMessage{
		Type:       rpDataNetworkToMS,
		Reference:  0x36,
		Originator: "+15550000000",
		TPDU:       tpdu,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	body, contentType := multipartSMSBody(t, `<short-message-info><From>sip:sender@example.net</From></short-message-info>`, rpdu)

	inboundTransport := newServiceTransport()
	msg := newInboundRequest("call-1", "1 MESSAGE", body)
	msg.Headers.Set("Content-Type", contentType)
	msg.Headers.Add("Feature-Caps", "*;+g.3gpp.smsip-msisdn-less")
	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: msg, Transport: inboundTransport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	select {
	case got := <-gotCh:
		if got.From != "+15551234567" || got.FromURI != "" || got.Text != "hello" {
			t.Fatalf("Incoming = %+v, want TP-OA +15551234567, empty FromURI, text hello", got)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for incoming sms callback")
	}
	select {
	case report := <-reportCh:
		mediaType, _, err := mime.ParseMediaType(report.Header("Content-Type"))
		if err != nil {
			t.Fatalf("ParseMediaType() error = %v", err)
		}
		if mediaType != messageContentType {
			t.Fatalf("delivery report Content-Type = %q, want %q", mediaType, messageContentType)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for delivery report")
	}
}

func TestHandleInboundMSISDNLessStatusReportUsesPlainDeliveryReport(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	statusCh := make(chan StatusReport, 1)
	reportCh := make(chan sip.Message, 1)
	svc, err := New(Config{Logger: testLogger(), OnStatusReport: func(report StatusReport) { statusCh <- report }}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "MESSAGE" {
			return
		}
		reportCh <- req
		transport.queue(newResponse(req, 202, "Accepted"))
	}

	tpdu, err := (statusReportTPDU{Message: StatusReport{
		Recipient:         dummyMSISDN,
		MessageReference:  0x27,
		Status:            0x00,
		ServiceCenterTime: time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC),
		DischargeTime:     time.Date(2026, 5, 30, 12, 1, 0, 0, time.UTC),
	}}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(status report) error = %v", err)
	}
	rpdu, err := (rpMessage{
		Type:       rpDataNetworkToMS,
		Reference:  0x39,
		Originator: "+15550000000",
		TPDU:       tpdu,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(RP-DATA) error = %v", err)
	}
	body, contentType := multipartSMSBody(t, `<short-message-info><From>sip:sender@example.net</From></short-message-info>`, rpdu)

	inboundTransport := newServiceTransport()
	msg := newInboundRequest("call-status", "1 MESSAGE", body)
	msg.Headers.Set("Content-Type", contentType)
	msg.Headers.Add("Feature-Caps", "*;+g.3gpp.smsip-msisdn-less")
	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: msg, Transport: inboundTransport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	select {
	case got := <-statusCh:
		if got.MessageReference != 0x27 || got.Recipient != dummyMSISDN {
			t.Fatalf("StatusReport = %+v, want ref 0x27 recipient dummy MSISDN", got)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for status report callback")
	}
	select {
	case report := <-reportCh:
		mediaType, _, err := mime.ParseMediaType(report.Header("Content-Type"))
		if err != nil {
			t.Fatalf("ParseMediaType() error = %v", err)
		}
		if mediaType != messageContentType {
			t.Fatalf("delivery report Content-Type = %q, want %q", mediaType, messageContentType)
		}
		var got rpMessage
		if err := got.UnmarshalBinary(report.Body); err != nil {
			t.Fatalf("report RP unmarshal error = %v", err)
		}
		if got.Type != rpAckMSToNetwork || got.Reference != 0x39 {
			t.Fatalf("report RP = %+v, want RP-ACK ref 0x39", got)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for delivery report")
	}
}

func TestHandleInboundSMSPPDataDownloadUsesUICCResponseInRPACK(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	card := &smsppDownloadStubCard{resp: usimcard.SMSPPDownloadResponse{SW1: 0x90, SW2: 0x00, Data: []byte{0xAA, 0xBB}}}
	svc, err := New(Config{Logger: testLogger()}, sess, reg, card)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	reports := make(chan sip.Message, 1)
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "MESSAGE" {
			return
		}
		reports <- req
		transport.queue(newResponse(req, 202, "Accepted"))
	}

	tpdu := []byte{0x00}
	tpdu = append(tpdu, mustEncodeTPAddress(t, "+15551234567")...)
	tpdu = append(tpdu, 0x7F, 0xF6)
	tpdu = append(tpdu, bytes.Repeat([]byte{0x00}, 7)...)
	tpdu = append(tpdu, 0x03, 0x01, 0x02, 0x03)
	rpdu, err := (rpMessage{
		Type:       rpDataNetworkToMS,
		Reference:  0x42,
		Originator: "+15550000000",
		TPDU:       tpdu,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	inboundTransport := newServiceTransport()
	req := session.Request{Message: newInboundRequest("call-1", "1 MESSAGE", rpdu), Transport: inboundTransport}
	handled, err := svc.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	if card.req.ServiceCenterAddress != "+15550000000" || !bytes.Equal(card.req.TPDU, tpdu) {
		t.Fatalf("SMSPPDownload request = %+v, want service center +15550000000 and TPDU % X", card.req, tpdu)
	}

	select {
	case report := <-reports:
		var got rpMessage
		if err := got.UnmarshalBinary(report.Body); err != nil {
			t.Fatalf("report RP unmarshal error = %v", err)
		}
		if got.Type != rpAckMSToNetwork || got.Reference != 0x42 || !bytes.Equal(got.UserData, []byte{0xAA, 0xBB}) {
			t.Fatalf("report RP = %+v, want RP-ACK ref 0x42 user data AA BB", got)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for RP-ACK report")
	}
}

func TestHandleInboundSMSDelaysRPACKUntilCallbackReturns(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	callbackStarted := make(chan struct{})
	callbackRelease := make(chan struct{})
	reportCh := make(chan sip.Message, 1)
	svc, err := New(Config{Logger: testLogger(),
		OnIncoming: func(in Incoming) {
			close(callbackStarted)
			<-callbackRelease
		},
	}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "MESSAGE" {
			return
		}
		reportCh <- req
		transport.queue(newResponse(req, 202, "Accepted"))
	}

	tpdu, err := buildDeliver("+15551234567", "hello")
	if err != nil {
		t.Fatalf("buildDeliver() error = %v", err)
	}
	rpdu, err := (rpMessage{
		Type:       rpDataNetworkToMS,
		Reference:  0x01,
		Originator: "+15550000000",
		TPDU:       tpdu,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	inboundTransport := newServiceTransport()
	done := make(chan error, 1)
	go func() {
		_, err := svc.HandleRequest(context.Background(), session.Request{
			Message:   newInboundRequest("call-1", "1 MESSAGE", rpdu),
			Transport: inboundTransport,
		})
		done <- err
	}()

	select {
	case <-callbackStarted:
	case <-time.After(time.Second):
		t.Fatal("waiting for callback start")
	}

	select {
	case req := <-reportCh:
		t.Fatalf("delivery report sent before callback returned: %s", req.StartLine)
	case <-time.After(20 * time.Millisecond):
	}

	close(callbackRelease)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("HandleRequest() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for HandleRequest()")
	}

	select {
	case req := <-reportCh:
		if sip.RequestURI(req) != "sip:ipsmgw.example.net" {
			t.Fatalf("delivery report Request-URI = %q, want sip:ipsmgw.example.net", sip.RequestURI(req))
		}
		if req.Header("To") != "<sip:ipsmgw.example.net>" {
			t.Fatalf("delivery report To = %q, want <sip:ipsmgw.example.net>", req.Header("To"))
		}
		if req.Header("In-Reply-To") != "call-1" {
			t.Fatalf("In-Reply-To = %q, want call-1", req.Header("In-Reply-To"))
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for delivery report")
	}
}

func TestReportTargetUsesIPSMGWAssertedIdentity(t *testing.T) {
	tests := []struct {
		name string
		msg  sip.Message
		want string
	}{
		{
			name: "p asserted identity",
			msg: sip.Message{Headers: sip.Headers{
				{Name: "P-Asserted-Identity", Value: "<sip:ipsmgw.example.net>"},
				{Name: "From", Value: "<sip:user@example.net>;tag=remote"},
				{Name: "Via", Value: "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-1"},
			}},
			want: "sip:ipsmgw.example.net",
		},
		{
			name: "missing p asserted identity",
			msg: sip.Message{Headers: sip.Headers{
				{Name: "From", Value: "<sip:user@example.net>;tag=remote"},
				{Name: "Via", Value: "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-1"},
			}},
			want: "",
		},
		{
			name: "tel asserted identity rejected for request uri",
			msg: sip.Message{Headers: sip.Headers{
				{Name: "P-Asserted-Identity", Value: "<tel:+15551234567>"},
			}},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &Service{}
			if got := svc.reportTarget(tt.msg); got != tt.want {
				t.Fatalf("reportTarget() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeXMLInfoRejectsDuplicateElements(t *testing.T) {
	tests := []struct {
		name string
		xml  string
	}{
		{
			name: "duplicate empty To",
			xml:  `<short-message-info><To></To><To>sip:bob@example.net</To></short-message-info>`,
		},
		{
			name: "duplicate empty From",
			xml:  `<short-message-info><From></From><From>sip:alice@example.net</From></short-message-info>`,
		},
		{
			name: "duplicate Correlation-ID",
			xml:  `<short-message-info><Correlation-ID><Sender>sip:a@example.net</Sender></Correlation-ID><Correlation-ID><Sender>sip:b@example.net</Sender></Correlation-ID></short-message-info>`,
		},
		{
			name: "duplicate Delivery-Outcome",
			xml:  `<short-message-info><Delivery-Outcome>SuccessfulTransfer</Delivery-Outcome><Delivery-Outcome>SMDeliveryFailure</Delivery-Outcome></short-message-info>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decodeXMLInfo([]byte(tt.xml)); err == nil {
				t.Fatal("decodeXMLInfo() error = nil, want duplicate element error")
			}
		})
	}
}

func TestDecodeXMLInfoRejectsNonSIPURIs(t *testing.T) {
	tests := []struct {
		name string
		xml  string
	}{
		{
			name: "To tel URI",
			xml:  `<short-message-info><To>tel:+15551234567</To></short-message-info>`,
		},
		{
			name: "From plain string",
			xml:  `<short-message-info><From>alice@example.net</From></short-message-info>`,
		},
		{
			name: "Correlation Sender tel URI",
			xml:  `<short-message-info><Correlation-ID><Sender>tel:+15551234567</Sender><Receiver>sip:bob@example.net</Receiver><HLR-ID>hlr</HLR-ID></Correlation-ID></short-message-info>`,
		},
		{
			name: "Correlation Receiver plain string",
			xml:  `<short-message-info><Correlation-ID><Sender>sip:alice@example.net</Sender><Receiver>bob@example.net</Receiver><HLR-ID>hlr</HLR-ID></Correlation-ID></short-message-info>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decodeXMLInfo([]byte(tt.xml)); err == nil {
				t.Fatal("decodeXMLInfo() error = nil, want SIP URI validation error")
			}
		})
	}
}

func TestMarshalXMLInfoRejectsNonSIPURIs(t *testing.T) {
	tests := []struct {
		name string
		info xmlInfo
	}{
		{
			name: "To tel URI",
			info: xmlInfo{To: "tel:+15551234567"},
		},
		{
			name: "From plain string",
			info: xmlInfo{From: "alice@example.net"},
		},
		{
			name: "Correlation Sender tel URI",
			info: xmlInfo{
				CorrelationID: xmlCorrelationID{
					Sender:   "tel:+15551234567",
					Receiver: "sip:bob@example.net",
					HLRID:    "hlr",
				},
				HasCorrelationID: true,
			},
		},
		{
			name: "Correlation Receiver plain string",
			info: xmlInfo{
				CorrelationID: xmlCorrelationID{
					Sender:   "sip:alice@example.net",
					Receiver: "bob@example.net",
					HLRID:    "hlr",
				},
				HasCorrelationID: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.info.MarshalText(); err == nil {
				t.Fatal("MarshalText() error = nil, want SIP URI validation error")
			}
		})
	}
}

func TestXMLInfoRoundTripIncludesCorrelationAndOutcome(t *testing.T) {
	tests := []struct {
		name string
		info xmlInfo
	}{
		{
			name: "addressing",
			info: xmlInfo{
				To:   "sip:bob@example.net",
				From: "sip:alice@example.net",
			},
		},
		{
			name: "correlation and delivery outcome",
			info: xmlInfo{
				CorrelationID: xmlCorrelationID{
					Sender:   "sip:alice@example.net",
					Receiver: "sip:bob@example.net",
					HLRID:    "hlr.example.net",
				},
				HasCorrelationID: true,
				DeliveryOutcome:  "SMDeliveryFailure",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, err := tt.info.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			var got xmlInfo
			if err := got.UnmarshalText(text); err != nil {
				t.Fatalf("UnmarshalText() error = %v", err)
			}
			if got != tt.info {
				t.Fatalf("UnmarshalText() = %+v, want %+v body=%s", got, tt.info, text)
			}
		})
	}
}

func TestXMLInfoReadFromWriteTo(t *testing.T) {
	tests := []struct {
		name string
		info xmlInfo
	}{
		{
			name: "addresses",
			info: xmlInfo{
				To:   "sip:bob@example.net",
				From: "sip:alice@example.net",
			},
		},
		{
			name: "correlation",
			info: xmlInfo{
				CorrelationID: xmlCorrelationID{
					Sender:   "sip:alice@example.net",
					Receiver: "sip:bob@example.net",
					HLRID:    "hlr.example.net",
				},
				HasCorrelationID: true,
				DeliveryOutcome:  deliveryOutcomeSuccessfulTransfer,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			written, err := tt.info.WriteTo(&out)
			if err != nil {
				t.Fatalf("WriteTo() error = %v", err)
			}
			if written != int64(out.Len()) {
				t.Fatalf("WriteTo() bytes = %d, want %d", written, out.Len())
			}

			var got xmlInfo
			read, err := got.ReadFrom(bytes.NewReader(out.Bytes()))
			if err != nil {
				t.Fatalf("ReadFrom() error = %v", err)
			}
			if read != int64(out.Len()) {
				t.Fatalf("ReadFrom() bytes = %d, want %d", read, out.Len())
			}
			if got != tt.info {
				t.Fatalf("ReadFrom() = %+v, want %+v body=%s", got, tt.info, out.String())
			}
		})
	}
}

func TestDecodeXMLInfoNormalizesUnknownDeliveryOutcome(t *testing.T) {
	tests := []struct {
		name string
		xml  string
		want string
	}{
		{
			name: "known outcome",
			xml:  `<short-message-info><Delivery-Outcome>SuccessfulTransfer</Delivery-Outcome></short-message-info>`,
			want: deliveryOutcomeSuccessfulTransfer,
		},
		{
			name: "unknown outcome",
			xml:  `<short-message-info><Delivery-Outcome>FutureOutcome</Delivery-Outcome></short-message-info>`,
			want: deliveryOutcomeSMDeliveryFailure,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeXMLInfo([]byte(tt.xml))
			if err != nil {
				t.Fatalf("decodeXMLInfo() error = %v", err)
			}
			if got.DeliveryOutcome != tt.want {
				t.Fatalf("DeliveryOutcome = %q, want %q", got.DeliveryOutcome, tt.want)
			}
		})
	}
}

func TestDecodeXMLInfoAcceptsDocumentNamespace(t *testing.T) {
	got, err := decodeXMLInfo([]byte(`<short-message-info xmlns="urn:vendor"><To>sip:bob@example.net</To><From>sip:alice@example.net</From><Correlation-ID><Sender>sip:a@example.net</Sender><Receiver>sip:b@example.net</Receiver><HLR-ID>hlr</HLR-ID></Correlation-ID><Delivery-Outcome>SuccessfulTransfer</Delivery-Outcome></short-message-info>`))
	if err != nil {
		t.Fatalf("decodeXMLInfo() error = %v", err)
	}
	if got.To != "sip:bob@example.net" || got.From != "sip:alice@example.net" {
		t.Fatalf("To/From = %q/%q, want namespaced values", got.To, got.From)
	}
	if !got.HasCorrelationID || got.CorrelationID.Sender != "sip:a@example.net" || got.CorrelationID.Receiver != "sip:b@example.net" || got.CorrelationID.HLRID != "hlr" {
		t.Fatalf("CorrelationID = %+v has=%t, want namespaced correlation id", got.CorrelationID, got.HasCorrelationID)
	}
	if got.DeliveryOutcome != deliveryOutcomeSuccessfulTransfer {
		t.Fatalf("DeliveryOutcome = %q, want %q", got.DeliveryOutcome, deliveryOutcomeSuccessfulTransfer)
	}
}

func TestEnvelopeEndpointSplitsNumberAndURI(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		wantNumber string
		wantURI    string
	}{
		{name: "sip phone uri", value: "sip:+19293101226@one.att.net", wantNumber: "+19293101226", wantURI: "sip:+19293101226@one.att.net"},
		{name: "sips phone uri", value: "sips:+19293101226@one.att.net", wantNumber: "+19293101226", wantURI: "sips:+19293101226@one.att.net"},
		{name: "tel phone uri", value: "tel:+19293101226", wantNumber: "+19293101226", wantURI: "tel:+19293101226"},
		{name: "name address", value: "<sip:+19293101226@one.att.net>;tag=abc", wantNumber: "+19293101226", wantURI: "sip:+19293101226@one.att.net"},
		{name: "non dialable sip uri", value: "sip:alice@one.att.net", wantURI: "sip:alice@one.att.net"},
		{name: "legacy bare target", value: "+19293101226", wantNumber: "+19293101226"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := envelopeEndpoint(tt.value)
			if got.Number != tt.wantNumber || got.URI != tt.wantURI {
				t.Fatalf("envelopeEndpoint() = %+v, want number %q uri %q", got, tt.wantNumber, tt.wantURI)
			}
		})
	}
}

func TestMarshalXMLInfoRejectsUnknownDeliveryOutcome(t *testing.T) {
	tests := []struct {
		name string
		info xmlInfo
	}{
		{
			name: "unknown outcome",
			info: xmlInfo{DeliveryOutcome: "FutureOutcome"},
		},
		{
			name: "case mismatch",
			info: xmlInfo{DeliveryOutcome: "smdeliveryfailure"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.info.MarshalText(); err == nil {
				t.Fatal("MarshalText() error = nil, want delivery outcome validation error")
			}
		})
	}
}

func TestDecodeXMLInfoRejectsDuplicateCorrelationIDChildren(t *testing.T) {
	tests := []struct {
		name string
		xml  string
	}{
		{
			name: "duplicate Sender",
			xml:  `<short-message-info><Correlation-ID><Sender>sip:a@example.net</Sender><Sender>sip:b@example.net</Sender><Receiver>sip:c@example.net</Receiver><HLR-ID>hlr</HLR-ID></Correlation-ID></short-message-info>`,
		},
		{
			name: "duplicate Receiver",
			xml:  `<short-message-info><Correlation-ID><Sender>sip:a@example.net</Sender><Receiver>sip:b@example.net</Receiver><Receiver>sip:c@example.net</Receiver><HLR-ID>hlr</HLR-ID></Correlation-ID></short-message-info>`,
		},
		{
			name: "duplicate HLR-ID",
			xml:  `<short-message-info><Correlation-ID><Sender>sip:a@example.net</Sender><Receiver>sip:b@example.net</Receiver><HLR-ID>hlr1</HLR-ID><HLR-ID>hlr2</HLR-ID></Correlation-ID></short-message-info>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decodeXMLInfo([]byte(tt.xml)); err == nil {
				t.Fatal("decodeXMLInfo() error = nil, want duplicate child error")
			}
		})
	}
}

func TestDecodeXMLInfoRejectsIncompleteCorrelationID(t *testing.T) {
	tests := []struct {
		name string
		xml  string
	}{
		{
			name: "missing Sender",
			xml:  `<short-message-info><Correlation-ID><Receiver>sip:b@example.net</Receiver><HLR-ID>hlr</HLR-ID></Correlation-ID></short-message-info>`,
		},
		{
			name: "missing Receiver",
			xml:  `<short-message-info><Correlation-ID><Sender>sip:a@example.net</Sender><HLR-ID>hlr</HLR-ID></Correlation-ID></short-message-info>`,
		},
		{
			name: "missing HLR-ID",
			xml:  `<short-message-info><Correlation-ID><Sender>sip:a@example.net</Sender><Receiver>sip:b@example.net</Receiver></Correlation-ID></short-message-info>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decodeXMLInfo([]byte(tt.xml)); err == nil {
				t.Fatal("decodeXMLInfo() error = nil, want incomplete Correlation-ID error")
			}
		})
	}
}

func TestDecodeMultipartSMSPayloadRejectsDuplicateXMLPart(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, xmlBody := range []string{
		`<short-message-info><From>sip:alice@example.net</From></short-message-info>`,
		`<short-message-info><From>sip:bob@example.net</From></short-message-info>`,
	} {
		part, err := writer.CreatePart(textproto.MIMEHeader{
			"Content-Type":        {xmlContentType},
			"Content-Disposition": {xmlDisposition},
		})
		if err != nil {
			t.Fatalf("CreatePart(xml) error = %v", err)
		}
		if _, err := part.Write([]byte(xmlBody)); err != nil {
			t.Fatalf("Write(xml) error = %v", err)
		}
	}
	part, err := writer.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {messageContentType},
		"Content-Transfer-Encoding": {binaryTransferValue},
	})
	if err != nil {
		t.Fatalf("CreatePart(sms) error = %v", err)
	}
	if _, err := part.Write([]byte{rpDataNetworkToMS, 0x01}); err != nil {
		t.Fatalf("Write(sms) error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	msg := sip.NewRequest("MESSAGE", "sip:user@example.net")
	msg.Headers.Add("Content-Type", mixedMultipartType+"; boundary="+writer.Boundary())
	msg.Body = body.Bytes()
	if _, err := decodeMessagePayload(msg); err == nil {
		t.Fatal("decodeMessagePayload() error = nil, want duplicate XML part error")
	}
}

func TestDecodeMultipartSMSPayloadRejectsInvalidXMLDisposition(t *testing.T) {
	tests := []struct {
		name        string
		disposition string
	}{
		{name: "missing disposition"},
		{name: "wrong disposition type", disposition: "attachment;handling=optional"},
		{name: "missing handling", disposition: "render"},
		{name: "wrong handling", disposition: "render;handling=required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			xmlHeader := textproto.MIMEHeader{
				"Content-Type": {xmlContentType},
			}
			if tt.disposition != "" {
				xmlHeader.Set("Content-Disposition", tt.disposition)
			}
			xmlPart, err := writer.CreatePart(xmlHeader)
			if err != nil {
				t.Fatalf("CreatePart(xml) error = %v", err)
			}
			if _, err := xmlPart.Write([]byte(`<short-message-info><From>sip:alice@example.net</From></short-message-info>`)); err != nil {
				t.Fatalf("Write(xml) error = %v", err)
			}
			part, err := writer.CreatePart(textproto.MIMEHeader{
				"Content-Type":              {messageContentType},
				"Content-Transfer-Encoding": {binaryTransferValue},
			})
			if err != nil {
				t.Fatalf("CreatePart(sms) error = %v", err)
			}
			if _, err := part.Write([]byte{rpDataNetworkToMS, 0x01}); err != nil {
				t.Fatalf("Write(sms) error = %v", err)
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}

			msg := sip.NewRequest("MESSAGE", "sip:user@example.net")
			msg.Headers.Add("Content-Type", mixedMultipartType+"; boundary="+writer.Boundary())
			msg.Body = body.Bytes()
			if _, err := decodeMessagePayload(msg); err == nil {
				t.Fatal("decodeMessagePayload() error = nil, want invalid XML disposition error")
			}
		})
	}
}

func TestDecodeMultipartSMSPayloadUnsupportedBodyPartHandling(t *testing.T) {
	tests := []struct {
		name    string
		header  textproto.MIMEHeader
		wantErr bool
	}{
		{
			name: "optional unsupported part ignored",
			header: textproto.MIMEHeader{
				"Content-Type":        {"text/plain"},
				"Content-Disposition": {"render;handling=optional"},
			},
		},
		{
			name: "optional malformed content type ignored",
			header: textproto.MIMEHeader{
				"Content-Type":        {"%%%"},
				"Content-Disposition": {"render;handling=optional"},
			},
		},
		{
			name: "missing disposition is required",
			header: textproto.MIMEHeader{
				"Content-Type": {"text/plain"},
			},
			wantErr: true,
		},
		{
			name: "explicit required unsupported part rejected",
			header: textproto.MIMEHeader{
				"Content-Type":        {"text/plain"},
				"Content-Disposition": {"render;handling=required"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rpdu := []byte{rpDataNetworkToMS, 0x01}
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			unknownPart, err := writer.CreatePart(tt.header)
			if err != nil {
				t.Fatalf("CreatePart(unknown) error = %v", err)
			}
			if _, err := unknownPart.Write([]byte("ignored")); err != nil {
				t.Fatalf("Write(unknown) error = %v", err)
			}
			part, err := writer.CreatePart(textproto.MIMEHeader{
				"Content-Type":              {messageContentType},
				"Content-Transfer-Encoding": {binaryTransferValue},
			})
			if err != nil {
				t.Fatalf("CreatePart(sms) error = %v", err)
			}
			if _, err := part.Write(rpdu); err != nil {
				t.Fatalf("Write(sms) error = %v", err)
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}

			msg := sip.NewRequest("MESSAGE", "sip:user@example.net")
			msg.Headers.Add("Content-Type", mixedMultipartType+"; boundary="+writer.Boundary())
			msg.Body = body.Bytes()
			got, err := decodeMessagePayload(msg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("decodeMessagePayload() error = nil, want unsupported body part error")
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeMessagePayload() error = %v", err)
			}
			if !bytes.Equal(got.RPDU, rpdu) {
				t.Fatalf("decodeMessagePayload() RPDU = % X, want % X", got.RPDU, rpdu)
			}
		})
	}
}

func TestDecodeMessagePayloadRejectsNonBinaryTransferEncoding(t *testing.T) {
	tests := []struct {
		name    string
		message func(t *testing.T) sip.Message
	}{
		{
			name: "single sms body",
			message: func(t *testing.T) sip.Message {
				t.Helper()
				msg := newInboundRequest("call-cte-single", "1 MESSAGE", []byte{rpDataNetworkToMS, 0x01})
				msg.Headers.Set("Content-Transfer-Encoding", "base64")
				return msg
			},
		},
		{
			name: "multipart sms part",
			message: func(t *testing.T) sip.Message {
				t.Helper()
				var body bytes.Buffer
				writer := multipart.NewWriter(&body)
				part, err := writer.CreatePart(textproto.MIMEHeader{
					"Content-Type":              {messageContentType},
					"Content-Transfer-Encoding": {"quoted-printable"},
				})
				if err != nil {
					t.Fatalf("CreatePart(sms) error = %v", err)
				}
				if _, err := part.Write([]byte{rpDataNetworkToMS, 0x01}); err != nil {
					t.Fatalf("Write(sms) error = %v", err)
				}
				if err := writer.Close(); err != nil {
					t.Fatalf("Close() error = %v", err)
				}
				msg := sip.NewRequest("MESSAGE", "sip:user@example.net")
				msg.Headers.Add("Content-Type", mixedMultipartType+"; boundary="+writer.Boundary())
				msg.Body = body.Bytes()
				return msg
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeMessagePayload(tt.message(t))
			if err == nil {
				t.Fatal("decodeMessagePayload() error = nil, want non-binary transfer encoding error")
			}
			if !strings.Contains(err.Error(), "content transfer encoding") {
				t.Fatalf("decodeMessagePayload() error = %v, want content transfer encoding", err)
			}
		})
	}
}

func TestHandleMessageRejectsNonBinaryTransferEncoding(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	inboundTransport := newServiceTransport()
	svc, err := New(Config{Logger: testLogger()}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() {
		if err := svc.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()
	msg := newInboundRequest("call-cte-status", "1 MESSAGE", []byte{rpDataNetworkToMS, 0x01})
	msg.Headers.Set("Content-Transfer-Encoding", "base64")

	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: msg, Transport: inboundTransport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	if len(inboundTransport.writes) != 1 {
		t.Fatalf("inbound response count = %d, want 1", len(inboundTransport.writes))
	}
	resp := mustParseMessage(t, inboundTransport.writes[0])
	if got := resp.StatusCode(); got != sipStatusUnsupportedMediaType {
		t.Fatalf("response status = %d, want %d", got, sipStatusUnsupportedMediaType)
	}
	if got := resp.Header("Accept"); got != acceptHeader {
		t.Fatalf("Accept = %q, want %q", got, acceptHeader)
	}
	for _, data := range transport.writes {
		req := mustParseMessage(t, data)
		if req.Method() == "MESSAGE" {
			t.Fatalf("unexpected outbound MESSAGE: %s", req.StartLine)
		}
	}
}

func TestHandleMessageRejectsUnsupportedContentType(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	inboundTransport := newServiceTransport()
	svc, err := New(Config{Logger: testLogger()}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() {
		if err := svc.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()
	msg := newInboundRequest("call-content-type-status", "1 MESSAGE", []byte("hello"))
	msg.Headers.Set("Content-Type", "text/plain")

	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: msg, Transport: inboundTransport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	if len(inboundTransport.writes) != 1 {
		t.Fatalf("inbound response count = %d, want 1", len(inboundTransport.writes))
	}
	resp := mustParseMessage(t, inboundTransport.writes[0])
	if got := resp.StatusCode(); got != sipStatusUnsupportedMediaType {
		t.Fatalf("response status = %d, want %d", got, sipStatusUnsupportedMediaType)
	}
	if got := resp.Header("Accept"); got != acceptHeader {
		t.Fatalf("Accept = %q, want %q", got, acceptHeader)
	}
}

func TestSendReturnsSuccessWhenSubmitReportMissing(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	errCh := make(chan error, 1)
	svc, err := New(Config{
		Logger:              testLogger(),
		SubmitReportTimeout: 20 * time.Millisecond,
		OnError:             func(err error) { errCh <- err },
	}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() {
		if err := svc.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	requests := make(chan []byte, 4)
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "MESSAGE" {
			return
		}
		requests <- append([]byte(nil), data...)
		transport.queue(newResponse(req, 202, "Accepted"))
	}

	type sendResult struct {
		submission Submission
		err        error
	}
	sendDone := make(chan sendResult, 1)
	go func() {
		submission, err := svc.Send(context.Background(), "777", "BAL")
		sendDone <- sendResult{submission: submission, err: err}
	}()
	first := nextSMSRequest(t, requests)

	var result sendResult
	select {
	case result = <-sendDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Send() did not return before submit report timeout")
	}
	if result.err != nil {
		t.Fatalf("Send() error = %v", result.err)
	}
	if len(result.submission.Segments) != 1 {
		t.Fatalf("len(submission.Segments) = %d, want 1", len(result.submission.Segments))
	}

	time.Sleep(100 * time.Millisecond)
	var states []SubmissionState
	for update := range result.submission.Updates {
		states = append(states, update.State)
	}
	if !slices.Contains(states, SubmissionSubmittedToIMS) {
		t.Fatalf("submission update states = %v, want %s", states, SubmissionSubmittedToIMS)
	}
	if !slices.Contains(states, SubmissionSubmitUnknown) {
		t.Fatalf("submission update states = %v, want %s", states, SubmissionSubmitUnknown)
	}

	if err := sendSubmitReport(svc, rpMessage{Type: rpErrorNetworkToMS, Reference: moReference(t, first), Cause: rpCauseTemporaryFailure, HasCause: true}, first.Header("Call-ID")); err != nil {
		t.Fatalf("late sendSubmitReport() error = %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("OnError = %v, want none", err)
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case retry := <-requests:
		t.Fatalf("unexpected retry MESSAGE after submit report timeout:\n%s", retry)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSendReturnsPartialSubmissionAfterMultipartFailure(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	errCh := make(chan error, 1)
	svc, err := New(Config{
		Logger:              testLogger(),
		SubmitReportTimeout: 20 * time.Millisecond,
		OnError:             func(err error) { errCh <- err },
	}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() {
		if err := svc.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	requests := make(chan []byte, 4)
	var messageCount atomic.Int32
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "MESSAGE" {
			return
		}
		requests <- append([]byte(nil), data...)
		switch messageCount.Add(1) {
		case 1:
			transport.queue(newResponse(req, 202, "Accepted"))
		default:
			transport.queue(newResponse(req, 500, "Server Internal Error"))
		}
	}

	submission, err := svc.Send(context.Background(), "777", strings.Repeat("A", 200))
	if err == nil {
		t.Fatal("Send() error = nil, want second segment failure")
	}
	var partial *PartialSubmissionError
	if !errors.As(err, &partial) {
		t.Fatalf("Send() error = %T %[1]v, want PartialSubmissionError", err)
	}
	if len(submission.Segments) != 1 {
		t.Fatalf("len(submission.Segments) = %d, want 1", len(submission.Segments))
	}
	if len(partial.Submission.Segments) != 1 {
		t.Fatalf("len(partial.Submission.Segments) = %d, want 1", len(partial.Submission.Segments))
	}
	first := nextSMSRequest(t, requests)

	time.Sleep(100 * time.Millisecond)
	var states []SubmissionState
	for update := range submission.Updates {
		states = append(states, update.State)
	}
	if !slices.Contains(states, SubmissionSubmittedToIMS) {
		t.Fatalf("submission update states = %v, want %s", states, SubmissionSubmittedToIMS)
	}
	if !slices.Contains(states, SubmissionSubmitUnknown) {
		t.Fatalf("submission update states = %v, want %s", states, SubmissionSubmitUnknown)
	}

	if err := sendSubmitReport(svc, rpMessage{Type: rpAckNetworkToMS, Reference: moReference(t, first)}, first.Header("Call-ID")); err != nil {
		t.Fatalf("late sendSubmitReport() error = %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("OnError = %v, want none", err)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSendMatchesSubmitReportByRPReference(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "rp ack without in-reply-to"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newServiceTransport()
			sess, reg := registeredService(t, transport)
			errCh := make(chan error, 1)
			svc, err := New(Config{
				Logger:              testLogger(),
				SubmitReportTimeout: time.Second,
				OnError:             func(err error) { errCh <- err },
			}, sess, reg, serviceStubCard{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				if err := svc.Close(); err != nil {
					t.Fatalf("Close() error = %v", err)
				}
			}()

			requests := make(chan []byte, 1)
			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				if req.Method() != "MESSAGE" {
					return
				}
				requests <- append([]byte(nil), data...)
				transport.queue(newResponse(req, 202, "Accepted"))
			}

			sendErr := make(chan error, 1)
			go func() {
				_, err := svc.Send(context.Background(), "777", "BAL")
				sendErr <- err
			}()
			first := nextSMSRequest(t, requests)
			var firstRP rpMessage
			if err := firstRP.UnmarshalBinary(first.Body); err != nil {
				t.Fatalf("first RP unmarshal error = %v", err)
			}
			ackBody, err := (rpMessage{Type: rpAckNetworkToMS, Reference: firstRP.Reference}).MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary(ack) error = %v", err)
			}
			select {
			case err := <-sendErr:
				if err != nil {
					t.Fatalf("Send() error = %v", err)
				}
			case <-time.After(100 * time.Millisecond):
				t.Fatal("Send() did not return before submit report")
			}

			inbound := newServiceTransport()
			ack := newInboundRequest("submit-report", "2 MESSAGE", ackBody)
			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: ack, Transport: inbound})
			if err != nil {
				t.Fatalf("HandleRequest(ack) error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest(ack) handled = false, want true")
			}
			if len(inbound.writes) != 1 {
				t.Fatalf("inbound response count = %d, want 1", len(inbound.writes))
			}
			resp := mustParseMessage(t, inbound.writes[0])
			if got := resp.StatusCode(); got != sipStatusOK {
				t.Fatalf("response status = %d, want %d", got, sipStatusOK)
			}
			select {
			case err := <-errCh:
				t.Fatalf("OnError = %v, want none", err)
			default:
			}
		})
	}
}

func TestSendSIPURIRequiresInReplyToForSubmitReport(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{
		Logger:              testLogger(),
		SubmitReportTimeout: time.Second,
	}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() {
		if err := svc.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	requests := make(chan []byte, 1)
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "MESSAGE" {
			return
		}
		requests <- append([]byte(nil), data...)
		transport.queue(newResponse(req, 202, "Accepted"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sendErr := make(chan error, 1)
	go func() {
		_, err := svc.Send(ctx, "sip:bob@example.net", "BAL")
		sendErr <- err
	}()

	first := nextSMSRequest(t, requests)
	reportBody, err := (rpMessage{Type: rpAckNetworkToMS, Reference: moReference(t, first)}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(submit report) error = %v", err)
	}
	select {
	case err := <-sendErr:
		if err != nil {
			t.Fatalf("Send() error = %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Send() did not return before submit report")
	}

	missing := newInboundRequest("submit-report-missing", "2 MESSAGE", reportBody)
	missingTransport := newServiceTransport()
	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: missing, Transport: missingTransport})
	if err != nil {
		t.Fatalf("HandleRequest(missing In-Reply-To) error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest(missing In-Reply-To) handled = false, want true")
	}
	if len(missingTransport.writes) != 1 {
		t.Fatalf("missing In-Reply-To response count = %d, want 1", len(missingTransport.writes))
	}
	if got := mustParseMessage(t, missingTransport.writes[0]).StatusCode(); got != sipStatusNotAcceptableHere {
		t.Fatalf("missing In-Reply-To status = %d, want %d", got, sipStatusNotAcceptableHere)
	}

	matched := newInboundRequest("submit-report-matched", "3 MESSAGE", reportBody)
	matched.Headers.Add("In-Reply-To", first.Header("Call-ID"))
	matchedTransport := newServiceTransport()
	handled, err = svc.HandleRequest(context.Background(), session.Request{Message: matched, Transport: matchedTransport})
	if err != nil {
		t.Fatalf("HandleRequest(matched submit report) error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest(matched submit report) handled = false, want true")
	}
	if len(matchedTransport.writes) != 1 {
		t.Fatalf("matched submit report response count = %d, want 1", len(matchedTransport.writes))
	}
	if got := mustParseMessage(t, matchedTransport.writes[0]).StatusCode(); got != sipStatusOK {
		t.Fatalf("matched submit report status = %d, want %d", got, sipStatusOK)
	}

	duplicateMissing := newInboundRequest("submit-report-duplicate-missing", "4 MESSAGE", reportBody)
	duplicateTransport := newServiceTransport()
	handled, err = svc.HandleRequest(context.Background(), session.Request{Message: duplicateMissing, Transport: duplicateTransport})
	if err != nil {
		t.Fatalf("HandleRequest(duplicate missing In-Reply-To) error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest(duplicate missing In-Reply-To) handled = false, want true")
	}
	if len(duplicateTransport.writes) != 1 {
		t.Fatalf("duplicate missing In-Reply-To response count = %d, want 1", len(duplicateTransport.writes))
	}
	if got := mustParseMessage(t, duplicateTransport.writes[0]).StatusCode(); got != sipStatusNotAcceptableHere {
		t.Fatalf("duplicate missing In-Reply-To status = %d, want %d", got, sipStatusNotAcceptableHere)
	}
}

func TestSendDoesNotRetrySubmitRPError(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	errCh := make(chan error, 1)
	svc, err := New(Config{
		Logger:              testLogger(),
		SubmitReportTimeout: time.Second,
		OnError:             func(err error) { errCh <- err },
	}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() {
		if err := svc.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	requests := make(chan []byte, 4)
	reportErr := make(chan error, 1)
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "MESSAGE" {
			return
		}
		requests <- append([]byte(nil), data...)
		var rp rpMessage
		if err := rp.UnmarshalBinary(req.Body); err != nil {
			reportErr <- fmt.Errorf("first RP unmarshal: %w", err)
		} else {
			report := rpMessage{Type: rpErrorNetworkToMS, Reference: rp.Reference, Cause: rpCauseTemporaryFailure, HasCause: true}
			reportMsg := newInboundRequest("submit-report", "2 MESSAGE", nil)
			reportMsg.Headers.Add("In-Reply-To", req.Header("Call-ID"))
			if !svc.completePending(reportMsg, report) {
				reportErr <- fmt.Errorf("completePending() = false")
			} else {
				reportErr <- nil
			}
		}
		transport.queue(newResponse(req, 202, "Accepted"))
	}

	type sendResult struct {
		submission Submission
		err        error
	}
	sendDone := make(chan sendResult, 1)
	go func() {
		submission, err := svc.Send(context.Background(), "777", "BAL")
		sendDone <- sendResult{submission: submission, err: err}
	}()
	_ = nextSMSRequest(t, requests)

	select {
	case err := <-reportErr:
		if err != nil {
			t.Fatalf("sendSubmitReport() error = %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("sendSubmitReport() did not return")
	}

	var result sendResult
	select {
	case result = <-sendDone:
		if result.err != nil {
			t.Fatalf("Send() error = %v", result.err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Send() did not return after RP-ERROR")
	}

	var states []SubmissionState
	var rejected SubmissionUpdate
	for update := range result.submission.Updates {
		states = append(states, update.State)
		if update.State == SubmissionRejectedBySMSC {
			rejected = update
		}
	}
	if !slices.Contains(states, SubmissionSubmittedToIMS) {
		t.Fatalf("submission update states = %v, want %s", states, SubmissionSubmittedToIMS)
	}
	if !slices.Contains(states, SubmissionRejectedBySMSC) {
		t.Fatalf("submission update states = %v, want %s", states, SubmissionRejectedBySMSC)
	}
	if !rejected.HasRPCause || rejected.RPCause != rpCauseTemporaryFailure {
		t.Fatalf("rejected update cause = has %t cause %d, want temporary failure", rejected.HasRPCause, rejected.RPCause)
	}

	select {
	case data := <-requests:
		t.Fatalf("unexpected retried MESSAGE: %s", mustParseMessage(t, data).StartLine)
	case err := <-errCh:
		t.Fatalf("OnError = %v, want none for synchronous RP-ERROR", err)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestHandleInboundReservedRPDirectionReturnsRPError97(t *testing.T) {
	tpdu, err := buildDeliver("+15551234567", "hello")
	if err != nil {
		t.Fatalf("buildDeliver() error = %v", err)
	}
	msToNetworkRPDU, err := (rpMessage{
		Type:      rpDataMSToNetwork,
		Reference: 0x22,
		TPDU:      tpdu,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	tests := []struct {
		name string
		rpdu []byte
		ref  byte
	}{
		{name: "wrong direction RP-DATA", rpdu: msToNetworkRPDU, ref: 0x22},
		{name: "reserved RP MTI", rpdu: []byte{0x07, 0x23}, ref: 0x23},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newServiceTransport()
			sess, reg := registeredService(t, transport)
			svc, err := New(Config{Logger: testLogger()}, sess, reg, serviceStubCard{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			reports := make(chan sip.Message, 1)
			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				if req.Method() != "MESSAGE" {
					return
				}
				reports <- req
				transport.queue(newResponse(req, 202, "Accepted"))
			}

			inboundTransport := newServiceTransport()
			req := session.Request{Message: newInboundRequest("call-1", "1 MESSAGE", tt.rpdu), Transport: inboundTransport}
			handled, err := svc.HandleRequest(context.Background(), req)
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}

			select {
			case report := <-reports:
				var got rpMessage
				if err := got.UnmarshalBinary(report.Body); err != nil {
					t.Fatalf("report RP unmarshal error = %v", err)
				}
				if got.Type != rpErrorMSToNetwork || got.Reference != tt.ref || got.Cause != rpCauseMessageTypeNotImplemented {
					t.Fatalf("report RP = %+v, want RP-ERROR ref 0x%02X cause 97", got, tt.ref)
				}
			case <-time.After(time.Second):
				t.Fatal("waiting for RP-ERROR report")
			}
		})
	}
}

func TestHandleMalformedInboundRPDataReturnsRPError96(t *testing.T) {
	tests := []struct {
		name string
		rpdu []byte
		ref  byte
	}{
		{
			name: "trailing octet after RP user data",
			rpdu: func() []byte {
				raw := append([]byte{rpDataNetworkToMS, 0x44}, encodeRPAddress("+15550000000")...)
				raw = append(raw, encodeRPAddress("")...)
				raw = append(raw, 0x01, 0x00, 0xFF)
				return raw
			}(),
			ref: 0x44,
		},
		{
			name: "RP user data over maximum",
			rpdu: func() []byte {
				raw := append([]byte{rpDataNetworkToMS, 0x45}, encodeRPAddress("+15550000000")...)
				raw = append(raw, encodeRPAddress("")...)
				raw = append(raw, byte(maxRPDataUserDataOctets+1))
				raw = append(raw, bytes.Repeat([]byte{0x00}, maxRPDataUserDataOctets+1)...)
				return raw
			}(),
			ref: 0x45,
		},
		{
			name: "missing TPDU in mandatory RP user data",
			rpdu: func() []byte {
				raw := append([]byte{rpDataNetworkToMS, 0x46}, encodeRPAddress("+15550000000")...)
				raw = append(raw, encodeRPAddress("")...)
				raw = append(raw, 0x00)
				return raw
			}(),
			ref: 0x46,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newServiceTransport()
			sess, reg := registeredService(t, transport)
			svc, err := New(Config{Logger: testLogger()}, sess, reg, serviceStubCard{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			reports := make(chan sip.Message, 1)
			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				if req.Method() != "MESSAGE" {
					return
				}
				reports <- req
				transport.queue(newResponse(req, 202, "Accepted"))
			}

			inboundTransport := newServiceTransport()
			req := session.Request{Message: newInboundRequest("call-1", "1 MESSAGE", tt.rpdu), Transport: inboundTransport}
			handled, err := svc.HandleRequest(context.Background(), req)
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}

			select {
			case report := <-reports:
				var got rpMessage
				if err := got.UnmarshalBinary(report.Body); err != nil {
					t.Fatalf("report RP unmarshal error = %v", err)
				}
				if got.Type != rpErrorMSToNetwork || got.Reference != tt.ref || got.Cause != rpCauseInvalidMandatoryInformation {
					t.Fatalf("report RP = %+v, want RP-ERROR ref 0x%02X cause 96", got, tt.ref)
				}
			case <-time.After(time.Second):
				t.Fatal("waiting for RP-ERROR report")
			}
		})
	}
}

func newServiceTransport() *serviceStubTransport {
	return &serviceStubTransport{
		local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5062},
		remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060},
		readCh: make(chan []byte, 16),
	}
}

func ackReports(t *testing.T, transport *serviceStubTransport) {
	t.Helper()
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() == "MESSAGE" {
			transport.queue(newResponse(req, 202, "Accepted"))
		}
	}
}

func ackMOSubmit(t *testing.T, svc *Service, req sip.Message) {
	t.Helper()
	report := rpMessage{Type: rpAckNetworkToMS, Reference: moReference(t, req)}
	inReplyTo := req.Header("Call-ID")
	errCh := make(chan error, 1)
	go func() {
		errCh <- sendSubmitReport(svc, report, inReplyTo)
	}()
	t.Cleanup(func() {
		t.Helper()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("sendSubmitReport() error = %v", err)
			}
		case <-time.After(time.Second):
			t.Error("sendSubmitReport() did not return")
		}
	})
}

func sendSubmitReport(svc *Service, report rpMessage, inReplyTo string) error {
	body, err := report.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal submit report: %w", err)
	}
	msg := newInboundRequest("submit-report", "2 MESSAGE", body)
	if inReplyTo != "" {
		msg.Headers.Add("In-Reply-To", inReplyTo)
	}
	inbound := newServiceTransport()
	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: msg, Transport: inbound})
	if err != nil {
		return fmt.Errorf("handle submit report: %w", err)
	}
	if !handled {
		return fmt.Errorf("handle submit report: handled = false, want true")
	}
	return nil
}

func moReference(t *testing.T, req sip.Message) byte {
	t.Helper()
	body := req.Body
	mediaType, _, err := mime.ParseMediaType(req.Header("Content-Type"))
	if err != nil {
		t.Fatalf("ParseMediaType(Content-Type) error = %v", err)
	}
	if strings.EqualFold(mediaType, mixedMultipartType) {
		_, body = multipartSMSReport(t, req)
	}
	var rp rpMessage
	if err := rp.UnmarshalBinary(body); err != nil {
		t.Fatalf("RP unmarshal error = %v", err)
	}
	return rp.Reference
}

func registeredService(t *testing.T, transport *serviceStubTransport) (*session.Session, *registration.Service) {
	t.Helper()
	sess, err := session.Open(session.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(testRegistrationConfig(transport), sess, serviceStubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch req.Method() {
		case "REGISTER":
			if len(transport.writes) == 1 {
				transport.queue(newResponse(req, 401, "Unauthorized",
					sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=",algorithm=AKAv1-MD5,qop="auth"`},
					sip.Header{Name: "Security-Server", Value: `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=1111;spi-s=2222`},
				))
				return
			}
			transport.queue(newResponse(req, 200, "OK",
				sip.Header{Name: "P-Associated-URI", Value: "<tel:+15551234567>"},
				sip.Header{Name: "Service-Route", Value: "<sip:pcscf.example.com;lr>"},
			))
		}
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	return sess, reg
}

func registeredServiceWithAssociatedURIs(t *testing.T, transport *serviceStubTransport, associatedURIs ...string) (*session.Session, *registration.Service) {
	t.Helper()
	sess, err := session.Open(session.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(testRegistrationConfig(transport), sess, serviceStubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch req.Method() {
		case "REGISTER":
			if len(transport.writes) == 1 {
				transport.queue(newResponse(req, 401, "Unauthorized",
					sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=",algorithm=AKAv1-MD5,qop="auth"`},
					sip.Header{Name: "Security-Server", Value: `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=1111;spi-s=2222`},
				))
				return
			}
			headers := []sip.Header{{Name: "Service-Route", Value: "<sip:pcscf.example.com;lr>"}}
			if len(associatedURIs) > 0 {
				headers = append(headers, sip.Header{Name: "P-Associated-URI", Value: strings.Join(associatedURIs, ",")})
			}
			transport.queue(newResponse(req, 200, "OK", headers...))
		}
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	return sess, reg
}

func testRegistrationConfig(transport *serviceStubTransport) registration.Config {
	return registration.Config{
		Logger:            testLogger(),
		UserAgent:         "test-agent",
		AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aa",
		DialSecureUDP: func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
			return transport, nil
		},
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return transport, nil
		},
	}
}

func newInboundRequest(callID, cseq string, body []byte) sip.Message {
	msg := sip.NewRequest("MESSAGE", "sip:test@example.com")
	msg.Headers = sip.Headers{
		{Name: "Via", Value: "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1"},
		{Name: "From", Value: "<tel:+15551234567>;tag=remote"},
		{Name: "To", Value: "<sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org>"},
		{Name: "P-Asserted-Identity", Value: "<sip:ipsmgw.example.net>"},
		{Name: "Call-ID", Value: callID},
		{Name: "CSeq", Value: cseq},
		{Name: "Content-Type", Value: "application/vnd.3gpp.sms"},
	}
	msg.Body = body
	return msg
}

func newResponse(req sip.Message, code int, reason string, extra ...sip.Header) sip.Message {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req, code)
	resp.Headers = append(resp.Headers, extra...)
	return resp
}

func mustParseMessage(t *testing.T, data []byte) sip.Message {
	t.Helper()
	msg, err := sip.ParseMessage(data)
	if err != nil {
		t.Fatalf("ParseMessage() error = %v", err)
	}
	return msg
}

func nextSMSRequest(t *testing.T, requests <-chan []byte) sip.Message {
	t.Helper()
	select {
	case data := <-requests:
		return mustParseMessage(t, data)
	case <-time.After(time.Second):
		t.Fatal("waiting for outbound SMS MESSAGE")
		return sip.Message{}
	}
}

func multipartSMSBody(t *testing.T, xmlBody string, rpdu []byte) ([]byte, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	xmlPart, err := writer.CreatePart(textproto.MIMEHeader{
		"Content-Type":        {xmlContentType},
		"Content-Disposition": {xmlDisposition},
	})
	if err != nil {
		t.Fatalf("CreatePart(xml) error = %v", err)
	}
	if _, err := xmlPart.Write([]byte(xmlBody)); err != nil {
		t.Fatalf("Write(xml) error = %v", err)
	}
	part, err := writer.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {messageContentType},
		"Content-Transfer-Encoding": {binaryTransferValue},
	})
	if err != nil {
		t.Fatalf("CreatePart(sms) error = %v", err)
	}
	if _, err := part.Write(rpdu); err != nil {
		t.Fatalf("Write(sms) error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	return body.Bytes(), mixedMultipartType + "; boundary=" + writer.Boundary()
}

func multipartSMSReport(t *testing.T, msg sip.Message) (xmlInfo, []byte) {
	t.Helper()
	mediaType, params, err := mime.ParseMediaType(msg.Header("Content-Type"))
	if err != nil {
		t.Fatalf("ParseMediaType() error = %v", err)
	}
	if mediaType != mixedMultipartType {
		t.Fatalf("Content-Type = %q, want %q", mediaType, mixedMultipartType)
	}
	reader := multipart.NewReader(bytes.NewReader(msg.Body), params["boundary"])
	var info xmlInfo
	var rpdu []byte
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextPart() error = %v", err)
		}
		data, err := io.ReadAll(part)
		if err != nil {
			t.Fatalf("ReadAll(part) error = %v", err)
		}
		mediaType, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			t.Fatalf("part ParseMediaType() error = %v", err)
		}
		switch mediaType {
		case xmlContentType:
			if err := validateXMLDisposition(part.Header.Get("Content-Disposition")); err != nil {
				t.Fatalf("XML Content-Disposition error = %v", err)
			}
			info, err = decodeXMLInfo(data)
			if err != nil {
				t.Fatalf("decodeXMLInfo() error = %v", err)
			}
		case messageContentType:
			rpdu = append([]byte(nil), data...)
		}
	}
	if info.To == "" {
		t.Fatal("delivery report XML To = empty")
	}
	if rpdu == nil {
		t.Fatal("delivery report RPDU = nil")
	}
	return info, rpdu
}
