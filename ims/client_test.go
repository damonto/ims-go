package ims

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/damonto/ims-client/usim"
)

type stubTransport struct {
	local      net.Addr
	remote     net.Addr
	writes     [][]byte
	writeAddrs []net.Addr
	reads      [][]byte
	onWrite    func(data []byte)
}

func (t *stubTransport) LocalAddr() net.Addr  { return t.local }
func (t *stubTransport) RemoteAddr() net.Addr { return t.remote }
func (t *stubTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	for {
		if len(t.reads) > 0 {
			packet := t.reads[0]
			t.reads = t.reads[1:]
			return packet, t.remote, nil
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}
func (t *stubTransport) WritePacket(ctx context.Context, data []byte) error {
	return t.writePacket(data, nil)
}

func (t *stubTransport) WritePacketTo(ctx context.Context, data []byte, addr net.Addr) error {
	return t.writePacket(data, addr)
}

func (t *stubTransport) writePacket(data []byte, addr net.Addr) error {
	pkt := append([]byte(nil), data...)
	t.writes = append(t.writes, pkt)
	if addr != nil {
		switch v := addr.(type) {
		case *net.UDPAddr:
			t.writeAddrs = append(t.writeAddrs, &net.UDPAddr{IP: append(net.IP(nil), v.IP...), Port: v.Port, Zone: v.Zone})
		case *net.TCPAddr:
			t.writeAddrs = append(t.writeAddrs, &net.TCPAddr{IP: append(net.IP(nil), v.IP...), Port: v.Port, Zone: v.Zone})
		default:
			t.writeAddrs = append(t.writeAddrs, addr)
		}
	} else {
		t.writeAddrs = append(t.writeAddrs, nil)
	}
	if t.onWrite != nil {
		t.onWrite(pkt)
	}
	return nil
}
func (t *stubTransport) Close() error { return nil }

type stubCard struct{}

func (stubCard) IMSI() string { return "001010123456789" }
func (stubCard) MCC() string  { return "001" }
func (stubCard) MNC() string  { return "001" }
func (stubCard) SMSC() string { return "+15550000000" }
func (stubCard) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	return usim.AKAResult{RES: []byte("password")}, nil
}

type identityStubCard struct {
	stubCard
	homeDomain      string
	privateIdentity string
	publicIdentity  string
}

func (c identityStubCard) HomeDomain() string      { return c.homeDomain }
func (c identityStubCard) PrivateIdentity() string { return c.privateIdentity }
func (c identityStubCard) PublicIdentity() string  { return c.publicIdentity }

func testAuthNonce(seed byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32))
}

func authorizationField(value, field string) string {
	for _, part := range strings.Split(value, ",") {
		name, rawValue, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		if strings.EqualFold(name, field) || strings.EqualFold(name, "Digest "+field) {
			return strings.Trim(rawValue, `"`)
		}
	}
	return ""
}

func authorizationNonce(value string) string {
	return authorizationField(value, "nonce")
}

const (
	testPublicIdentity = "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org"
	testUserAgent      = "test-agent"
	testUSSDLanguage   = "en"
)

func newUDPStubTransport(localPort, remotePort int) *stubTransport {
	return &stubTransport{
		local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort},
		remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remotePort},
	}
}

func newTCPStubTransport(localPort, remotePort int) *stubTransport {
	return &stubTransport{
		local:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort},
		remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remotePort},
	}
}

func newClientUDPTransport() *stubTransport  { return newUDPStubTransport(5062, 5060) }
func newInboundUDPTransport() *stubTransport { return newUDPStubTransport(15062, 15060) }
func newClientTCPTransport() *stubTransport  { return newTCPStubTransport(5062, 5060) }

func newTestClient(t *testing.T, cfg Config, transport Transport) *Client {
	t.Helper()
	if cfg.PublicIdentity == "" {
		cfg.PublicIdentity = testPublicIdentity
	}
	client, err := NewClient(cfg, transport, stubCard{})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	return client
}

func TestNewClientIdentityResolution(t *testing.T) {
	tests := []struct {
		name                string
		cfg                 Config
		card                cardProvider
		wantPrivateIdentity string
		wantPublicIdentity  string
		wantRegisterURI     string
	}{
		{
			name:                "falls back to IMSI identities",
			cfg:                 Config{},
			card:                stubCard{},
			wantPrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
			wantPublicIdentity:  testPublicIdentity,
			wantRegisterURI:     "sip:ims.mnc001.mcc001.3gppnetwork.org",
		},
		{
			name: "uses identity provider defaults",
			cfg:  Config{},
			card: identityStubCard{
				homeDomain:      "ims.example.com",
				privateIdentity: "alice@ims.example.com",
				publicIdentity:  "sip:alice@example.com",
			},
			wantPrivateIdentity: "alice@ims.example.com",
			wantPublicIdentity:  "sip:alice@example.com",
			wantRegisterURI:     "sip:ims.example.com",
		},
		{
			name: "config public identity wins",
			cfg:  Config{PublicIdentity: "sip:override@example.com", HomeDomain: "ims.override.example.com"},
			card: identityStubCard{
				homeDomain:      "ims.example.com",
				privateIdentity: "alice@ims.example.com",
				publicIdentity:  "sip:alice@example.com",
			},
			wantPrivateIdentity: "alice@ims.example.com",
			wantPublicIdentity:  "sip:override@example.com",
			wantRegisterURI:     "sip:ims.override.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.cfg, newClientUDPTransport(), tt.card)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}
			if client.privateIdentity != tt.wantPrivateIdentity {
				t.Fatalf("privateIdentity = %q, want %q", client.privateIdentity, tt.wantPrivateIdentity)
			}
			if client.cfg.PublicIdentity != tt.wantPublicIdentity {
				t.Fatalf("PublicIdentity = %q, want %q", client.cfg.PublicIdentity, tt.wantPublicIdentity)
			}
			if client.registerURI != tt.wantRegisterURI {
				t.Fatalf("registerURI = %q, want %q", client.registerURI, tt.wantRegisterURI)
			}
		})
	}
}

func newTestUSSDClient(t *testing.T, cfg Config, transport Transport) *Client {
	t.Helper()
	if cfg.UserAgent == "" {
		cfg.UserAgent = testUserAgent
	}
	if cfg.USSDLanguage == "" {
		cfg.USSDLanguage = testUSSDLanguage
	}
	if cfg.Transport == "" {
		cfg.Transport = "tcp"
	}
	return newTestClient(t, cfg, transport)
}

func mustParseMessage(t *testing.T, label string, data []byte) Message {
	t.Helper()
	msg, err := ParseMessage(data)
	if err != nil {
		t.Fatalf("ParseMessage(%s) error = %v", label, err)
	}
	return msg
}

func waitForWriteEvents(t *testing.T, ch <-chan struct{}, want int) {
	t.Helper()
	for range want {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for %d write events", want)
		}
	}
}

func newTestResponse(req Message, code int, reason string) Message {
	resp := NewResponse(code, reason)
	resp.Headers = responseHeaders(req, code)
	return resp
}

func newInboundSMSRequest(callID, cseq string, rpdu []byte) Message {
	msg := NewRequest("MESSAGE", "tel:+15550000000")
	msg.AddHeader("Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-test")
	msg.AddHeader("From", "<sip:server@example.com>;tag=1")
	msg.AddHeader("To", fmt.Sprintf("<%s>", testPublicIdentity))
	msg.AddHeader("Call-ID", callID)
	msg.AddHeader("CSeq", cseq)
	msg.AddHeader("P-Asserted-Identity", "<tel:+15550000000>")
	msg.Body = rpdu
	return msg
}

func newSMSNetworkRequest(target, branch, callID, cseq string, body []byte) Message {
	msg := NewRequest("MESSAGE", target)
	msg.AddHeader("Via", fmt.Sprintf("SIP/2.0/UDP 127.0.0.1:5060;branch=%s", branch))
	msg.AddHeader("From", "<sip:smsc@example.com>;tag=1")
	msg.AddHeader("To", fmt.Sprintf("<%s>", target))
	msg.AddHeader("Call-ID", callID)
	msg.AddHeader("CSeq", cseq)
	msg.AddHeader("P-Asserted-Identity", "<tel:+15550000000>")
	msg.Body = body
	return msg
}

func newInboundRequest(method, callID, cseq string) Message {
	msg := NewRequest(method, testPublicIdentity)
	msg.AddHeader("Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-test")
	msg.AddHeader("From", "<sip:server@example.com>;tag=1")
	msg.AddHeader("To", fmt.Sprintf("<%s>", testPublicIdentity))
	msg.AddHeader("Call-ID", callID)
	msg.AddHeader("CSeq", cseq)
	return msg
}

func TestUpgradeSecureTransport(t *testing.T) {
	transport := newClientTCPTransport()
	secureTransport := newClientTCPTransport()
	serverTransport := newTCPStubTransport(5061, 5063)
	serverDatagramTransport := newUDPStubTransport(4500, 4501)
	client := newTestClient(t, Config{Transport: "tcp"}, transport)
	client.securityVerify = &SecurityParam{Alg: "hmac-md5-96", PortC: 4501, PortS: 4500, SPIC: 0x11111111, SPIS: 0x22222222}
	client.authIK = []byte{0xAA, 0xBB}

	var dialCfg SecureTCPConfig
	var listenTCPCfg SecureTCPConfig
	var listenUDPCfg SecureUDPConfig
	client.cfg.DialSecureTCP = func(ctx context.Context, cfg SecureTCPConfig) (Transport, error) {
		dialCfg = cfg
		return secureTransport, nil
	}
	client.cfg.ListenSecureTCP = func(ctx context.Context, cfg SecureTCPConfig) (Transport, error) {
		listenTCPCfg = cfg
		return serverTransport, nil
	}
	client.cfg.ListenSecureUDP = func(ctx context.Context, cfg SecureUDPConfig) (Transport, error) {
		listenUDPCfg = cfg
		return serverDatagramTransport, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.upgradeSecureTransport(ctx); err != nil {
		t.Fatalf("upgradeSecureTransport() error = %v", err)
	}
	if client.transport != secureTransport {
		t.Fatal("transport not replaced")
	}
	if client.serverTransport != serverTransport {
		t.Fatal("serverTransport not set")
	}
	if client.serverDatagramTransport != serverDatagramTransport {
		t.Fatal("serverDatagramTransport not set")
	}
	if dialCfg.LocalPort != client.securityClient.PortC || dialCfg.RemotePort != client.securityVerify.PortS || dialCfg.OutboundSPI != client.securityVerify.SPIS || dialCfg.InboundSPI != client.securityClient.SPIC {
		t.Fatalf("dial secure config = %+v", dialCfg)
	}
	if listenTCPCfg.LocalPort != client.securityClient.PortS || listenTCPCfg.RemotePort != client.securityVerify.PortC || listenTCPCfg.OutboundSPI != client.securityVerify.SPIC || listenTCPCfg.InboundSPI != client.securityClient.SPIS {
		t.Fatalf("listen TCP config = %+v", listenTCPCfg)
	}
	if listenUDPCfg.LocalPort != client.securityClient.PortS || listenUDPCfg.RemotePort != client.securityVerify.PortC || listenUDPCfg.OutboundSPI != client.securityVerify.SPIC || listenUDPCfg.InboundSPI != client.securityClient.SPIS {
		t.Fatalf("listen UDP config = %+v", listenUDPCfg)
	}
	if got := dialCfg.IntegrityKey; len(got) != len(client.authIK) || got[0] != client.authIK[0] || got[1] != client.authIK[1] {
		t.Fatalf("dial integrity key = %v, want %v", got, client.authIK)
	}
}

func TestSendPendingSkipsProvisionalResponses(t *testing.T) {
	transport := newClientUDPTransport()
	client := newTestClient(t, Config{}, transport)
	req := client.buildMessage("tel:777", []byte("hello"), "")
	transport.onWrite = func(_ []byte) {
		client.dispatchResponse(newTestResponse(req, 100, "Trying"))
		client.dispatchResponse(newTestResponse(req, 200, "OK"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := client.sendPending(ctx, req)
	if err != nil {
		t.Fatalf("sendPending() error = %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Fatalf("StatusCode() = %d, want 200", resp.StatusCode())
	}
}

func TestExchangeSkipsRequestsAndProvisionalResponses(t *testing.T) {
	transport := newClientUDPTransport()
	client := newTestClient(t, Config{}, transport)
	req := client.buildMessage("tel:777", []byte("hello"), "")
	transport.reads = [][]byte{
		newInboundRequest("MESSAGE", "incoming-1", "1 MESSAGE").Bytes(),
		newTestResponse(req, 100, "Trying").Bytes(),
		newTestResponse(req, 200, "OK").Bytes(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := client.exchange(ctx, req)
	if err != nil {
		t.Fatalf("exchange() error = %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Fatalf("StatusCode() = %d, want 200", resp.StatusCode())
	}
	if len(transport.writes) != 1 {
		t.Fatalf("len(transport.writes) = %d, want 1", len(transport.writes))
	}
}

func TestHandleRequestDispatch(t *testing.T) {
	tests := []struct {
		name       string
		msg        Message
		wantWrites int
		wantStatus int
	}{
		{name: "notify acknowledged", msg: newInboundRequest("NOTIFY", "notify-1", "1 NOTIFY"), wantWrites: 1, wantStatus: 200},
		{name: "ack ignored", msg: newInboundRequest("ACK", "ack-1", "1 ACK"), wantWrites: 0},
		{name: "unsupported method rejected", msg: newInboundRequest("OPTIONS", "options-1", "1 OPTIONS"), wantWrites: 1, wantStatus: 405},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newInboundUDPTransport()
			client := newTestClient(t, Config{}, newClientUDPTransport())
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := client.handleRequest(ctx, transport, tt.msg); err != nil {
				t.Fatalf("handleRequest() error = %v", err)
			}
			if len(transport.writes) != tt.wantWrites {
				t.Fatalf("len(writes) = %d, want %d", len(transport.writes), tt.wantWrites)
			}
			if tt.wantWrites == 0 {
				return
			}
			resp := mustParseMessage(t, "response", transport.writes[0])
			if got := resp.StatusCode(); got != tt.wantStatus {
				t.Fatalf("StatusCode() = %d, want %d", got, tt.wantStatus)
			}
		})
	}
}

func TestHandleIncomingMessage(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{name: "gsm7", text: "hello"},
		{name: "ucs2", text: "你好"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newClientUDPTransport()
			inboundTransport := newInboundUDPTransport()
			var got IncomingSMS
			count := 0
			client := newTestClient(t, Config{OnSMS: func(msg IncomingSMS) { got = msg; count++ }}, transport)
			reportCh := make(chan struct{}, 1)
			transport.onWrite = func(data []byte) {
				reportCh <- struct{}{}
				req, err := ParseMessage(data)
				if err != nil {
					t.Errorf("ParseMessage(delivery-report) error = %v", err)
					return
				}
				go client.dispatchResponse(newTestResponse(req, 202, "Accepted"))
			}

			tpdu, err := buildSMSDeliver("+15551234567", tt.text)
			if err != nil {
				t.Fatalf("buildSMSDeliver() error = %v", err)
			}
			rpdu := append([]byte{rpDataNetworkToMS, 0x01}, 0x00)
			rpdu = append(rpdu, encodeRPAddress("+15550000000")...)
			rpdu = append(rpdu, byte(len(tpdu)))
			rpdu = append(rpdu, tpdu...)

			msg := newInboundSMSRequest("call-1", "1 MESSAGE", rpdu)

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := client.handleRequest(ctx, inboundTransport, msg); err != nil {
				t.Fatalf("handleRequest() error = %v", err)
			}
			if err := client.handleRequest(ctx, inboundTransport, msg); err != nil {
				t.Fatalf("handleRequest(duplicate) error = %v", err)
			}
			waitForWriteEvents(t, reportCh, 1)
			if count != 1 {
				t.Fatalf("sms callback count = %d, want 1", count)
			}
			if got.Text != tt.text || got.From != "15551234567" {
				t.Fatalf("incoming sms = %+v", got)
			}
			if len(transport.writes) != 1 {
				t.Fatalf("len(client writes) = %d, want 1", len(transport.writes))
			}
			if len(inboundTransport.writes) != 2 {
				t.Fatalf("len(inbound writes) = %d, want 2", len(inboundTransport.writes))
			}
			response := mustParseMessage(t, "response", inboundTransport.writes[0])
			if response.StatusCode() != 200 {
				t.Fatalf("response.StatusCode() = %d, want 200", response.StatusCode())
			}
			ack := mustParseMessage(t, "ack", transport.writes[0])
			if ack.Method() != "MESSAGE" {
				t.Fatalf("ack.Method() = %q, want MESSAGE", ack.Method())
			}
			if ack.Header("Content-Transfer-Encoding") != "binary" {
				t.Fatalf("ack Content-Transfer-Encoding = %q, want binary", ack.Header("Content-Transfer-Encoding"))
			}
		})
	}
}

func TestSMSDeliveryReportTarget(t *testing.T) {
	tests := []struct {
		name string
		msg  func() Message
		want string
	}{
		{
			name: "prefers sip asserted identity",
			msg: func() Message {
				msg := newInboundSMSRequest("call-1", "1 MESSAGE", []byte{rpAckNetworkToMS, 0x01})
				msg.Headers = upsertHeader(msg.Headers, "P-Asserted-Identity", "<sip:ipsmgw.example.com>")
				msg.Headers = upsertHeader(msg.Headers, "From", "<tel:+15551234567>;tag=1")
				return msg
			},
			want: "sip:ipsmgw.example.com",
		},
		{
			name: "falls back to sip from",
			msg: func() Message {
				msg := newInboundSMSRequest("call-1", "1 MESSAGE", []byte{rpAckNetworkToMS, 0x01})
				msg.Headers = upsertHeader(msg.Headers, "P-Asserted-Identity", "<tel:+15550000000>")
				msg.Headers = upsertHeader(msg.Headers, "From", "<sip:ipsmgw.example.com>;tag=remote-1")
				return msg
			},
			want: "sip:ipsmgw.example.com",
		},
		{
			name: "falls back to last via sent by",
			msg: func() Message {
				msg := newInboundSMSRequest("call-1", "1 MESSAGE", []byte{rpAckNetworkToMS, 0x01})
				msg.Headers = upsertHeader(msg.Headers, "P-Asserted-Identity", "<tel:+15550000000>")
				msg.Headers = upsertHeader(msg.Headers, "From", "<tel:+15551234567>;tag=remote-1")
				msg.Headers = upsertHeader(msg.Headers, "Via", "SIP/2.0/UDP pcscf.example.com;branch=z9hG4bK-pcscf, SIP/2.0/UDP ipsmgw.example.com:6000;branch=z9hG4bK-gw")
				return msg
			},
			want: "sip:ipsmgw.example.com:6000",
		},
	}

	client := newTestClient(t, Config{}, newClientUDPTransport())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := client.smsReportTarget(tt.msg()); got != tt.want {
				t.Fatalf("smsReportTarget() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHandleIncomingMessageRoutesResponseToSourcePort(t *testing.T) {
	transport := newUDPStubTransport(20481, 32773)
	transport.remote = &net.UDPAddr{IP: net.IPv4(172, 29, 63, 232), Port: 32773}
	client := newTestClient(t, Config{}, newClientUDPTransport())

	tpdu, err := buildSMSDeliver("+15551234567", "hello")
	if err != nil {
		t.Fatalf("buildSMSDeliver() error = %v", err)
	}
	rpdu := append([]byte{rpDataNetworkToMS, 0x01}, 0x00)
	rpdu = append(rpdu, encodeRPAddress("+15550000000")...)
	rpdu = append(rpdu, byte(len(tpdu)))
	rpdu = append(rpdu, tpdu...)

	msg := newInboundSMSRequest("call-1", "1 MESSAGE", rpdu)
	msg.Headers = upsertHeader(msg.Headers, "Via", "SIP/2.0/UDP 172.29.63.232:6000;branch=z9hG4bK-test")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.handleRequest(ctx, transport, msg); err != nil {
		t.Fatalf("handleRequest() error = %v", err)
	}
	if len(transport.writeAddrs) == 0 {
		t.Fatal("response write address not recorded")
	}
	addr, ok := transport.writeAddrs[0].(*net.UDPAddr)
	if !ok || addr == nil {
		t.Fatalf("response addr = %#v, want *net.UDPAddr", transport.writeAddrs[0])
	}
	if !addr.IP.Equal(net.IPv4(172, 29, 63, 232)) || addr.Port != 32773 {
		t.Fatalf("response addr = %v, want 172.29.63.232:32773", addr)
	}
}

func TestHandleIncomingMessageUsesViaTargetForDeliveryReport(t *testing.T) {
	transport := newClientUDPTransport()
	inboundTransport := newInboundUDPTransport()
	client := newTestClient(t, Config{}, transport)
	reportCh := make(chan struct{}, 1)
	transport.onWrite = func(data []byte) {
		reportCh <- struct{}{}
		req, err := ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage(delivery-report) error = %v", err)
			return
		}
		go client.dispatchResponse(newTestResponse(req, 202, "Accepted"))
	}

	tpdu, err := buildSMSDeliver("+15551234567", "hello")
	if err != nil {
		t.Fatalf("buildSMSDeliver() error = %v", err)
	}
	rpdu := append([]byte{rpDataNetworkToMS, 0x01}, 0x00)
	rpdu = append(rpdu, encodeRPAddress("+15550000000")...)
	rpdu = append(rpdu, byte(len(tpdu)))
	rpdu = append(rpdu, tpdu...)

	msg := newInboundSMSRequest("call-1", "1 MESSAGE", rpdu)
	msg.Headers = upsertHeader(msg.Headers, "From", "<tel:+15551234567>;tag=remote-1")
	msg.Headers = upsertHeader(msg.Headers, "P-Asserted-Identity", "<tel:+15551234567>")
	msg.Headers = upsertHeader(msg.Headers, "Via", "SIP/2.0/UDP pcscf.example.com;branch=z9hG4bK-pcscf, SIP/2.0/UDP 172.25.63.232:6000;branch=z9hG4bK-gw")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.handleRequest(ctx, inboundTransport, msg); err != nil {
		t.Fatalf("handleRequest() error = %v", err)
	}
	waitForWriteEvents(t, reportCh, 1)
	if len(transport.writes) != 1 {
		t.Fatalf("len(transport.writes) = %d, want 1", len(transport.writes))
	}
	req := mustParseMessage(t, "delivery report", transport.writes[0])
	parts := strings.Fields(req.StartLine)
	if len(parts) < 2 {
		t.Fatalf("request start line = %q", req.StartLine)
	}
	if parts[1] != "sip:172.25.63.232:6000" {
		t.Fatalf("delivery report target = %q, want %q", parts[1], "sip:172.25.63.232:6000")
	}
}

func TestResponseHeadersToTag(t *testing.T) {
	tests := []struct {
		name        string
		code        int
		request     Message
		wantHasTag  bool
		wantSameTag bool
	}{
		{
			name:       "adds tag for final response",
			code:       200,
			request:    newInboundRequest("MESSAGE", "call-1", "1 MESSAGE"),
			wantHasTag: true,
		},
		{
			name:       "keeps provisional response untagged",
			code:       100,
			request:    newInboundRequest("MESSAGE", "call-2", "1 MESSAGE"),
			wantHasTag: false,
		},
		{
			name: "preserves existing to tag",
			code: 200,
			request: func() Message {
				msg := newInboundRequest("MESSAGE", "call-3", "1 MESSAGE")
				msg.Headers = upsertHeader(msg.Headers, "To", fmt.Sprintf("<%s>;tag=network-tag", testPublicIdentity))
				return msg
			}(),
			wantHasTag:  true,
			wantSameTag: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := responseHeaders(tt.request, tt.code)
			resp := Message{Headers: headers}
			to := resp.Header("To")
			if got := addressURI(to); got != testPublicIdentity {
				t.Fatalf("addressURI(To) = %q, want %q", got, testPublicIdentity)
			}
			tag := headerTag(to)
			if got := tag != ""; got != tt.wantHasTag {
				t.Fatalf("has To tag = %v, want %v (To=%q)", got, tt.wantHasTag, to)
			}
			if tt.wantSameTag && tag != "network-tag" {
				t.Fatalf("To tag = %q, want %q", tag, "network-tag")
			}
		})
	}
}

func TestHandleIncomingMessageDuplicateResponseUsesSameToTag(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{
			name: "duplicate retransmission reuses response tag",
			text: "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newInboundUDPTransport()
			clientTransport := newClientUDPTransport()
			client := newTestClient(t, Config{}, clientTransport)
			clientTransport.onWrite = func(data []byte) {
				req, err := ParseMessage(data)
				if err != nil {
					t.Errorf("ParseMessage(delivery-report) error = %v", err)
					return
				}
				go client.dispatchResponse(newTestResponse(req, 202, "Accepted"))
			}

			tpdu, err := buildSMSDeliver("+15551234567", tt.text)
			if err != nil {
				t.Fatalf("buildSMSDeliver() error = %v", err)
			}
			rpdu := append([]byte{rpDataNetworkToMS, 0x01}, 0x00)
			rpdu = append(rpdu, encodeRPAddress("+15550000000")...)
			rpdu = append(rpdu, byte(len(tpdu)))
			rpdu = append(rpdu, tpdu...)
			msg := newInboundSMSRequest("call-1", "1 MESSAGE", rpdu)

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			if err := client.handleRequest(ctx, transport, msg); err != nil {
				t.Fatalf("handleRequest() error = %v", err)
			}
			if err := client.handleRequest(ctx, transport, msg); err != nil {
				t.Fatalf("handleRequest(duplicate) error = %v", err)
			}
			if len(transport.writes) != 2 {
				t.Fatalf("len(writes) = %d, want 2", len(transport.writes))
			}

			first := mustParseMessage(t, "first 200", transport.writes[0])
			second := mustParseMessage(t, "second 200", transport.writes[1])
			firstTag := headerTag(first.Header("To"))
			secondTag := headerTag(second.Header("To"))
			if firstTag == "" {
				t.Fatalf("first response To tag is empty")
			}
			if secondTag != firstTag {
				t.Fatalf("duplicate response To tag = %q, want %q", secondTag, firstTag)
			}
		})
	}
}

func TestSendSMS(t *testing.T) {
	transport := newClientUDPTransport()
	inboundTransport := newInboundUDPTransport()
	client := newTestClient(t, Config{}, transport)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	transport.onWrite = func(data []byte) {
		req, err := ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage(request) error = %v", err)
			return
		}
		if req.Header("Content-Transfer-Encoding") != "binary" {
			t.Errorf("request Content-Transfer-Encoding = %q, want binary", req.Header("Content-Transfer-Encoding"))
		}
		resp := newTestResponse(req, 202, "Accepted")
		go client.dispatchResponse(resp)
		if req.Method() != "MESSAGE" || len(req.Body) < 2 {
			return
		}
		rpRef := req.Body[1]
		go func() {
			time.Sleep(10 * time.Millisecond)
			ack := newSMSNetworkRequest(client.cfg.PublicIdentity, "z9hG4bK-sms-ack", "sms-ack-1", "1 MESSAGE", []byte{rpAckNetworkToMS, rpRef})
			if err := client.handleRequest(context.Background(), inboundTransport, ack); err != nil {
				t.Errorf("handleRequest(rp-ack) error = %v", err)
			}
		}()
	}

	if err := client.SendSMS(ctx, "777", "BAL"); err != nil {
		t.Fatalf("SendSMS() error = %v", err)
	}
}

func TestHandleIncomingMessageSameBodyDifferentTransaction(t *testing.T) {
	transport := newClientUDPTransport()
	inboundTransport := newInboundUDPTransport()
	var got []IncomingSMS
	client := newTestClient(t, Config{OnSMS: func(msg IncomingSMS) {
		got = append(got, msg)
	}}, transport)
	reportCh := make(chan struct{}, 2)
	transport.onWrite = func(data []byte) {
		reportCh <- struct{}{}
		req, err := ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage(delivery-report) error = %v", err)
			return
		}
		go client.dispatchResponse(newTestResponse(req, 202, "Accepted"))
	}

	tpdu, err := buildSMSDeliver("+15551234567", "same body")
	if err != nil {
		t.Fatalf("buildSMSDeliver() error = %v", err)
	}
	rpdu := append([]byte{rpDataNetworkToMS, 0x01}, 0x00)
	rpdu = append(rpdu, encodeRPAddress("+15550000000")...)
	rpdu = append(rpdu, byte(len(tpdu)))
	rpdu = append(rpdu, tpdu...)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i := range 2 {
		msg := newInboundSMSRequest(fmt.Sprintf("call-%d", i+1), fmt.Sprintf("%d MESSAGE", i+1), rpdu)
		if err := client.handleRequest(ctx, inboundTransport, msg); err != nil {
			t.Fatalf("handleRequest(%d) error = %v", i, err)
		}
	}

	waitForWriteEvents(t, reportCh, 2)
	if len(got) != 2 {
		t.Fatalf("sms callback count = %d, want 2", len(got))
	}
	for i, msg := range got {
		if msg.Text != "same body" || msg.From != "15551234567" {
			t.Fatalf("incoming sms %d = %+v", i, msg)
		}
	}
	if len(transport.writes) != 2 {
		t.Fatalf("len(transport.writes) = %d, want 2", len(transport.writes))
	}
}

func TestSendSMSRPError(t *testing.T) {
	transport := newClientUDPTransport()
	inboundTransport := newInboundUDPTransport()
	client := newTestClient(t, Config{}, transport)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	transport.onWrite = func(data []byte) {
		req, err := ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage(request) error = %v", err)
			return
		}
		resp := newTestResponse(req, 202, "Accepted")
		go client.dispatchResponse(resp)
		if req.Method() != "MESSAGE" || len(req.Body) < 2 {
			return
		}
		rpRef := req.Body[1]
		go func() {
			time.Sleep(10 * time.Millisecond)
			report := newSMSNetworkRequest(client.cfg.PublicIdentity, "z9hG4bK-sms-error", "sms-error-1", "1 MESSAGE", []byte{rpErrorNetworkToMS, rpRef, 0x01, rpCauseInvalidMandatoryInformation})
			if err := client.handleRequest(context.Background(), inboundTransport, report); err != nil {
				t.Errorf("handleRequest(rp-error) error = %v", err)
			}
		}()
	}

	err := client.SendSMS(ctx, "777", "BAL")
	var rpErr *RPError
	if !errors.As(err, &rpErr) || rpErr.Cause != rpCauseInvalidMandatoryInformation {
		t.Fatalf("SendSMS() error = %v, want RP cause %d", err, rpCauseInvalidMandatoryInformation)
	}
}

func TestClientCloseContextSendsBYEAndDeregister(t *testing.T) {
	transport := newClientUDPTransport()
	client := newTestClient(t, Config{}, transport)
	client.setRegistered(true)
	client.authRealm = "ims.mnc001.mcc001.3gppnetwork.org"
	client.authNonce = testAuthNonce(0x33)
	session := &USSDSession{
		client:      client,
		callID:      "ussd-close-1",
		sessionID:   "session-close-1",
		localTag:    "local",
		remoteTag:   "remote",
		remoteTo:    "<sip:service@example.com>;tag=remote",
		targetURI:   "sip:*100%23;phone-context=ims.mnc001.mcc001.3gppnetwork.org@ims.mnc001.mcc001.3gppnetwork.org;user=dialstring",
		routeSet:    []string{"<sip:scscf.example.com;lr>"},
		inviteSeq:   1,
		language:    "en",
		events:      make(chan USSDMessage, 1),
		remoteCSeqs: map[string]struct{}{},
	}
	client.ussd[session.callID] = session

	var byeReq Message
	var deregReq Message
	transport.onWrite = func(data []byte) {
		req, err := ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage(request) error = %v", err)
			return
		}
		resp := newTestResponse(req, 200, "OK")
		switch req.Method() {
		case "BYE":
			byeReq = req
			transport.reads = append(transport.reads, resp.Bytes())
		case "REGISTER":
			deregReq = req
			transport.reads = append(transport.reads, resp.Bytes())
		default:
			t.Errorf("unexpected method %q", req.Method())
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.CloseContext(ctx); err != nil {
		t.Fatalf("CloseContext() error = %v", err)
	}
	if byeReq.Method() != "BYE" {
		t.Fatalf("BYE request not observed: %+v", byeReq)
	}
	if deregReq.Method() != "REGISTER" {
		t.Fatalf("REGISTER request not observed: %+v", deregReq)
	}
	if got := deregReq.Header("Contact"); got != "*" {
		t.Fatalf("deregister Contact = %q, want *", got)
	}
	if got := deregReq.Header("Expires"); got != "0" {
		t.Fatalf("deregister Expires = %q, want 0", got)
	}
	if got := deregReq.Header("Authorization"); got == "" {
		t.Fatal("deregister Authorization = empty, want digest credentials")
	}
	if !session.isClosed() {
		t.Fatal("session.isClosed() = false, want true")
	}
	if client.isRegistered() {
		t.Fatal("client.isRegistered() = true, want false")
	}
}

func TestRegisterBuildersUseSecondsAndAccessNetworkInfo(t *testing.T) {
	tests := []struct {
		name       string
		accessInfo string
		wantPANI   string
	}{
		{name: "default omitted"},
		{name: "configured value", accessInfo: "IEEE-802.11;i-wlan-node-id=001122334455", wantPANI: "IEEE-802.11;i-wlan-node-id=001122334455"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newClientUDPTransport()
			client := newTestClient(t, Config{
				RegisterExpires:   90 * time.Second,
				AccessNetworkInfo: tt.accessInfo,
			}, transport)

			register := client.buildRegister("", "", nil)
			if got := register.Header("Expires"); got != "90" {
				t.Fatalf("REGISTER Expires = %q, want 90", got)
			}
			if got := register.Header("P-Access-Network-Info"); got != tt.wantPANI {
				t.Fatalf("REGISTER P-Access-Network-Info = %q, want %q", got, tt.wantPANI)
			}

			subscribe := client.buildSubscribe()
			if got := subscribe.Header("Expires"); got != "90" {
				t.Fatalf("SUBSCRIBE Expires = %q, want 90", got)
			}
			if got := subscribe.Header("P-Access-Network-Info"); got != tt.wantPANI {
				t.Fatalf("SUBSCRIBE P-Access-Network-Info = %q, want %q", got, tt.wantPANI)
			}
		})
	}
}

func TestBuildRegisterAuthorizationHeader(t *testing.T) {
	tests := []struct {
		name         string
		nonce        string
		response     string
		wantNonce    string
		wantResponse string
		wantRealm    string
		wantUsername string
	}{
		{
			name:         "initial register uses empty digest fields",
			wantRealm:    "ims.mnc001.mcc001.3gppnetwork.org",
			wantUsername: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
		},
		{
			name:         "challenged register keeps provided digest fields",
			nonce:        testAuthNonce(0x01),
			response:     "deadbeef",
			wantNonce:    testAuthNonce(0x01),
			wantResponse: "deadbeef",
			wantRealm:    "ims.mnc001.mcc001.3gppnetwork.org",
			wantUsername: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestClient(t, Config{}, newClientUDPTransport())
			register := client.buildRegister(tt.nonce, tt.response, nil)

			got := register.Header("Authorization")
			if got == "" {
				t.Fatal("REGISTER Authorization = empty")
			}
			if gotNonce := authorizationField(got, "nonce"); gotNonce != tt.wantNonce {
				t.Fatalf("REGISTER Authorization nonce = %q, want %q", gotNonce, tt.wantNonce)
			}
			if gotResponse := authorizationField(got, "response"); gotResponse != tt.wantResponse {
				t.Fatalf("REGISTER Authorization response = %q, want %q", gotResponse, tt.wantResponse)
			}
			if gotRealm := authorizationField(got, "realm"); gotRealm != tt.wantRealm {
				t.Fatalf("REGISTER Authorization realm = %q, want %q", gotRealm, tt.wantRealm)
			}
			if gotUsername := authorizationField(got, "username"); gotUsername != tt.wantUsername {
				t.Fatalf("REGISTER Authorization username = %q, want %q", gotUsername, tt.wantUsername)
			}
		})
	}
}

func TestRefreshRegistrationUsesStoredNextNonce(t *testing.T) {
	tests := []struct {
		name       string
		firstNonce string
		nextNonce  string
	}{
		{name: "nextnonce refresh", firstNonce: testAuthNonce(0x01), nextNonce: testAuthNonce(0x02)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newClientUDPTransport()
			client := newTestClient(t, Config{}, transport)
			client.authRealm = "ims.mnc001.mcc001.3gppnetwork.org"
			client.authNonce = tt.firstNonce

			var seen []string
			transport.onWrite = func(data []byte) {
				req, err := ParseMessage(data)
				if err != nil {
					t.Errorf("ParseMessage(request) error = %v", err)
					return
				}
				if !req.IsRequest() || req.Method() != "REGISTER" {
					return
				}
				seen = append(seen, authorizationNonce(req.Header("Authorization")))
				resp := newTestResponse(req, 200, "OK")
				resp.AddHeader("Expires", "120")
				if len(seen) == 1 {
					resp.AddHeader("Authentication-Info", fmt.Sprintf(`nextnonce="%s"`, tt.nextNonce))
				}
				go client.dispatchResponse(resp)
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := client.refreshRegistration(ctx); err != nil {
				t.Fatalf("refreshRegistration(first) error = %v", err)
			}
			if err := client.refreshRegistration(ctx); err != nil {
				t.Fatalf("refreshRegistration(second) error = %v", err)
			}
			want := []string{tt.firstNonce, tt.nextNonce}
			if len(seen) != len(want) {
				t.Fatalf("seen nonces = %v, want %v", seen, want)
			}
			for i := range want {
				if seen[i] != want[i] {
					t.Fatalf("seen nonces = %v, want %v", seen, want)
				}
			}
		})
	}
}

func TestAppendConcatSMS(t *testing.T) {
	type step struct {
		text  string
		total byte
		seq   byte
	}

	tests := []struct {
		name         string
		steps        []step
		wantComplete bool
		wantText     string
	}{
		{
			name:         "out of order completes on last fragment",
			steps:        []step{{text: "world", total: 2, seq: 2}, {text: "hello ", total: 2, seq: 1}},
			wantComplete: true,
			wantText:     "hello world",
		},
		{
			name:         "single fragment stays incomplete",
			steps:        []step{{text: "hello ", total: 2, seq: 1}},
			wantComplete: false,
		},
		{
			name:         "changed total resets cached fragments",
			steps:        []step{{text: "old", total: 3, seq: 1}, {text: "hi ", total: 2, seq: 1}, {text: "there", total: 2, seq: 2}},
			wantComplete: true,
			wantText:     "hi there",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestClient(t, Config{}, newClientUDPTransport())

			var (
				got      IncomingSMS
				complete bool
				key      string
			)
			for i, step := range tt.steps {
				got, complete, key = client.appendConcatSMS(
					IncomingSMS{From: "15551234567", To: "15550000000", Text: step.text},
					smsConcatInfo{Reference: 0x22, Total: step.total, Sequence: step.seq},
				)
				if i < len(tt.steps)-1 && complete {
					t.Fatalf("complete at step %d, want incomplete", i)
				}
			}

			if complete != tt.wantComplete {
				t.Fatalf("complete = %v, want %v", complete, tt.wantComplete)
			}
			if key == "" {
				t.Fatal("concat key is empty")
			}
			if !tt.wantComplete {
				return
			}
			if got.Text != tt.wantText {
				t.Fatalf("got.Text = %q, want %q", got.Text, tt.wantText)
			}
		})
	}
}

func TestHandleIncomingMultipartSMS(t *testing.T) {
	transport := newClientUDPTransport()
	inboundTransport := newInboundUDPTransport()
	text := strings.Repeat("A", 200)
	parts, err := buildSMSUserDataParts(text)
	if err != nil {
		t.Fatalf("buildSMSUserDataParts() error = %v", err)
	}
	var got []IncomingSMS
	client := newTestClient(t, Config{OnSMS: func(msg IncomingSMS) {
		got = append(got, msg)
	}}, transport)
	reportCh := make(chan struct{}, len(parts))
	transport.onWrite = func(data []byte) {
		reportCh <- struct{}{}
		req, err := ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage(delivery-report) error = %v", err)
			return
		}
		go client.dispatchResponse(newTestResponse(req, 202, "Accepted"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i, part := range parts {
		tpdu := part.marshalDeliver("+15551234567")
		rpdu := append([]byte{rpDataNetworkToMS, byte(i + 1)}, 0x00)
		rpdu = append(rpdu, encodeRPAddress("+15550000000")...)
		rpdu = append(rpdu, byte(len(tpdu)))
		rpdu = append(rpdu, tpdu...)
		msg := newInboundSMSRequest(fmt.Sprintf("multipart-call-%d", i+1), fmt.Sprintf("%d MESSAGE", i+1), rpdu)
		if err := client.handleRequest(ctx, inboundTransport, msg); err != nil {
			t.Fatalf("handleRequest(part %d) error = %v", i, err)
		}
	}
	waitForWriteEvents(t, reportCh, len(parts))
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	if got[0].Text != text || got[0].From != "15551234567" {
		t.Fatalf("got[0] = %+v", got[0])
	}
	if len(inboundTransport.writes) != len(parts) {
		t.Fatalf("len(inboundTransport.writes) = %d, want %d", len(inboundTransport.writes), len(parts))
	}
	if len(transport.writes) != len(parts) {
		t.Fatalf("len(transport.writes) = %d, want %d", len(transport.writes), len(parts))
	}
}

func TestSendMultipartSMS(t *testing.T) {
	transport := newClientUDPTransport()
	inboundTransport := newInboundUDPTransport()
	client := newTestClient(t, Config{}, transport)
	text := strings.Repeat("A", 200)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	transport.onWrite = func(data []byte) {
		req, err := ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage(request) error = %v", err)
			return
		}
		resp := newTestResponse(req, 202, "Accepted")
		go client.dispatchResponse(resp)
		if req.Method() != "MESSAGE" || len(req.Body) < 2 {
			return
		}
		rpRef := req.Body[1]
		go func() {
			time.Sleep(10 * time.Millisecond)
			ack := newSMSNetworkRequest(client.cfg.PublicIdentity, "z9hG4bK-sms-ack", fmt.Sprintf("sms-ack-%d", rpRef), fmt.Sprintf("%d MESSAGE", rpRef), []byte{rpAckNetworkToMS, rpRef})
			if err := client.handleRequest(context.Background(), inboundTransport, ack); err != nil {
				t.Errorf("handleRequest(rp-ack) error = %v", err)
			}
		}()
	}
	if err := client.SendSMS(ctx, "777", text); err != nil {
		t.Fatalf("SendSMS() error = %v", err)
	}
	if len(transport.writes) < 2 {
		t.Fatalf("len(transport.writes) = %d, want >= 2", len(transport.writes))
	}
}
