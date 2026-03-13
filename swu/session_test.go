package swu

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/damonto/ims-client/usim"
)

type testCard struct {
	imsi string
	mcc  string
	mnc  string
	aka  usim.AKAResult
	rand []byte
	autn []byte
}

func (c testCard) IMSI() string { return c.imsi }
func (c testCard) MCC() string  { return c.mcc }
func (c testCard) MNC() string  { return c.mnc }

func (c testCard) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	select {
	case <-ctx.Done():
		return usim.AKAResult{}, ctx.Err()
	default:
	}
	if c.rand != nil && !bytes.Equal(rand, c.rand) {
		return usim.AKAResult{}, fmt.Errorf("aka rand = %x, want %x", rand, c.rand)
	}
	if c.autn != nil && !bytes.Equal(autn, c.autn) {
		return usim.AKAResult{}, fmt.Errorf("aka autn = %x, want %x", autn, c.autn)
	}
	return c.aka, nil
}

type sequenceCard struct {
	imsi    string
	mcc     string
	mnc     string
	results []usim.AKAResult
	rands   [][]byte
	autns   [][]byte
	calls   int
}

func (c *sequenceCard) IMSI() string { return c.imsi }
func (c *sequenceCard) MCC() string  { return c.mcc }
func (c *sequenceCard) MNC() string  { return c.mnc }

func (c *sequenceCard) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	select {
	case <-ctx.Done():
		return usim.AKAResult{}, ctx.Err()
	default:
	}
	if c.calls >= len(c.results) {
		return usim.AKAResult{}, fmt.Errorf("aka call %d out of range", c.calls)
	}
	if len(c.rands) > c.calls && c.rands[c.calls] != nil && !bytes.Equal(rand, c.rands[c.calls]) {
		return usim.AKAResult{}, fmt.Errorf("aka rand[%d] = %x, want %x", c.calls, rand, c.rands[c.calls])
	}
	if len(c.autns) > c.calls && c.autns[c.calls] != nil && !bytes.Equal(autn, c.autns[c.calls]) {
		return usim.AKAResult{}, fmt.Errorf("aka autn[%d] = %x, want %x", c.calls, autn, c.autns[c.calls])
	}
	result := c.results[c.calls]
	c.calls++
	return result, nil
}

const testResponderSPI = 0x0102030405060708

func mustListenUDP4(t *testing.T, name string) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket(%s): %v", name, err)
	}
	return conn
}

func mustUnmarshalIKEPacket(t *testing.T, label string, data []byte) IKEPacket {
	t.Helper()
	var packet IKEPacket
	if err := packet.UnmarshalBinary(data); err != nil {
		t.Fatalf("IKEPacket.UnmarshalBinary(%s): %v", label, err)
	}
	return packet
}

func mustUnmarshalAKAMessage(t *testing.T, label string, data []byte) AKAMessage {
	t.Helper()
	var message AKAMessage
	if err := message.UnmarshalBinary(data); err != nil {
		t.Fatalf("AKAMessage.UnmarshalBinary(%s): %v", label, err)
	}
	return message
}

func mustSealIKE(t *testing.T, label string, crypto *ikeCrypto, header IKEHeader, payloads []Payload) []byte {
	t.Helper()
	wire, err := crypto.SealIKE(header, payloads, false)
	if err != nil {
		t.Fatalf("SealIKE(%s): %v", label, err)
	}
	return wire
}

func testIKESAInitResponse(initiatorSPI uint64, publicKey, responderNonce []byte) IKEPacket {
	return testIKESAInitResponseForGroup(initiatorSPI, transformDH1024MODP, publicKey, responderNonce)
}

func testIKESAInitResponseForGroup(initiatorSPI uint64, dhGroup uint16, publicKey, responderNonce []byte) IKEPacket {
	return IKEPacket{
		Header: IKEHeader{InitiatorSPI: initiatorSPI, ResponderSPI: testResponderSPI, Version: ikeVersion20, ExchangeType: exchangeTypeIKESAInit, Flags: flagResponse, MessageID: 0},
		Payloads: []Payload{
			&SecurityAssociationPayload{Proposals: []Proposal{{ProtocolID: proposalProtocolIKE, Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 128)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA196}, {TransformType: transformTypePRF, ID: transformPRFHMACSHA1}, {TransformType: transformTypeDH, ID: dhGroup}}}}},
			&KeyExchangePayload{DHGroup: dhGroup, Data: publicKey},
			&NoncePayload{Data: responderNonce},
		},
	}
}

func testIKEAuthResponseHeader(initiatorSPI uint64, messageID uint32) IKEHeader {
	return IKEHeader{
		InitiatorSPI: initiatorSPI,
		ResponderSPI: testResponderSPI,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeIKEAuth,
		Flags:        flagResponse,
		MessageID:    messageID,
	}
}

func testAKAChallengeAttributes(rand, autn []byte) []AKAAttribute {
	return []AKAAttribute{
		{Type: akaAttrRAND, Value: append([]byte{0x00, 0x00}, rand...)},
		{Type: akaAttrAUTN, Value: append([]byte{0x00, 0x00}, autn...)},
	}
}

func buildTestAKAChallenge(identifier byte, rand, autn, autKey []byte) ([]byte, error) {
	return buildAKAMessage(eapCodeRequest, identifier, akaSubtypeChallenge, testAKAChallengeAttributes(rand, autn), autKey, nil)
}

func TestDial(t *testing.T) {
	tests := []struct {
		name    string
		ctx     func() (context.Context, context.CancelFunc)
		cfg     Config
		check   func(t *testing.T, session *Session)
		wantErr string
	}{
		{
			name: "uses provided packet conn",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			cfg: Config{
				RemoteAddr: "127.0.0.1:500",
				NATTPort:   4500,
				PacketConn: &recordPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}},
			},
			check: func(t *testing.T, session *Session) {
				t.Helper()
				if !session.outerRemote.IP.Equal(net.IPv4(127, 0, 0, 1)) || session.outerRemote.Port != 500 {
					t.Fatalf("outerRemote = %v", session.outerRemote)
				}
				if !session.outerNAT.IP.Equal(net.IPv4(127, 0, 0, 1)) || session.outerNAT.Port != 4500 {
					t.Fatalf("outerNAT = %v", session.outerNAT)
				}
				if session.owned {
					t.Fatal("owned = true, want false")
				}
			},
		},
		{
			name: "canceled context",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
			cfg:     Config{RemoteAddr: "127.0.0.1:500", PacketConn: &recordPacketConn{}},
			wantErr: context.Canceled.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := tt.ctx()
			defer cancel()
			session, err := Dial(ctx, tt.cfg)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Dial() error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			defer session.Close()
			if tt.check != nil {
				tt.check(t, session)
			}
		})
	}
}

func TestSessionConnectAndDataPlane(t *testing.T) {
	initConn := mustListenUDP4(t, "init")
	defer initConn.Close()
	natConn := mustListenUDP4(t, "nat")
	defer natConn.Close()

	challengeRAND := bytes.Repeat([]byte{0x10}, 16)
	challengeAUTN := bytes.Repeat([]byte{0x20}, 16)
	card := testCard{
		imsi: "001010123456789",
		mcc:  "001",
		mnc:  "01",
		rand: challengeRAND,
		autn: challengeAUTN,
		aka: usim.AKAResult{
			RES: []byte{0x11, 0x22, 0x33, 0x44},
			IK:  bytes.Repeat([]byte{0x33}, 16),
			CK:  bytes.Repeat([]byte{0x44}, 16),
		},
	}

	serverErr := make(chan error, 1)
	go runTestEPDG(serverErr, initConn, natConn, card)

	natAddr := natConn.LocalAddr().(*net.UDPAddr)
	session, err := Dial(context.Background(), Config{
		RemoteAddr:   initConn.LocalAddr().String(),
		NATTPort:     natAddr.Port,
		LocalSIPPort: 5062,
		SIPPort:      5060,
	})
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := session.Connect(ctx, "356789012345678", card); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	if got := session.LocalAddr().String(); got != "10.0.0.10:5062" {
		t.Fatalf("LocalAddr() = %q, want %q", got, "10.0.0.10:5062")
	}
	if got := session.RemoteAddr().String(); got != "10.0.0.1:5060" {
		t.Fatalf("RemoteAddr() = %q, want %q", got, "10.0.0.1:5060")
	}
	if session.livenessTimeout != 30*time.Second {
		t.Fatalf("livenessTimeout = %v, want %v", session.livenessTimeout, 30*time.Second)
	}
	if err := session.WritePacket(ctx, []byte("REGISTER sip:ims.test SIP/2.0\r\n\r\n")); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	payload, addr, err := session.ReadPacket(ctx)
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if !bytes.Equal(payload, []byte("SIP/2.0 200 OK\r\n\r\n")) {
		t.Fatalf("ReadPacket() payload = %q", string(payload))
	}
	if got := addr.String(); got != "10.0.0.1:5060" {
		t.Fatalf("ReadPacket() addr = %q, want %q", got, "10.0.0.1:5060")
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not finish")
	}
}

func runTestEPDG(errCh chan<- error, initConn, natConn net.PacketConn, card testCard) {
	errCh <- runTestEPDGOnce(initConn, natConn, card)
}

func runTestEPDGOnce(initConn, natConn net.PacketConn, card testCard) error {
	buf := make([]byte, 64*1024)
	initConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, clientInitAddr, err := initConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("reading sa_init request: %w", err)
	}
	saInitReqRaw := append([]byte(nil), buf[:n]...)
	var saInitReq IKEPacket
	if err := saInitReq.UnmarshalBinary(saInitReqRaw); err != nil {
		return fmt.Errorf("parsing sa_init request: %w", err)
	}
	nonce := findNoncePayload(saInitReq.Payloads)
	ke := findKEPayload(saInitReq.Payloads, transformDH1024MODP)
	if nonce == nil || ke == nil {
		return fmt.Errorf("sa_init request missing nonce or ke")
	}
	serverCrypto, err := newIKECrypto(transformDH1024MODP)
	if err != nil {
		return fmt.Errorf("creating server crypto: %w", err)
	}
	serverCrypto.SetProposal(transformENCRAESCBC, 128, transformINTEGHMACSHA196, transformPRFHMACSHA1)
	serverCrypto.SetSPIs(saInitReq.Header.InitiatorSPI, testResponderSPI)
	responderNonce := bytes.Repeat([]byte{0x22}, 16)
	serverCrypto.SetNonces(nonce.Data, responderNonce)
	if err := serverCrypto.DeriveIKEKeys(ke.Data); err != nil {
		return fmt.Errorf("deriving server ike keys: %w", err)
	}
	responseRaw, err := testIKESAInitResponse(saInitReq.Header.InitiatorSPI, serverCrypto.PublicKey(), responderNonce).MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshalling sa_init response: %w", err)
	}
	if _, err := initConn.WriteTo(responseRaw, clientInitAddr); err != nil {
		return fmt.Errorf("writing sa_init response: %w", err)
	}

	natConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, clientNATAddr, err := natConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("reading ike_auth init request: %w", err)
	}
	if !hasNonESPMarker(buf[:n]) {
		return fmt.Errorf("ike_auth init request missing non-esp marker")
	}
	var ikeAuthInit IKEPacket
	if err := ikeAuthInit.UnmarshalBinary(buf[4:n]); err != nil {
		return fmt.Errorf("parsing ike_auth init request: %w", err)
	}
	ikeAuthPayloads, err := serverCrypto.OpenIKE(ikeAuthInit, true)
	if err != nil {
		return fmt.Errorf("opening ike_auth init request: %w", err)
	}
	idi := findIDPayload(ikeAuthPayloads, payloadTypeIDi)
	childSA := findSAPayload(ikeAuthPayloads)
	if idi == nil || childSA == nil || len(childSA.Proposals) == 0 || len(childSA.Proposals[0].SPI) != 4 {
		return fmt.Errorf("ike_auth init request missing idi or child sa")
	}
	if notify := findNotifyPayload(ikeAuthPayloads, notifyTypeDeviceIdentity); notify != nil {
		return fmt.Errorf("ike_auth init request unexpectedly included device identity")
	}
	clientESPSPI := binary.BigEndian.Uint32(childSA.Proposals[0].SPI)
	if err := serverCrypto.DeriveEAPKeys(idi.Data, card.aka.RES, card.aka.IK, card.aka.CK); err != nil {
		return fmt.Errorf("deriving server eap keys: %w", err)
	}
	challengeRaw, err := buildTestAKAChallenge(0x09, card.rand, card.autn, serverCrypto.EAPAuthKey())
	if err != nil {
		return fmt.Errorf("marshalling aka challenge: %w", err)
	}
	challengeResp, err := serverCrypto.SealIKE(testIKEAuthResponseHeader(saInitReq.Header.InitiatorSPI, 1), []Payload{&EAPPayload{Data: challengeRaw}}, false)
	if err != nil {
		return fmt.Errorf("sealing aka challenge: %w", err)
	}
	if _, err := natConn.WriteTo(append([]byte{0, 0, 0, 0}, challengeResp...), clientNATAddr); err != nil {
		return fmt.Errorf("writing aka challenge: %w", err)
	}

	natConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = natConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("reading aka response: %w", err)
	}
	var akaResponse IKEPacket
	if err := akaResponse.UnmarshalBinary(buf[4:n]); err != nil {
		return fmt.Errorf("parsing aka response: %w", err)
	}
	akaPayloads, err := serverCrypto.OpenIKE(akaResponse, true)
	if err != nil {
		return fmt.Errorf("opening aka response: %w", err)
	}
	eapPayload := findEAPPayload(akaPayloads)
	if eapPayload == nil {
		return fmt.Errorf("aka response missing eap payload")
	}
	wantAKAResponse, err := BuildAKAResponse(0x09, card.aka.RES, serverCrypto.EAPAuthKey())
	if err != nil {
		return fmt.Errorf("building expected aka response: %w", err)
	}
	if !bytes.Equal(eapPayload.Data, wantAKAResponse) {
		return fmt.Errorf("aka response mismatch")
	}
	eapSuccess, err := (EAPPacket{Code: eapCodeSuccess, Identifier: 0x09}).MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshalling eap success: %w", err)
	}
	eapSuccessResp, err := serverCrypto.SealIKE(testIKEAuthResponseHeader(saInitReq.Header.InitiatorSPI, 2), []Payload{&EAPPayload{Data: eapSuccess}}, false)
	if err != nil {
		return fmt.Errorf("sealing eap success: %w", err)
	}
	if _, err := natConn.WriteTo(append([]byte{0, 0, 0, 0}, eapSuccessResp...), clientNATAddr); err != nil {
		return fmt.Errorf("writing eap success: %w", err)
	}

	natConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = natConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("reading final auth request: %w", err)
	}
	var finalAuth IKEPacket
	if err := finalAuth.UnmarshalBinary(buf[4:n]); err != nil {
		return fmt.Errorf("parsing final auth request: %w", err)
	}
	finalAuthPayloads, err := serverCrypto.OpenIKE(finalAuth, true)
	if err != nil {
		return fmt.Errorf("opening final auth request: %w", err)
	}
	auth, ok := finalAuthPayloads[0].(*AuthPayload)
	if !ok {
		return fmt.Errorf("final auth payload type = %T", finalAuthPayloads[0])
	}
	wantAuth, err := serverCrypto.ComputeInitiatorAuth(saInitReqRaw, responderNonce, idi.RawData())
	if err != nil {
		return fmt.Errorf("computing expected auth: %w", err)
	}
	if !bytes.Equal(auth.Data, wantAuth) {
		return fmt.Errorf("final auth mismatch")
	}

	responderESPSPI := uint32(0xaabbccdd)
	finalResp, err := serverCrypto.SealIKE(testIKEAuthResponseHeader(saInitReq.Header.InitiatorSPI, 3), []Payload{
		&ConfigPayload{ConfigType: configTypeReply, Attributes: []Attribute{NewTLVAttribute(configAttrInternalIPv4Address, []byte{10, 0, 0, 10}), NewTLVAttribute(configAttrPCSCFIPv4Address, []byte{10, 0, 0, 1}), NewTLVAttribute(configAttrTimeoutPeriodForLivenessCheck, []byte{0, 0, 0, 30})}},
		&SecurityAssociationPayload{Proposals: []Proposal{{ProtocolID: proposalProtocolESP, SPI: uint32Bytes(responderESPSPI), Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 128)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA196}, {TransformType: transformTypeESN, ID: 0}}}}},
	}, false)
	if err != nil {
		return fmt.Errorf("sealing final auth response: %w", err)
	}
	if _, err := natConn.WriteTo(append([]byte{0, 0, 0, 0}, finalResp...), clientNATAddr); err != nil {
		return fmt.Errorf("writing final auth response: %w", err)
	}

	espKeys, err := serverCrypto.DeriveESPKeys(128, transformINTEGHMACSHA196)
	if err != nil {
		return fmt.Errorf("deriving esp keys: %w", err)
	}
	inbound := ESPCodec{SPI: clientESPSPI, Encryption: EncryptionAESCBC, Integrity: IntegrityHMACSHA196, EncryptionKey: espKeys.EncryptionInitiator, IntegrityKey: espKeys.IntegrityInitiator}
	outbound := ESPCodec{SPI: responderESPSPI, Encryption: EncryptionAESCBC, Integrity: IntegrityHMACSHA196, EncryptionKey: espKeys.EncryptionResponder, IntegrityKey: espKeys.IntegrityResponder}

	natConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = natConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("reading esp data: %w", err)
	}
	espPacket, err := inbound.Decode(buf[:n])
	if err != nil {
		return fmt.Errorf("decoding esp data: %w", err)
	}
	payload, peer, err := decodeInnerUDPPacket(espPacket.Payload, espPacket.NextHeader, 5060)
	if err != nil {
		return fmt.Errorf("parsing inner udp packet: %w", err)
	}
	if got := peer.String(); got != "10.0.0.10:5062" {
		return fmt.Errorf("peer addr = %q, want %q", got, "10.0.0.10:5062")
	}
	if !bytes.Equal(payload, []byte("REGISTER sip:ims.test SIP/2.0\r\n\r\n")) {
		return fmt.Errorf("unexpected client payload %q", string(payload))
	}
	innerResp, nextHeader, err := buildInnerUDPPacket(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5060}, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 10), Port: 5062}, []byte("SIP/2.0 200 OK\r\n\r\n"))
	if err != nil {
		return fmt.Errorf("building inner udp response: %w", err)
	}
	sealed, err := outbound.Encode(ESPPacket{SPI: responderESPSPI, Sequence: 1, NextHeader: nextHeader, Payload: innerResp})
	if err != nil {
		return fmt.Errorf("encoding esp response: %w", err)
	}
	if _, err := natConn.WriteTo(sealed, clientNATAddr); err != nil {
		return fmt.Errorf("writing esp response: %w", err)
	}
	return nil
}

type scriptedRead struct {
	data []byte
	addr net.Addr
	err  error
}

type scriptedPacketConn struct {
	localAddr net.Addr
	reads     []scriptedRead
}

func (c *scriptedPacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	if len(c.reads) == 0 {
		return 0, nil, fmt.Errorf("ReadFrom() exhausted")
	}
	read := c.reads[0]
	c.reads = c.reads[1:]
	if read.err != nil {
		return 0, nil, read.err
	}
	copy(buf, read.data)
	return len(read.data), read.addr, nil
}

func (c *scriptedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) { return len(p), nil }
func (c *scriptedPacketConn) Close() error                                 { return nil }
func (c *scriptedPacketConn) LocalAddr() net.Addr {
	if c.localAddr != nil {
		return c.localAddr
	}
	return &net.UDPAddr{IP: net.IPv4zero, Port: 4500}
}
func (c *scriptedPacketConn) SetDeadline(_ time.Time) error      { return nil }
func (c *scriptedPacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *scriptedPacketConn) SetWriteDeadline(_ time.Time) error { return nil }

type exchangePacketConn struct {
	mu        sync.Mutex
	localAddr net.Addr
	reads     []scriptedRead
	writes    [][]byte
	writeAddr []net.Addr
}

func (c *exchangePacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	if len(c.reads) == 0 {
		return 0, nil, fmt.Errorf("ReadFrom() exhausted")
	}
	read := c.reads[0]
	c.reads = c.reads[1:]
	if read.err != nil {
		return 0, nil, read.err
	}
	copy(buf, read.data)
	return len(read.data), read.addr, nil
}

func (c *exchangePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.writeAddr = append(c.writeAddr, addr)
	return len(p), nil
}

func (c *exchangePacketConn) Close() error { return nil }
func (c *exchangePacketConn) LocalAddr() net.Addr {
	if c.localAddr != nil {
		return c.localAddr
	}
	return &net.UDPAddr{IP: net.IPv4zero, Port: 4500}
}
func (c *exchangePacketConn) SetDeadline(_ time.Time) error      { return nil }
func (c *exchangePacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *exchangePacketConn) SetWriteDeadline(_ time.Time) error { return nil }

type recordPacketConn struct {
	mu        sync.Mutex
	localAddr net.Addr
	writes    [][]byte
	writeAddr []net.Addr
}

func (c *recordPacketConn) ReadFrom(_ []byte) (int, net.Addr, error) {
	return 0, nil, fmt.Errorf("ReadFrom() should not be called")
}

func (c *recordPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.writeAddr = append(c.writeAddr, addr)
	return len(p), nil
}

func (c *recordPacketConn) Close() error { return nil }

func (c *recordPacketConn) LocalAddr() net.Addr {
	if c.localAddr != nil {
		return c.localAddr
	}
	return &net.UDPAddr{IP: net.IPv4zero, Port: 4500}
}

func (c *recordPacketConn) SetDeadline(_ time.Time) error      { return nil }
func (c *recordPacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *recordPacketConn) SetWriteDeadline(_ time.Time) error { return nil }

func (c *recordPacketConn) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.writes)
}

func TestExchangeIKE(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 4500}
	response, err := (IKEPacket{Header: IKEHeader{InitiatorSPI: 1, ResponderSPI: 2, Version: ikeVersion20, ExchangeType: exchangeTypeInformational, Flags: flagResponse, MessageID: 7}}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(response) error = %v", err)
	}
	tests := []struct {
		name      string
		nat       bool
		wantWrite []byte
	}{
		{name: "plain ike", nat: false, wantWrite: []byte{0x01, 0x02, 0x03}},
		{name: "natt ike", nat: true, wantWrite: []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &exchangePacketConn{reads: []scriptedRead{{data: append([]byte{0x00, 0x00, 0x00, 0x00}, response...), addr: peer}}}
			session := &Session{conn: conn, logger: testLogger()}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, addr, err := session.exchangeIKE(ctx, peer, []byte{0x01, 0x02, 0x03}, tt.nat, 7)
			if err != nil {
				t.Fatalf("exchangeIKE() error = %v", err)
			}
			if !bytes.Equal(got, response) {
				t.Fatalf("exchangeIKE() response mismatch")
			}
			if addr == nil || addr.String() != peer.String() {
				t.Fatalf("exchangeIKE() addr = %v, want %v", addr, peer)
			}
			if len(conn.writes) != 1 {
				t.Fatalf("len(conn.writes) = %d, want 1", len(conn.writes))
			}
			if !bytes.Equal(conn.writes[0], tt.wantWrite) {
				t.Fatalf("write = %v, want %v", conn.writes[0], tt.wantWrite)
			}
		})
	}
}

func TestExchangeIKESAInitRetriesWithResponderDHGroup(t *testing.T) {
	state, err := newConnectState("356789012345678", testCard{imsi: "001010123456789", mcc: "001", mnc: "01"})
	if err != nil {
		t.Fatalf("newConnectState() error = %v", err)
	}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 500}
	serverCrypto, err := newIKECrypto(transformDH2048MODP)
	if err != nil {
		t.Fatalf("newIKECrypto() error = %v", err)
	}
	responderNonce := bytes.Repeat([]byte{0x44}, 16)
	notifyData := make([]byte, 2)
	binary.BigEndian.PutUint16(notifyData, transformDH2048MODP)
	invalidKE, err := (IKEPacket{
		Header: IKEHeader{InitiatorSPI: state.initiatorSPI, ResponderSPI: testResponderSPI, Version: ikeVersion20, ExchangeType: exchangeTypeIKESAInit, Flags: flagResponse, MessageID: 0},
		Payloads: []Payload{
			&NotifyPayload{NotifyType: notifyTypeInvalidKEPayload, Data: notifyData},
		},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(INVALID_KE_PAYLOAD) error = %v", err)
	}
	valid, err := testIKESAInitResponseForGroup(state.initiatorSPI, transformDH2048MODP, serverCrypto.PublicKey(), responderNonce).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(valid SA_INIT) error = %v", err)
	}
	conn := &exchangePacketConn{
		reads: []scriptedRead{
			{data: invalidKE, addr: peer},
			{data: valid, addr: peer},
		},
	}
	session := &Session{conn: conn, logger: testLogger(), outerRemote: peer}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := session.exchangeIKESAInit(ctx, state); err != nil {
		t.Fatalf("exchangeIKESAInit() error = %v", err)
	}
	if len(conn.writes) != 2 {
		t.Fatalf("len(conn.writes) = %d, want 2", len(conn.writes))
	}
	firstReq := mustUnmarshalIKEPacket(t, "sa-init-1", conn.writes[0])
	secondReq := mustUnmarshalIKEPacket(t, "sa-init-2", conn.writes[1])
	if ke := findKEPayload(firstReq.Payloads, 0); ke == nil || ke.DHGroup != transformDH1024MODP {
		t.Fatalf("first request KE = %+v, want group %d", ke, transformDH1024MODP)
	}
	if ke := findKEPayload(secondReq.Payloads, 0); ke == nil || ke.DHGroup != transformDH2048MODP {
		t.Fatalf("second request KE = %+v, want group %d", ke, transformDH2048MODP)
	}
	if state.crypto.dhGroup != transformDH2048MODP {
		t.Fatalf("state.crypto.dhGroup = %d, want %d", state.crypto.dhGroup, transformDH2048MODP)
	}
}

func TestReadIKEMessage(t *testing.T) {
	_, responder := newInformationalIKEPair(t)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 4500}
	target := mustSealIKE(t, "target", responder, IKEHeader{InitiatorSPI: 1, ResponderSPI: 2, Version: ikeVersion20, ExchangeType: exchangeTypeInformational, Flags: flagResponse, MessageID: 7}, nil)
	tests := []struct {
		name  string
		reads []scriptedRead
		want  []byte
	}{
		{
			name: "skips malformed and mismatched message ids",
			reads: []scriptedRead{
				{data: []byte{0x00, 0x01}, addr: peer},
				{data: mustSealIKE(t, "mismatch", responder, IKEHeader{InitiatorSPI: 1, ResponderSPI: 2, Version: ikeVersion20, ExchangeType: exchangeTypeInformational, Flags: flagResponse, MessageID: 6}, nil), addr: peer},
				{data: append([]byte{0x00, 0x00, 0x00, 0x00}, target...), addr: peer},
			},
			want: target,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{conn: &scriptedPacketConn{reads: append([]scriptedRead(nil), tt.reads...)}, logger: testLogger()}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, addr, err := session.readIKEMessage(ctx, 7, time.Second)
			if err != nil {
				t.Fatalf("readIKEMessage() error = %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("readIKEMessage() packet mismatch")
			}
			if addr == nil || addr.String() != peer.String() {
				t.Fatalf("readIKEMessage() addr = %v, want %v", addr, peer)
			}
		})
	}
}

func TestHandleIKEPacket(t *testing.T) {
	initiator, err := newIKECrypto(transformDH1024MODP)
	if err != nil {
		t.Fatalf("newIKECrypto(initiator) error = %v", err)
	}
	responder, err := newIKECrypto(transformDH1024MODP)
	if err != nil {
		t.Fatalf("newIKECrypto(responder) error = %v", err)
	}
	initiator.SetProposal(transformENCRAESCBC, 128, transformINTEGHMACSHA196, transformPRFHMACSHA1)
	responder.SetProposal(transformENCRAESCBC, 128, transformINTEGHMACSHA196, transformPRFHMACSHA1)
	initiator.SetSPIs(1, 2)
	responder.SetSPIs(1, 2)
	nonceI := bytes.Repeat([]byte{0x11}, 16)
	nonceR := bytes.Repeat([]byte{0x22}, 16)
	initiator.SetNonces(nonceI, nonceR)
	responder.SetNonces(nonceI, nonceR)
	if err := initiator.DeriveIKEKeys(responder.PublicKey()); err != nil {
		t.Fatalf("DeriveIKEKeys(initiator) error = %v", err)
	}
	if err := responder.DeriveIKEKeys(initiator.PublicKey()); err != nil {
		t.Fatalf("DeriveIKEKeys(responder) error = %v", err)
	}

	tests := []struct {
		name         string
		request      []Payload
		deviceID     string
		wantPayloads int
		check        func(t *testing.T, payloads []Payload)
	}{
		{
			name:         "dpd",
			request:      nil,
			deviceID:     "356789012345678",
			wantPayloads: 0,
		},
		{
			name: "device identity",
			request: []Payload{
				&NotifyPayload{ProtocolID: 0, NotifyType: notifyTypeDeviceIdentity, Data: []byte{0x00, 0x01, deviceIdentityIMEI}},
			},
			deviceID:     "356789012345678",
			wantPayloads: 1,
			check: func(t *testing.T, payloads []Payload) {
				t.Helper()
				notify := findNotifyPayload(payloads, notifyTypeDeviceIdentity)
				if notify == nil {
					t.Fatal("findNotifyPayload() = nil, want device identity")
				}
				identityType, value, err := decodeDeviceIdentity(notify.Data)
				if err != nil {
					t.Fatalf("decodeDeviceIdentity() error = %v", err)
				}
				if identityType != deviceIdentityIMEI {
					t.Fatalf("identityType = %d, want %d", identityType, deviceIdentityIMEI)
				}
				if len(value) == 0 {
					t.Fatal("len(value) = 0, want non-zero")
				}
			},
		},
		{
			name: "config reply",
			request: []Payload{
				&ConfigPayload{ConfigType: configTypeRequest, Attributes: []Attribute{NewTLVAttribute(configAttrPCSCFIPv4Address, []byte{10, 0, 0, 1})}},
			},
			deviceID:     "356789012345678",
			wantPayloads: 1,
			check: func(t *testing.T, payloads []Payload) {
				t.Helper()
				config := findConfigPayload(payloads)
				if config == nil {
					t.Fatal("findConfigPayload() = nil, want cfg reply")
				}
				if config.ConfigType != configTypeReply {
					t.Fatalf("ConfigType = %d, want %d", config.ConfigType, configTypeReply)
				}
				if len(config.Attributes) != 1 || config.Attributes[0].Type != configAttrPCSCFIPv4Address || len(config.Attributes[0].Value) != 0 {
					t.Fatalf("config.Attributes = %+v", config.Attributes)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &recordPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			session := &Session{
				conn:           conn,
				logger:         testLogger(),
				outerNAT:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 4500},
				closeCtx:       ctx,
				closeCancel:    cancel,
				ike:            initiator,
				initiatorSPI:   1,
				responderSPI:   2,
				deviceIdentity: tt.deviceID,
			}
			header := IKEHeader{InitiatorSPI: 1, ResponderSPI: 2, Version: ikeVersion20, ExchangeType: exchangeTypeInformational, MessageID: 7}
			request := mustSealIKE(t, "request", responder, header, tt.request)
			handled, err := session.handleIKEPacket(request, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 4500})
			if err != nil {
				t.Fatalf("handleIKEPacket() error = %v", err)
			}
			if !handled {
				t.Fatal("handleIKEPacket() = false, want true")
			}
			if len(conn.writes) != 1 {
				t.Fatalf("len(writes) = %d, want 1", len(conn.writes))
			}
			if !hasNonESPMarker(conn.writes[0]) {
				t.Fatal("response missing non-esp marker")
			}
			packet := mustUnmarshalIKEPacket(t, "response", conn.writes[0][4:])
			payloads, err := responder.OpenIKE(packet, true)
			if err != nil {
				t.Fatalf("OpenIKE(response) error = %v", err)
			}
			if len(payloads) != tt.wantPayloads {
				t.Fatalf("len(payloads) = %d, want %d", len(payloads), tt.wantPayloads)
			}
			if tt.check != nil {
				tt.check(t, payloads)
			}
		})
	}
}

func TestParseChildSAAndConfig(t *testing.T) {
	tests := []struct {
		name     string
		payloads []Payload
		want     TunnelInfo
		wantErr  string
	}{
		{
			name: "ipv4 success",
			payloads: []Payload{
				&ConfigPayload{ConfigType: configTypeReply, Attributes: []Attribute{NewTLVAttribute(configAttrInternalIPv4Address, []byte{10, 0, 0, 10}), NewTLVAttribute(configAttrPCSCFIPv4Address, []byte{10, 0, 0, 1})}},
				&SecurityAssociationPayload{Proposals: []Proposal{{ProtocolID: proposalProtocolESP, SPI: uint32Bytes(0x11223344), Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 128)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA196}}}}},
			},
			want: TunnelInfo{InnerIP: net.IPv4(10, 0, 0, 10).To4(), PCSCFIP: net.IPv4(10, 0, 0, 1).To4(), ESPResponderSPI: 0x11223344, Encryption: transformENCRAESCBC, EncryptionKeyLen: 128, Integrity: transformINTEGHMACSHA196},
		},
		{
			name: "ipv6 success",
			payloads: []Payload{
				&ConfigPayload{ConfigType: configTypeReply, Attributes: []Attribute{NewTLVAttribute(configAttrInternalIPv6Address, net.ParseIP("2001:db8::10").To16()), NewTLVAttribute(configAttrPCSCFIPv6Address, net.ParseIP("2001:db8::1").To16())}},
				&SecurityAssociationPayload{Proposals: []Proposal{{ProtocolID: proposalProtocolESP, SPI: uint32Bytes(0x55667788), Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 256)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA256}}}}},
			},
			want: TunnelInfo{InnerIP: net.ParseIP("2001:db8::10").To16(), PCSCFIP: net.ParseIP("2001:db8::1").To16(), ESPResponderSPI: 0x55667788, Encryption: transformENCRAESCBC, EncryptionKeyLen: 256, Integrity: transformINTEGHMACSHA256},
		},
		{
			name: "invalid spi length",
			payloads: []Payload{
				&ConfigPayload{ConfigType: configTypeReply, Attributes: []Attribute{NewTLVAttribute(configAttrInternalIPv4Address, []byte{10, 0, 0, 10}), NewTLVAttribute(configAttrPCSCFIPv4Address, []byte{10, 0, 0, 1})}},
				&SecurityAssociationPayload{Proposals: []Proposal{{ProtocolID: proposalProtocolESP, SPI: []byte{0x11, 0x22}, Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 128)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA196}}}}},
			},
			wantErr: "invalid responder esp spi length",
		},
		{
			name: "mismatched families",
			payloads: []Payload{
				&ConfigPayload{ConfigType: configTypeReply, Attributes: []Attribute{NewTLVAttribute(configAttrInternalIPv4Address, []byte{10, 0, 0, 10}), NewTLVAttribute(configAttrPCSCFIPv6Address, net.ParseIP("2001:db8::1").To16())}},
				&SecurityAssociationPayload{Proposals: []Proposal{{ProtocolID: proposalProtocolESP, SPI: uint32Bytes(0x11223344), Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 128)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA196}}}}},
			},
			wantErr: "p-cscf and internal ip families do not match",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tunnelInfoFromChildSA(tt.payloads)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("tunnelInfoFromChildSA() error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("tunnelInfoFromChildSA() error = %v", err)
			}
			if got.ESPResponderSPI != tt.want.ESPResponderSPI || got.Encryption != tt.want.Encryption || got.EncryptionKeyLen != tt.want.EncryptionKeyLen || got.Integrity != tt.want.Integrity || !got.InnerIP.Equal(tt.want.InnerIP) || !got.PCSCFIP.Equal(tt.want.PCSCFIP) {
				t.Fatalf("tunnelInfoFromChildSA() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestPrepareConnectValidation(t *testing.T) {
	conn := &recordPacketConn{}
	closedCtx, closedCancel := context.WithCancel(context.Background())
	closedCancel()
	tests := []struct {
		name    string
		session *Session
		imei    string
		card    Card
		wantErr string
	}{
		{name: "nil card", session: &Session{conn: conn, logger: testLogger()}, imei: "356789012345678", wantErr: "card is nil"},
		{name: "empty imei", session: &Session{conn: conn, logger: testLogger()}, card: testCard{imsi: "001010123456789", mcc: "001", mnc: "01"}, wantErr: "imei is empty"},
		{name: "closed session", session: &Session{conn: conn, closeCtx: closedCtx, logger: testLogger()}, imei: "356789012345678", card: testCard{imsi: "001010123456789", mcc: "001", mnc: "01"}, wantErr: "session is closed"},
		{name: "already connected", session: &Session{conn: conn, connected: true, logger: testLogger()}, imei: "356789012345678", card: testCard{imsi: "001010123456789", mcc: "001", mnc: "01"}, wantErr: "already connected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.session.prepareConnect(tt.imei, tt.card)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("prepareConnect() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseLivenessTimeout(t *testing.T) {
	tests := []struct {
		name     string
		payloads []Payload
		want     time.Duration
	}{
		{name: "missing config", want: 0},
		{
			name: "missing attr",
			payloads: []Payload{
				&ConfigPayload{ConfigType: configTypeReply, Attributes: []Attribute{NewTLVAttribute(configAttrPCSCFIPv4Address, []byte{10, 0, 0, 1})}},
			},
			want: 0,
		},
		{
			name: "valid",
			payloads: []Payload{
				&ConfigPayload{ConfigType: configTypeReply, Attributes: []Attribute{NewTLVAttribute(configAttrTimeoutPeriodForLivenessCheck, []byte{0, 0, 0, 45})}},
			},
			want: 45 * time.Second,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := livenessTimeout(tt.payloads); got != tt.want {
				t.Fatalf("livenessTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandleIKEPacketResponseWaiter(t *testing.T) {
	tests := []struct {
		name          string
		corrupt       bool
		wantErr       bool
		wantDelivered bool
	}{
		{name: "valid", wantDelivered: true},
		{name: "invalid auth", corrupt: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initiator, responder := newInformationalIKEPair(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			session := &Session{
				closeCtx:      ctx,
				closeCancel:   cancel,
				logger:        testLogger(),
				ike:           initiator,
				initiatorSPI:  1,
				responderSPI:  2,
				informWaiters: map[uint32]chan inboundIKE{},
			}
			waiter := session.registerInformationalWaiter(7)
			defer session.unregisterInformationalWaiter(7, waiter)

			wire := mustSealIKE(t, "response", responder, IKEHeader{InitiatorSPI: 1, ResponderSPI: 2, Version: ikeVersion20, ExchangeType: exchangeTypeInformational, Flags: flagResponse, MessageID: 7}, nil)
			if tt.corrupt {
				wire[len(wire)-1] ^= 0xFF
			}

			handled, err := session.handleIKEPacket(wire, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500})
			if !handled {
				t.Fatal("handleIKEPacket() = false, want true")
			}
			if tt.wantErr {
				if err == nil {
					t.Fatal("handleIKEPacket() error = nil, want non-nil")
				}
			} else if err != nil {
				t.Fatalf("handleIKEPacket() error = %v", err)
			}

			select {
			case got := <-waiter:
				if !tt.wantDelivered {
					t.Fatal("waiter received unexpected informational response")
				}
				if !bytes.Equal(got.data, wire) {
					t.Fatal("waiter data mismatch")
				}
			case <-time.After(100 * time.Millisecond):
				if tt.wantDelivered {
					t.Fatal("waiter did not receive informational response")
				}
			}
		})
	}
}

func TestSessionConnectAfterAKASynchronizationFailure(t *testing.T) {
	initConn := mustListenUDP4(t, "init")
	defer initConn.Close()
	natConn := mustListenUDP4(t, "nat")
	defer natConn.Close()

	firstRAND := bytes.Repeat([]byte{0x10}, 16)
	firstAUTN := bytes.Repeat([]byte{0x20}, 16)
	secondRAND := bytes.Repeat([]byte{0x30}, 16)
	secondAUTN := bytes.Repeat([]byte{0x40}, 16)
	auts := bytes.Repeat([]byte{0x55}, 14)
	secondAKA := usim.AKAResult{
		RES: []byte{0xAA, 0xBB, 0xCC, 0xDD},
		IK:  bytes.Repeat([]byte{0x77}, 16),
		CK:  bytes.Repeat([]byte{0x88}, 16),
	}
	card := &sequenceCard{
		imsi:    "001010123456789",
		mcc:     "001",
		mnc:     "01",
		rands:   [][]byte{firstRAND, secondRAND},
		autns:   [][]byte{firstAUTN, secondAUTN},
		results: []usim.AKAResult{{AUTS: auts}, secondAKA},
	}

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- runTestEPDGSyncOnce(initConn, natConn, secondAKA, firstRAND, firstAUTN, secondRAND, secondAUTN, auts)
	}()

	natAddr := natConn.LocalAddr().(*net.UDPAddr)
	session, err := Dial(context.Background(), Config{RemoteAddr: initConn.LocalAddr().String(), NATTPort: natAddr.Port, LocalSIPPort: 5062, SIPPort: 5060})
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := session.Connect(ctx, "356789012345678", card); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not finish")
	}
}

func TestSessionConnectAKAAuthenticationReject(t *testing.T) {
	initConn := mustListenUDP4(t, "init")
	defer initConn.Close()
	natConn := mustListenUDP4(t, "nat")
	defer natConn.Close()

	challengeRAND := bytes.Repeat([]byte{0x60}, 16)
	challengeAUTN := bytes.Repeat([]byte{0x70}, 16)
	card := &sequenceCard{
		imsi:    "001010123456789",
		mcc:     "001",
		mnc:     "01",
		rands:   [][]byte{challengeRAND},
		autns:   [][]byte{challengeAUTN},
		results: []usim.AKAResult{{Reject: true}},
	}

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- runTestEPDGRejectOnce(initConn, natConn, challengeRAND, challengeAUTN)
	}()

	natAddr := natConn.LocalAddr().(*net.UDPAddr)
	session, err := Dial(context.Background(), Config{RemoteAddr: initConn.LocalAddr().String(), NATTPort: natAddr.Port, LocalSIPPort: 5062, SIPPort: 5060})
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = session.Connect(ctx, "356789012345678", card)
	if err == nil {
		t.Fatal("Connect() error = nil, want failure")
	}
	if !errors.Is(err, ErrEAPFailure) {
		t.Fatalf("Connect() error = %v, want ErrEAPFailure", err)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not finish")
	}
}

func runTestEPDGSyncOnce(initConn, natConn net.PacketConn, successAKA usim.AKAResult, firstRAND, firstAUTN, secondRAND, secondAUTN, auts []byte) error {
	buf := make([]byte, 64*1024)
	initConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, clientInitAddr, err := initConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("reading sa_init request: %w", err)
	}
	saInitReqRaw := append([]byte(nil), buf[:n]...)
	var saInitReq IKEPacket
	if err := saInitReq.UnmarshalBinary(saInitReqRaw); err != nil {
		return fmt.Errorf("parsing sa_init request: %w", err)
	}
	nonce := findNoncePayload(saInitReq.Payloads)
	ke := findKEPayload(saInitReq.Payloads, transformDH1024MODP)
	if nonce == nil || ke == nil {
		return fmt.Errorf("sa_init request missing nonce or ke")
	}
	serverCrypto, err := newIKECrypto(transformDH1024MODP)
	if err != nil {
		return fmt.Errorf("creating server crypto: %w", err)
	}
	serverCrypto.SetProposal(transformENCRAESCBC, 128, transformINTEGHMACSHA196, transformPRFHMACSHA1)
	serverCrypto.SetSPIs(saInitReq.Header.InitiatorSPI, 0x0102030405060708)
	responderNonce := bytes.Repeat([]byte{0x22}, 16)
	serverCrypto.SetNonces(nonce.Data, responderNonce)
	if err := serverCrypto.DeriveIKEKeys(ke.Data); err != nil {
		return fmt.Errorf("deriving server ike keys: %w", err)
	}
	response := IKEPacket{Header: IKEHeader{InitiatorSPI: saInitReq.Header.InitiatorSPI, ResponderSPI: 0x0102030405060708, Version: ikeVersion20, ExchangeType: exchangeTypeIKESAInit, Flags: flagResponse, MessageID: 0}, Payloads: []Payload{&SecurityAssociationPayload{Proposals: []Proposal{{ProtocolID: proposalProtocolIKE, Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 128)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA196}, {TransformType: transformTypePRF, ID: transformPRFHMACSHA1}, {TransformType: transformTypeDH, ID: transformDH1024MODP}}}}}, &KeyExchangePayload{DHGroup: transformDH1024MODP, Data: serverCrypto.PublicKey()}, &NoncePayload{Data: responderNonce}}}
	responseRaw, err := response.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshalling sa_init response: %w", err)
	}
	if _, err := initConn.WriteTo(responseRaw, clientInitAddr); err != nil {
		return fmt.Errorf("writing sa_init response: %w", err)
	}

	natConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, clientNATAddr, err := natConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("reading ike_auth init request: %w", err)
	}
	var ikeAuthInit IKEPacket
	if err := ikeAuthInit.UnmarshalBinary(buf[4:n]); err != nil {
		return fmt.Errorf("parsing ike_auth init request: %w", err)
	}
	ikeAuthPayloads, err := serverCrypto.OpenIKE(ikeAuthInit, true)
	if err != nil {
		return fmt.Errorf("opening ike_auth init request: %w", err)
	}
	idi := findIDPayload(ikeAuthPayloads, payloadTypeIDi)
	childSA := findSAPayload(ikeAuthPayloads)
	if idi == nil || childSA == nil || len(childSA.Proposals) == 0 || len(childSA.Proposals[0].SPI) != 4 {
		return fmt.Errorf("ike_auth init request missing idi or child sa")
	}
	clientESPSPI := binary.BigEndian.Uint32(childSA.Proposals[0].SPI)
	if err := serverCrypto.DeriveEAPKeys(idi.Data, []byte{0x01, 0x02, 0x03, 0x04}, bytes.Repeat([]byte{0xA1}, 16), bytes.Repeat([]byte{0xB2}, 16)); err != nil {
		return fmt.Errorf("deriving first server eap keys: %w", err)
	}
	challenge1, err := buildTestAKAChallenge(0x09, firstRAND, firstAUTN, serverCrypto.EAPAuthKey())
	if err != nil {
		return fmt.Errorf("marshalling first aka challenge: %w", err)
	}
	challenge1Resp, err := serverCrypto.SealIKE(testIKEAuthResponseHeader(saInitReq.Header.InitiatorSPI, 1), []Payload{&EAPPayload{Data: challenge1}}, false)
	if err != nil {
		return fmt.Errorf("sealing first aka challenge: %w", err)
	}
	if _, err := natConn.WriteTo(append([]byte{0, 0, 0, 0}, challenge1Resp...), clientNATAddr); err != nil {
		return fmt.Errorf("writing first aka challenge: %w", err)
	}

	natConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = natConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("reading synchronization failure response: %w", err)
	}
	var syncResp IKEPacket
	if err := syncResp.UnmarshalBinary(buf[4:n]); err != nil {
		return fmt.Errorf("parsing synchronization failure response: %w", err)
	}
	syncPayloads, err := serverCrypto.OpenIKE(syncResp, true)
	if err != nil {
		return fmt.Errorf("opening synchronization failure response: %w", err)
	}
	syncEAP := findEAPPayload(syncPayloads)
	if syncEAP == nil {
		return fmt.Errorf("synchronization failure response missing eap payload")
	}
	var syncMessage AKAMessage
	if err := syncMessage.UnmarshalBinary(syncEAP.Data); err != nil {
		return fmt.Errorf("parsing synchronization failure message: %w", err)
	}
	if syncMessage.Subtype != akaSubtypeSynchronizationFailure {
		return fmt.Errorf("synchronization failure subtype = %d", syncMessage.Subtype)
	}
	autsAttr := findAKAAttribute(syncMessage.Attributes, akaAttrAUTS)
	if autsAttr == nil || !bytes.Equal(autsAttr.Value, auts) {
		return fmt.Errorf("synchronization failure auts mismatch")
	}

	if err := serverCrypto.DeriveEAPKeys(idi.Data, successAKA.RES, successAKA.IK, successAKA.CK); err != nil {
		return fmt.Errorf("deriving second server eap keys: %w", err)
	}
	challenge2, err := buildTestAKAChallenge(0x0A, secondRAND, secondAUTN, serverCrypto.EAPAuthKey())
	if err != nil {
		return fmt.Errorf("marshalling second aka challenge: %w", err)
	}
	challenge2Resp, err := serverCrypto.SealIKE(testIKEAuthResponseHeader(saInitReq.Header.InitiatorSPI, 2), []Payload{&EAPPayload{Data: challenge2}}, false)
	if err != nil {
		return fmt.Errorf("sealing second aka challenge: %w", err)
	}
	if _, err := natConn.WriteTo(append([]byte{0, 0, 0, 0}, challenge2Resp...), clientNATAddr); err != nil {
		return fmt.Errorf("writing second aka challenge: %w", err)
	}

	natConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = natConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("reading second aka response: %w", err)
	}
	var akaResponse IKEPacket
	if err := akaResponse.UnmarshalBinary(buf[4:n]); err != nil {
		return fmt.Errorf("parsing second aka response: %w", err)
	}
	akaPayloads, err := serverCrypto.OpenIKE(akaResponse, true)
	if err != nil {
		return fmt.Errorf("opening second aka response: %w", err)
	}
	eapPayload := findEAPPayload(akaPayloads)
	if eapPayload == nil {
		return fmt.Errorf("second aka response missing eap payload")
	}
	wantAKAResponse, err := BuildAKAResponse(0x0A, successAKA.RES, serverCrypto.EAPAuthKey())
	if err != nil {
		return fmt.Errorf("building expected second aka response: %w", err)
	}
	if !bytes.Equal(eapPayload.Data, wantAKAResponse) {
		return fmt.Errorf("second aka response mismatch")
	}

	eapSuccess, err := (EAPPacket{Code: eapCodeSuccess, Identifier: 0x0A}).MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshalling eap success: %w", err)
	}
	eapSuccessResp, err := serverCrypto.SealIKE(testIKEAuthResponseHeader(saInitReq.Header.InitiatorSPI, 3), []Payload{&EAPPayload{Data: eapSuccess}}, false)
	if err != nil {
		return fmt.Errorf("sealing eap success: %w", err)
	}
	if _, err := natConn.WriteTo(append([]byte{0, 0, 0, 0}, eapSuccessResp...), clientNATAddr); err != nil {
		return fmt.Errorf("writing eap success: %w", err)
	}

	natConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = natConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("reading final auth request: %w", err)
	}
	var finalAuth IKEPacket
	if err := finalAuth.UnmarshalBinary(buf[4:n]); err != nil {
		return fmt.Errorf("parsing final auth request: %w", err)
	}
	finalAuthPayloads, err := serverCrypto.OpenIKE(finalAuth, true)
	if err != nil {
		return fmt.Errorf("opening final auth request: %w", err)
	}
	auth, ok := finalAuthPayloads[0].(*AuthPayload)
	if !ok {
		return fmt.Errorf("final auth payload type = %T", finalAuthPayloads[0])
	}
	wantAuth, err := serverCrypto.ComputeInitiatorAuth(saInitReqRaw, responderNonce, idi.RawData())
	if err != nil {
		return fmt.Errorf("computing expected auth: %w", err)
	}
	if !bytes.Equal(auth.Data, wantAuth) {
		return fmt.Errorf("final auth mismatch")
	}
	responderESPSPI := uint32(0xAABBCCDD)
	finalResp, err := serverCrypto.SealIKE(testIKEAuthResponseHeader(saInitReq.Header.InitiatorSPI, 4), []Payload{&ConfigPayload{ConfigType: configTypeReply, Attributes: []Attribute{NewTLVAttribute(configAttrInternalIPv4Address, []byte{10, 0, 0, 10}), NewTLVAttribute(configAttrPCSCFIPv4Address, []byte{10, 0, 0, 1})}}, &SecurityAssociationPayload{Proposals: []Proposal{{ProtocolID: proposalProtocolESP, SPI: uint32Bytes(responderESPSPI), Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 128)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA196}, {TransformType: transformTypeESN, ID: 0}}}}}}, false)
	if err != nil {
		return fmt.Errorf("sealing final auth response: %w", err)
	}
	if _, err := natConn.WriteTo(append([]byte{0, 0, 0, 0}, finalResp...), clientNATAddr); err != nil {
		return fmt.Errorf("writing final auth response: %w", err)
	}
	_ = clientESPSPI
	return nil
}

func runTestEPDGRejectOnce(initConn, natConn net.PacketConn, challengeRAND, challengeAUTN []byte) error {
	buf := make([]byte, 64*1024)
	initConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, clientInitAddr, err := initConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("reading sa_init request: %w", err)
	}
	var saInitReq IKEPacket
	if err := saInitReq.UnmarshalBinary(buf[:n]); err != nil {
		return fmt.Errorf("parsing sa_init request: %w", err)
	}
	nonce := findNoncePayload(saInitReq.Payloads)
	ke := findKEPayload(saInitReq.Payloads, transformDH1024MODP)
	if nonce == nil || ke == nil {
		return fmt.Errorf("sa_init request missing nonce or ke")
	}
	serverCrypto, err := newIKECrypto(transformDH1024MODP)
	if err != nil {
		return fmt.Errorf("creating server crypto: %w", err)
	}
	serverCrypto.SetProposal(transformENCRAESCBC, 128, transformINTEGHMACSHA196, transformPRFHMACSHA1)
	serverCrypto.SetSPIs(saInitReq.Header.InitiatorSPI, 0x0102030405060708)
	responderNonce := bytes.Repeat([]byte{0x22}, 16)
	serverCrypto.SetNonces(nonce.Data, responderNonce)
	if err := serverCrypto.DeriveIKEKeys(ke.Data); err != nil {
		return fmt.Errorf("deriving server ike keys: %w", err)
	}
	response := IKEPacket{Header: IKEHeader{InitiatorSPI: saInitReq.Header.InitiatorSPI, ResponderSPI: 0x0102030405060708, Version: ikeVersion20, ExchangeType: exchangeTypeIKESAInit, Flags: flagResponse, MessageID: 0}, Payloads: []Payload{&SecurityAssociationPayload{Proposals: []Proposal{{ProtocolID: proposalProtocolIKE, Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 128)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA196}, {TransformType: transformTypePRF, ID: transformPRFHMACSHA1}, {TransformType: transformTypeDH, ID: transformDH1024MODP}}}}}, &KeyExchangePayload{DHGroup: transformDH1024MODP, Data: serverCrypto.PublicKey()}, &NoncePayload{Data: responderNonce}}}
	responseRaw, err := response.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshalling sa_init response: %w", err)
	}
	if _, err := initConn.WriteTo(responseRaw, clientInitAddr); err != nil {
		return fmt.Errorf("writing sa_init response: %w", err)
	}

	natConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, clientNATAddr, err := natConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("reading ike_auth init request: %w", err)
	}
	var ikeAuthInit IKEPacket
	if err := ikeAuthInit.UnmarshalBinary(buf[4:n]); err != nil {
		return fmt.Errorf("parsing ike_auth init request: %w", err)
	}
	ikeAuthPayloads, err := serverCrypto.OpenIKE(ikeAuthInit, true)
	if err != nil {
		return fmt.Errorf("opening ike_auth init request: %w", err)
	}
	idi := findIDPayload(ikeAuthPayloads, payloadTypeIDi)
	if idi == nil {
		return fmt.Errorf("ike_auth init request missing idi")
	}
	if err := serverCrypto.DeriveEAPKeys(idi.Data, []byte{0x01, 0x02, 0x03, 0x04}, bytes.Repeat([]byte{0xA1}, 16), bytes.Repeat([]byte{0xB2}, 16)); err != nil {
		return fmt.Errorf("deriving server eap keys: %w", err)
	}
	challenge, err := buildTestAKAChallenge(0x09, challengeRAND, challengeAUTN, serverCrypto.EAPAuthKey())
	if err != nil {
		return fmt.Errorf("marshalling aka challenge: %w", err)
	}
	challengeResp, err := serverCrypto.SealIKE(testIKEAuthResponseHeader(saInitReq.Header.InitiatorSPI, 1), []Payload{&EAPPayload{Data: challenge}}, false)
	if err != nil {
		return fmt.Errorf("sealing aka challenge: %w", err)
	}
	if _, err := natConn.WriteTo(append([]byte{0, 0, 0, 0}, challengeResp...), clientNATAddr); err != nil {
		return fmt.Errorf("writing aka challenge: %w", err)
	}

	natConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = natConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("reading authentication reject response: %w", err)
	}
	var rejectResp IKEPacket
	if err := rejectResp.UnmarshalBinary(buf[4:n]); err != nil {
		return fmt.Errorf("parsing authentication reject response: %w", err)
	}
	rejectPayloads, err := serverCrypto.OpenIKE(rejectResp, true)
	if err != nil {
		return fmt.Errorf("opening authentication reject response: %w", err)
	}
	rejectEAP := findEAPPayload(rejectPayloads)
	if rejectEAP == nil {
		return fmt.Errorf("authentication reject response missing eap payload")
	}
	var rejectMessage AKAMessage
	if err := rejectMessage.UnmarshalBinary(rejectEAP.Data); err != nil {
		return fmt.Errorf("parsing authentication reject response: %w", err)
	}
	if rejectMessage.Subtype != akaSubtypeAuthenticationReject {
		return fmt.Errorf("authentication reject subtype = %d", rejectMessage.Subtype)
	}
	eapFailure, err := (EAPPacket{Code: eapCodeFailure, Identifier: 0x09}).MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshalling eap failure: %w", err)
	}
	failureResp, err := serverCrypto.SealIKE(testIKEAuthResponseHeader(saInitReq.Header.InitiatorSPI, 2), []Payload{&EAPPayload{Data: eapFailure}}, false)
	if err != nil {
		return fmt.Errorf("sealing eap failure: %w", err)
	}
	if _, err := natConn.WriteTo(append([]byte{0, 0, 0, 0}, failureResp...), clientNATAddr); err != nil {
		return fmt.Errorf("writing eap failure: %w", err)
	}
	return nil
}

func TestIKERetransmitDelay(t *testing.T) {
	tests := []struct {
		name    string
		attempt int
		want    time.Duration
	}{
		{name: "first", attempt: 0, want: 500 * time.Millisecond},
		{name: "second", attempt: 1, want: time.Second},
		{name: "third", attempt: 2, want: 2 * time.Second},
		{name: "cap", attempt: 8, want: 8 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ikeRetransmitDelay(tt.attempt); got != tt.want {
				t.Fatalf("ikeRetransmitDelay(%d) = %v, want %v", tt.attempt, got, tt.want)
			}
		})
	}
}

func TestSessionCloseDiscardsStateWithBorrowedConn(t *testing.T) {
	conn := mustListenUDP4(t, "session")
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	session := &Session{
		conn:                 conn,
		owned:                false,
		logger:               testLogger(),
		outerRemote:          &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 500},
		outerNAT:             &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500},
		closeCtx:             ctx,
		closeCancel:          cancel,
		readCh:               make(chan inboundPacket, 16),
		connected:            true,
		innerLocal:           &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5062},
		innerRemote:          &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5060},
		tunnel:               TunnelInfo{ESPInitiatorSPI: 1, ESPResponderSPI: 2},
		ike:                  &ikeCrypto{},
		initiatorSPI:         1,
		responderSPI:         2,
		deviceIdentity:       "356789012345678",
		nextMessageID:        7,
		lastProtectedRx:      time.Now(),
		lastProtectedTx:      time.Now(),
		livenessTimeout:      time.Second,
		natKeepaliveInterval: time.Second,
		informWaiters:        map[uint32]chan inboundIKE{7: make(chan inboundIKE, 1)},
	}
	session.wg.Add(1)
	go session.readLoop()

	done := make(chan error, 1)
	go func() { done <- session.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close() timed out for borrowed PacketConn")
	}

	session.mu.RLock()
	defer session.mu.RUnlock()
	if session.connected {
		t.Fatal("connected = true, want false")
	}
	if session.ike != nil {
		t.Fatal("ike = non-nil, want nil")
	}
	if session.innerLocal != nil || session.innerRemote != nil {
		t.Fatal("inner addresses not cleared")
	}
	if session.deviceIdentity != "" || session.nextMessageID != 0 {
		t.Fatal("session identifiers not cleared")
	}
}

func TestSessionSendInformationalRetransmits(t *testing.T) {
	initiator, responder := newInformationalIKEPair(t)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 4500}
	conn := &recordPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &Session{
		conn:          conn,
		logger:        testLogger(),
		outerNAT:      peer,
		closeCtx:      ctx,
		closeCancel:   cancel,
		ike:           initiator,
		initiatorSPI:  1,
		responderSPI:  2,
		informWaiters: map[uint32]chan inboundIKE{},
	}

	result := make(chan error, 1)
	go func() {
		requestCtx, requestCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer requestCancel()
		_, err := session.sendInformational(requestCtx, nil)
		result <- err
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if conn.writeCount() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if conn.writeCount() < 2 {
		t.Fatalf("writeCount = %d, want at least 2 retransmissions", conn.writeCount())
	}

	wire := mustSealIKE(t, "response", responder, IKEHeader{InitiatorSPI: 1, ResponderSPI: 2, Version: ikeVersion20, ExchangeType: exchangeTypeInformational, Flags: flagResponse, MessageID: 1}, nil)
	handled, err := session.handleIKEPacket(wire, peer)
	if err != nil {
		t.Fatalf("handleIKEPacket() error = %v", err)
	}
	if !handled {
		t.Fatal("handleIKEPacket() = false, want true")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("sendInformational() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sendInformational() did not finish")
	}
}

func TestSessionNATKeepaliveUpdatesLastProtectedTx(t *testing.T) {
	conn := &recordPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}}
	ctx, cancel := context.WithCancel(context.Background())
	session := &Session{
		conn:                 conn,
		logger:               testLogger(),
		outerNAT:             &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 4500},
		closeCtx:             ctx,
		closeCancel:          cancel,
		natKeepaliveInterval: 10 * time.Millisecond,
		lastProtectedTx:      time.Now().Add(-time.Minute),
	}
	start := time.Now()
	session.wg.Add(1)
	go session.natKeepaliveLoop()

	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if conn.writeCount() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	session.wg.Wait()
	if conn.writeCount() == 0 {
		t.Fatal("natKeepaliveLoop() did not send keepalive")
	}
	session.mu.RLock()
	lastTx := session.lastProtectedTx
	session.mu.RUnlock()
	if !lastTx.After(start) {
		t.Fatalf("lastProtectedTx = %v, want after %v", lastTx, start)
	}
}

func TestSessionFailureNotifiesDetachedTransports(t *testing.T) {
	type readTransport interface {
		ReadPacket(ctx context.Context) ([]byte, net.Addr, error)
		Close() error
	}

	tests := []struct {
		name    string
		build   func(session *Session) readTransport
		check   func(t *testing.T, transport readTransport)
		wantErr string
	}{
		{
			name: "tcp client transport",
			build: func(session *Session) readTransport {
				transport := &TCPTransport{
					session: session,
					msgCh:   make(chan []byte, 1),
					errCh:   make(chan error, 1),
					readyCh: make(chan struct{}),
					ackCh:   make(chan struct{}, 1),
				}
				session.tcp = transport
				return transport
			},
			check: func(t *testing.T, transport readTransport) {
				t.Helper()
				tcp, ok := transport.(*TCPTransport)
				if !ok {
					t.Fatalf("transport type = %T, want *TCPTransport", transport)
				}
				if !tcp.closed {
					t.Fatal("tcp.closed = false, want true")
				}
			},
			wantErr: "liveness check",
		},
		{
			name: "tcp server transport",
			build: func(session *Session) readTransport {
				transport := &TCPTransport{
					session: session,
					msgCh:   make(chan []byte, 1),
					errCh:   make(chan error, 1),
					readyCh: make(chan struct{}),
					ackCh:   make(chan struct{}, 1),
				}
				session.tcpServer = transport
				return transport
			},
			check: func(t *testing.T, transport readTransport) {
				t.Helper()
				tcp, ok := transport.(*TCPTransport)
				if !ok {
					t.Fatalf("transport type = %T, want *TCPTransport", transport)
				}
				if !tcp.closed {
					t.Fatal("tcp.closed = false, want true")
				}
			},
			wantErr: "liveness check",
		},
		{
			name: "secure udp transport",
			build: func(session *Session) readTransport {
				transport := &SecureUDPTransport{
					session: session,
					readCh:  make(chan inboundPacket, 1),
					done:    make(chan struct{}),
				}
				session.udpServer = transport
				return transport
			},
			check: func(t *testing.T, transport readTransport) {
				t.Helper()
				udp, ok := transport.(*SecureUDPTransport)
				if !ok {
					t.Fatalf("transport type = %T, want *SecureUDPTransport", transport)
				}
				if !udp.closed {
					t.Fatal("udp.closed = false, want true")
				}
			},
			wantErr: "liveness check",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			session := &Session{
				conn:        &recordPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}},
				logger:      testLogger(),
				closeCtx:    ctx,
				closeCancel: cancel,
			}
			transport := tt.build(session)
			defer func() { _ = transport.Close() }()

			result := make(chan error, 1)
			go func() {
				readCtx, readCancel := context.WithTimeout(context.Background(), time.Second)
				defer readCancel()
				_, _, err := transport.ReadPacket(readCtx)
				result <- err
			}()

			session.failSecurityAssociations(errors.New("liveness check: waiting message 5: timeout"))

			select {
			case err := <-result:
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ReadPacket() error = %v, want substring %q", err, tt.wantErr)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("ReadPacket() did not return after session failure")
			}

			tt.check(t, transport)
		})
	}
}

func TestSessionLivenessLoopContinuesRetransmitting(t *testing.T) {
	tests := []struct {
		name       string
		wantWrites int
		wait       time.Duration
	}{
		{name: "beyond previous five second cap", wantWrites: 5, wait: 9 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initiator, _ := newInformationalIKEPair(t)
			conn := &recordPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}}
			ctx, cancel := context.WithCancel(context.Background())
			session := &Session{
				conn:            conn,
				logger:          testLogger(),
				outerNAT:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 4500},
				closeCtx:        ctx,
				closeCancel:     cancel,
				ike:             initiator,
				initiatorSPI:    1,
				responderSPI:    2,
				livenessTimeout: time.Millisecond,
				lastProtectedRx: time.Now().Add(-time.Minute),
				informWaiters:   map[uint32]chan inboundIKE{},
			}

			session.wg.Add(1)
			go session.livenessLoop()

			deadline := time.Now().Add(tt.wait)
			for time.Now().Before(deadline) {
				if conn.writeCount() >= tt.wantWrites {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}

			cancel()
			session.wg.Wait()

			if got := conn.writeCount(); got < tt.wantWrites {
				t.Fatalf("writeCount = %d, want at least %d", got, tt.wantWrites)
			}
		})
	}
}

func newInformationalIKEPair(t *testing.T) (*ikeCrypto, *ikeCrypto) {
	t.Helper()
	initiator, err := newIKECrypto(transformDH1024MODP)
	if err != nil {
		t.Fatalf("newIKECrypto(initiator) error = %v", err)
	}
	responder, err := newIKECrypto(transformDH1024MODP)
	if err != nil {
		t.Fatalf("newIKECrypto(responder) error = %v", err)
	}
	initiator.SetProposal(transformENCRAESCBC, 128, transformINTEGHMACSHA196, transformPRFHMACSHA1)
	responder.SetProposal(transformENCRAESCBC, 128, transformINTEGHMACSHA196, transformPRFHMACSHA1)
	initiator.SetSPIs(1, 2)
	responder.SetSPIs(1, 2)
	nonceI := bytes.Repeat([]byte{0x11}, 16)
	nonceR := bytes.Repeat([]byte{0x22}, 16)
	initiator.SetNonces(nonceI, nonceR)
	responder.SetNonces(nonceI, nonceR)
	if err := initiator.DeriveIKEKeys(responder.PublicKey()); err != nil {
		t.Fatalf("DeriveIKEKeys(initiator) error = %v", err)
	}
	if err := responder.DeriveIKEKeys(initiator.PublicKey()); err != nil {
		t.Fatalf("DeriveIKEKeys(responder) error = %v", err)
	}
	return initiator, responder
}

func TestSessionCloseContextSendsDelete(t *testing.T) {
	initiator, responder := newInformationalIKEPair(t)
	conn := &recordPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &Session{
		conn:          conn,
		logger:        testLogger(),
		outerNAT:      &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 4500},
		closeCtx:      ctx,
		closeCancel:   cancel,
		connected:     true,
		ike:           initiator,
		initiatorSPI:  1,
		responderSPI:  2,
		nextMessageID: 7,
	}

	if err := session.CloseContext(context.Background()); err != nil {
		t.Fatalf("CloseContext() error = %v", err)
	}
	if conn.writeCount() != 1 {
		t.Fatalf("writeCount = %d, want 1 delete request", conn.writeCount())
	}
	if !hasNonESPMarker(conn.writes[0]) {
		t.Fatal("delete request missing non-esp marker")
	}
	packet := mustUnmarshalIKEPacket(t, "delete", conn.writes[0][4:])
	payloads, err := responder.OpenIKE(packet, true)
	if err != nil {
		t.Fatalf("OpenIKE(delete) error = %v", err)
	}
	deletePayload := findDeletePayload(payloads)
	if deletePayload == nil {
		t.Fatal("findDeletePayload() = nil, want delete payload")
	}
	if deletePayload.ProtocolID != protocolIDIKE {
		t.Fatalf("delete protocol = %d, want %d", deletePayload.ProtocolID, protocolIDIKE)
	}
	if len(deletePayload.SPIs) != 0 {
		t.Fatalf("delete spis = %d, want 0", len(deletePayload.SPIs))
	}
	if session.connected {
		t.Fatal("connected = true, want false")
	}
	if session.ike != nil {
		t.Fatal("ike = non-nil, want nil")
	}
}

func TestHandleIKEPacketDeleteRequestClearsSession(t *testing.T) {
	initiator, responder := newInformationalIKEPair(t)
	conn := &recordPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &Session{
		conn:          conn,
		owned:         true,
		logger:        testLogger(),
		outerNAT:      &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 4500},
		closeCtx:      ctx,
		closeCancel:   cancel,
		connected:     true,
		ike:           initiator,
		initiatorSPI:  1,
		responderSPI:  2,
		informWaiters: map[uint32]chan inboundIKE{},
	}
	request := mustSealIKE(t, "delete request", responder, IKEHeader{InitiatorSPI: 1, ResponderSPI: 2, Version: ikeVersion20, ExchangeType: exchangeTypeInformational, MessageID: 9}, []Payload{&DeletePayload{ProtocolID: protocolIDIKE}})
	handled, err := session.handleIKEPacket(request, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 4500})
	if err != nil {
		t.Fatalf("handleIKEPacket(delete) error = %v", err)
	}
	if !handled {
		t.Fatal("handleIKEPacket(delete) = false, want true")
	}
	if conn.writeCount() != 1 {
		t.Fatalf("writeCount = %d, want 1 delete response", conn.writeCount())
	}
	if !hasNonESPMarker(conn.writes[0]) {
		t.Fatal("delete response missing non-esp marker")
	}
	packet := mustUnmarshalIKEPacket(t, "response", conn.writes[0][4:])
	payloads, err := responder.OpenIKE(packet, true)
	if err != nil {
		t.Fatalf("OpenIKE(response) error = %v", err)
	}
	if len(payloads) != 0 {
		t.Fatalf("len(payloads) = %d, want 0", len(payloads))
	}
	if !session.isClosed() {
		t.Fatal("session.isClosed() = false, want true")
	}
	if session.connected {
		t.Fatal("connected = true, want false")
	}
	if session.ike != nil {
		t.Fatal("ike = non-nil, want nil")
	}
}
