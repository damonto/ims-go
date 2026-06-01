package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/damonto/vowifi-go/swu/ike"
)

func TestRetransmitDelays(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want []time.Duration
	}{
		{name: "default schedule", want: defaultIKERetransmitDelays},
		{
			name: "custom schedule",
			cfg: Config{IKERetransmitDelays: []time.Duration{
				500 * time.Millisecond,
				time.Second,
				2 * time.Second,
			}},
			want: []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := tt.cfg.Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			session := &Session{cfg: cfg}
			if got := session.ikeRetransmitDelays(); !slices.Equal(got, tt.want) {
				t.Fatalf("ikeRetransmitDelays() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEstablishedIKEExchangesUseConfiguredRetransmitSchedule(t *testing.T) {
	tests := []struct {
		name     string
		exchange func(context.Context, *Session) error
	}{
		{
			name: "informational",
			exchange: func(ctx context.Context, session *Session) error {
				crypto := testIKECrypto()
				state := informationalState{ike: crypto, localInitiator: true, peer: session.outerNAT}
				wire := protectedIKEWire(t, crypto, exchangeTypeInformational, flagInitiator, 7, nil, true)
				_, err := session.exchangeInformational(ctx, state, 7, wire, make(chan inboundIKE))
				return err
			},
		},
		{
			name: "protected",
			exchange: func(ctx context.Context, session *Session) error {
				_, err := session.exchangeProtected(ctx, protectedExchange{
					action:         "testing protected exchange",
					peer:           session.outerNAT,
					skipIKESABytes: true,
					messageID:      9,
					wire:           []byte{0x02},
					waiter:         make(chan inboundIKE),
				})
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session, err := Dial(context.Background(), Config{
				RemoteAddr:           "127.0.0.1:4500",
				PacketConn:           conn,
				Logger:               testLogger(),
				IKERetransmitDelays:  []time.Duration{500 * time.Millisecond},
				NATKeepaliveInterval: time.Second,
			})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			defer session.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
			defer cancel()

			err = tt.exchange(ctx, session)
			if !errors.Is(err, errIKERequestIncomplete) || strings.Contains(err.Error(), context.DeadlineExceeded.Error()) {
				t.Fatalf("exchange error = %v, want incomplete request after configured retransmit timeout", err)
			}
			if got := len(conn.writes); got != 1 {
				t.Fatalf("writes = %d, want 1", got)
			}
		})
	}
}

func TestSendDeleteRequestWaitsForIKEDeleteResponse(t *testing.T) {
	tests := []struct {
		name             string
		responsePayloads []ike.Payload
		wantErr          string
	}{
		{name: "empty response closes exchange"},
		{
			name: "non empty response is invalid",
			responsePayloads: []ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeCookie2, Data: []byte{0, 1, 2, 3, 4, 5, 6, 7}},
			},
			wantErr: "payload count 1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session := mustDialSession(t, conn)
			crypto := testIKECrypto()
			peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
			const messageID uint32 = 7
			session.mu.Lock()
			session.connected = true
			session.ike = crypto
			session.ikeLocalInitiator = true
			session.initiatorSPI = 0x0102030405060708
			session.responderSPI = 0x1112131415161718
			session.outerNAT = cloneUDPAddr(peer)
			session.nextMessageID = messageID
			session.mu.Unlock()

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			errCh := make(chan error, 1)
			go func() {
				errCh <- session.sendDeleteRequest(ctx)
			}()

			waitForWrites(t, conn, 1)
			response := protectedIKEWire(t, crypto, exchangeTypeInformational, flagResponse|flagInitiator, messageID, tt.responsePayloads, false)
			key := ikeMessageKeyForSPIs(0x0102030405060708, 0x1112131415161718, messageID)
			if !session.deliverInformationalWaiter(key, inboundIKE{data: response, addr: peer}) {
				t.Fatal("deliverInformationalWaiter() = false, want true")
			}

			err := <-errCh
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("sendDeleteRequest() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("sendDeleteRequest() error = %v", err)
			}
		})
	}
}

func TestValidateIKEDeleteResponsePayloads(t *testing.T) {
	tests := []struct {
		name     string
		payloads []ike.Payload
		wantErr  string
	}{
		{name: "empty response"},
		{
			name:     "nonempty response",
			payloads: []ike.Payload{&ike.NotifyPayload{NotifyType: notifyTypeCookie2}},
			wantErr:  "ike delete response payload count 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIKEDeleteResponsePayloads("deleting old ike sa", tt.payloads)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateIKEDeleteResponsePayloads() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateIKEDeleteResponsePayloads() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestHandleNonESPPacketLogsUnmatchedInformationalResponse(t *testing.T) {
	var logs bytes.Buffer
	session := &Session{
		logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	wire, err := (ike.IKEPacket{
		Header: ike.IKEHeader{
			InitiatorSPI: 0x0102030405060708,
			ResponderSPI: 0x1112131415161718,
			Version:      ikeVersion20,
			ExchangeType: exchangeTypeInformational,
			Flags:        flagResponse,
			MessageID:    16,
		},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	session.handleNonESPPacket(wire, nil)

	got := logs.String()
	if !strings.Contains(got, "ignoring unmatched informational response") {
		t.Fatalf("logs = %q, want unmatched informational response log", got)
	}
	if strings.Contains(got, "ignoring unexpected non-ESP marker packet") {
		t.Fatalf("logs = %q, got generic non-ESP marker log", got)
	}
}

func TestInformationalResponseHeaderSetsInitiatorAndResponseFlags(t *testing.T) {
	tests := []struct {
		name           string
		localInitiator bool
		want           byte
	}{
		{name: "local is original initiator", localInitiator: true, want: flagResponse | flagInitiator},
		{name: "local is original responder", want: flagResponse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := informationalResponseHeader(informationalState{
				localInitiator: tt.localInitiator,
				initiatorSPI:   0x0102030405060708,
				responderSPI:   0x1112131415161718,
			}, 16)

			if header.Flags != tt.want {
				t.Fatalf("Flags = 0x%02X, want 0x%02X", header.Flags, tt.want)
			}
		})
	}
}

func TestAllocateMessageIDStartsAtZeroAfterIKESARekey(t *testing.T) {
	tests := []struct {
		name string
		seed uint32
		want []uint32
	}{
		{name: "new ike sa counters", want: []uint32{0, 1}},
		{name: "established ike auth counter", seed: 2, want: []uint32{2, 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{nextMessageID: tt.seed}
			for _, want := range tt.want {
				got, err := session.allocateMessageID()
				if err != nil {
					t.Fatalf("allocateMessageID() error = %v", err)
				}
				if got != want {
					t.Fatalf("allocateMessageID() = %d, want %d", got, want)
				}
			}
		})
	}
}

func TestAllocateMessageIDRejectsOverflow(t *testing.T) {
	tests := []struct {
		name string
		seed uint32
	}{
		{name: "max id would wrap", seed: maxIKEMessageID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{nextMessageID: tt.seed}

			_, err := session.allocateMessageID()
			if !errors.Is(err, errIKEMessageIDExhausted) {
				t.Fatalf("allocateMessageID() error = %v, want %v", err, errIKEMessageIDExhausted)
			}
			if session.nextMessageID != tt.seed {
				t.Fatalf("nextMessageID = %d, want unchanged %d", session.nextMessageID, tt.seed)
			}
		})
	}
}

func TestPeerRequestMessageIDWindow(t *testing.T) {
	tests := []struct {
		name          string
		seed          uint32
		messageID     uint32
		wantCurrent   bool
		wantAfterNext uint32
	}{
		{name: "next peer request", seed: 4, messageID: 4, wantCurrent: true, wantAfterNext: 5},
		{name: "duplicate peer request", seed: 4, messageID: 3, wantAfterNext: 4},
		{name: "future peer request", seed: 4, messageID: 5, wantAfterNext: 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{nextPeerMessageID: tt.seed}

			if got := session.peerRequestMessageIDCurrent(tt.messageID); got != tt.wantCurrent {
				t.Fatalf("peerRequestMessageIDCurrent() = %t, want %t", got, tt.wantCurrent)
			}
			if err := session.advancePeerRequestMessageID(tt.messageID); err != nil {
				t.Fatalf("advancePeerRequestMessageID() error = %v", err)
			}
			if session.nextPeerMessageID != tt.wantAfterNext {
				t.Fatalf("nextPeerMessageID = %d, want %d", session.nextPeerMessageID, tt.wantAfterNext)
			}
		})
	}
}

func TestPeerRequestMessageIDRelation(t *testing.T) {
	tests := []struct {
		name      string
		seed      uint32
		messageID uint32
		want      ikeMessageIDRelation
	}{
		{name: "current", seed: 4, messageID: 4, want: ikeMessageIDCurrent},
		{name: "old", seed: 4, messageID: 3, want: ikeMessageIDOld},
		{name: "future", seed: 4, messageID: 5, want: ikeMessageIDFuture},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{nextPeerMessageID: tt.seed}

			got := session.peerRequestMessageIDRelationForState(informationalState{}, tt.messageID)

			if got != tt.want {
				t.Fatalf("peerRequestMessageIDRelationForState() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestAdvancePeerRequestMessageIDRejectsOverflow(t *testing.T) {
	tests := []struct {
		name      string
		seed      uint32
		messageID uint32
		wantNext  uint32
	}{
		{name: "max id would wrap", seed: maxIKEMessageID, messageID: maxIKEMessageID, wantNext: maxIKEMessageID},
		{name: "old max duplicate is ignored by current window", seed: 7, messageID: maxIKEMessageID, wantNext: 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{nextPeerMessageID: tt.seed}

			err := session.advancePeerRequestMessageID(tt.messageID)
			if tt.messageID == tt.seed {
				if !errors.Is(err, errIKEMessageIDExhausted) {
					t.Fatalf("advancePeerRequestMessageID() error = %v, want %v", err, errIKEMessageIDExhausted)
				}
			} else if err != nil {
				t.Fatalf("advancePeerRequestMessageID() error = %v", err)
			}
			if session.nextPeerMessageID != tt.wantNext {
				t.Fatalf("nextPeerMessageID = %d, want %d", session.nextPeerMessageID, tt.wantNext)
			}
		})
	}
}

func TestOldInformationalRequestWithoutCachedResponseIsIgnored(t *testing.T) {
	tests := []struct {
		name      string
		expected  uint32
		messageID uint32
	}{
		{name: "old retransmit after response cache expired", expected: 2, messageID: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session := mustDialSession(t, conn)
			defer session.Close()
			crypto := testIKECrypto()
			peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
			wire := protectedIKEWire(t, crypto, exchangeTypeInformational, 0, tt.messageID, nil, false)
			var packet ike.IKEPacket
			if err := packet.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			session.mu.Lock()
			session.ike = crypto
			session.ikeLocalInitiator = true
			session.initiatorSPI = packet.Header.InitiatorSPI
			session.responderSPI = packet.Header.ResponderSPI
			session.outerNAT = peer
			session.nextPeerMessageID = tt.expected
			session.mu.Unlock()
			state := informationalState{
				ike:            crypto,
				localInitiator: true,
				initiatorSPI:   packet.Header.InitiatorSPI,
				responderSPI:   packet.Header.ResponderSPI,
				peer:           peer,
			}

			ok, err := session.handleInformationalRequest(state, packet, peer)

			if !ok || err != nil {
				t.Fatalf("handleInformationalRequest() = (%t, %v), want handled without error", ok, err)
			}
			if len(conn.writes) != 0 {
				t.Fatalf("writes = %d, want no INVALID_MESSAGE_ID notification for old retransmit", len(conn.writes))
			}
		})
	}
}

func TestInvalidMessageIDNotificationIsRateLimited(t *testing.T) {
	tests := []struct {
		name      string
		invalidID uint32
	}{
		{name: "future message id", invalidID: 17},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldTimeout := invalidMessageIDNotifyTimeout
			invalidMessageIDNotifyTimeout = time.Millisecond
			t.Cleanup(func() { invalidMessageIDNotifyTimeout = oldTimeout })

			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session := mustDialSession(t, conn)
			crypto := testIKECrypto()
			state := informationalState{
				ike:            crypto,
				localInitiator: true,
				initiatorSPI:   0x0102030405060708,
				responderSPI:   0x1112131415161718,
				peer:           session.outerNAT,
			}

			if err := session.sendInvalidMessageIDNotification(state, tt.invalidID); err != nil {
				t.Fatalf("sendInvalidMessageIDNotification() error = %v", err)
			}
			if got := len(conn.writes); got != 1 {
				t.Fatalf("writes = %d, want 1", got)
			}

			var packet ike.IKEPacket
			if err := packet.UnmarshalBinary(conn.writes[0][4:]); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			payloads, err := crypto.OpenIKE(packet, true)
			if err != nil {
				t.Fatalf("OpenIKE() error = %v", err)
			}
			notify := ike.FindNotifyPayload(payloads, notifyTypeInvalidMessageID)
			if notify == nil {
				t.Fatalf("FindNotifyPayload(%d) = nil", notifyTypeInvalidMessageID)
			}
			if got := binary.BigEndian.Uint32(notify.Data); got != tt.invalidID {
				t.Fatalf("invalid Message ID notify data = %d, want %d", got, tt.invalidID)
			}

			if err := session.sendInvalidMessageIDNotification(state, tt.invalidID+1); err != nil {
				t.Fatalf("second sendInvalidMessageIDNotification() error = %v", err)
			}
			if got := len(conn.writes); got != 1 {
				t.Fatalf("writes after rate-limited notification = %d, want 1", got)
			}
		})
	}
}

func TestBuildInformationalConfigReply(t *testing.T) {
	tests := []struct {
		name      string
		state     informationalState
		attrs     []ike.Attribute
		wantTypes []uint16
		wantInfo  Info
	}{
		{
			name: "p-cscf restoration request ignored without advertised support",
			state: informationalState{
				cfg: Config{DisablePCSCFRestoration: true},
			},
			attrs: []ike.Attribute{
				ike.NewTLVAttribute(configAttrPCSCFIPv4Address, nil),
				ike.NewTLVAttribute(configAttrPCSCFIPv6Address, nil),
			},
		},
		{
			name: "liveness timeout request ignored in informational exchange",
			attrs: []ike.Attribute{
				ike.NewTLVAttribute(configAttrTimeoutPeriodForLivenessCheck, nil),
			},
		},
		{
			name: "mixed request replies only supported p-cscf restoration attributes",
			state: informationalState{
				info: Info{InnerIP: net.IPv4(10, 0, 0, 1), PCSCFIP: net.IPv4(10, 0, 0, 2), PCSCFIPs: []net.IP{net.IPv4(10, 0, 0, 2)}},
			},
			attrs: []ike.Attribute{
				ike.NewTLVAttribute(configAttrPCSCFIPv4Address, net.IPv4(10, 9, 8, 7).To4()),
				ike.NewTLVAttribute(configAttrTimeoutPeriodForLivenessCheck, nil),
			},
			wantTypes: []uint16{configAttrPCSCFIPv4Address},
			wantInfo:  Info{InnerIP: net.IPv4(10, 0, 0, 1), PCSCFIP: net.IPv4(10, 9, 8, 7).To4(), PCSCFIPs: []net.IP{net.IPv4(10, 9, 8, 7).To4()}},
		},
		{
			name: "p-cscf restoration keeps all advertised addresses",
			attrs: []ike.Attribute{
				ike.NewTLVAttribute(configAttrPCSCFIPv6Address, net.ParseIP("2001:db8::7").To16()),
				ike.NewTLVAttribute(configAttrPCSCFIPv6Address, net.ParseIP("2001:db8::8").To16()),
				ike.NewTLVAttribute(configAttrPCSCFIPv4Address, net.IPv4(10, 9, 8, 7).To4()),
			},
			wantTypes: []uint16{configAttrPCSCFIPv6Address, configAttrPCSCFIPv4Address},
			wantInfo: Info{
				PCSCFIP: net.ParseIP("2001:db8::7").To16(),
				PCSCFIPs: []net.IP{
					net.ParseIP("2001:db8::7").To16(),
					net.ParseIP("2001:db8::8").To16(),
					net.IPv4(10, 9, 8, 7).To4(),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reply, action := buildInformationalConfigReply(tt.state, []ike.Payload{
				&ike.ConfigPayload{ConfigType: configTypeRequest, Attributes: tt.attrs},
			})
			if len(tt.wantTypes) == 0 {
				if reply != nil {
					t.Fatalf("buildInformationalConfigReply() = %+v, want nil", reply)
				}
				if action.pcscfReselection {
					t.Fatalf("pcscfReselection = true, want false")
				}
				return
			}
			if reply == nil {
				t.Fatal("buildInformationalConfigReply() = nil, want config reply")
			}
			if reply.ConfigType != configTypeReply {
				t.Fatalf("reply config type = %d, want %d", reply.ConfigType, configTypeReply)
			}
			if len(reply.Attributes) != len(tt.wantTypes) {
				t.Fatalf("reply attrs = %v, want types %v", reply.Attributes, tt.wantTypes)
			}
			for i, attr := range reply.Attributes {
				if attr.Type != tt.wantTypes[i] {
					t.Fatalf("reply attr[%d] type = %d, want %d", i, attr.Type, tt.wantTypes[i])
				}
				if len(attr.Value) != 0 {
					t.Fatalf("reply attr[%d] value len = %d, want 0", i, len(attr.Value))
				}
			}
			if len(tt.wantInfo.PCSCFIPs) == 0 {
				if action.pcscfReselection {
					t.Fatalf("pcscfReselection = true, want false")
				}
				return
			}
			if !action.pcscfReselection {
				t.Fatalf("pcscfReselection = false, want true")
			}
			if !action.pcscfInfo.PCSCFIP.Equal(tt.wantInfo.PCSCFIP) {
				t.Fatalf("pcscfInfo.PCSCFIP = %s, want %s", action.pcscfInfo.PCSCFIP, tt.wantInfo.PCSCFIP)
			}
			if !ipListEqual(action.pcscfInfo.PCSCFIPs, tt.wantInfo.PCSCFIPs) {
				t.Fatalf("pcscfInfo.PCSCFIPs = %v, want %v", action.pcscfInfo.PCSCFIPs, tt.wantInfo.PCSCFIPs)
			}
		})
	}
}

func TestBuildInformationalResponsePayloadsCookie2(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{name: "minimum length cookie2 is copied", data: []byte{0, 1, 2, 3, 4, 5, 6, 7}},
		{name: "maximum length cookie2 is copied", data: bytes.Repeat([]byte{0xa5}, maxCookieNotifyDataLength)},
		{name: "too short cookie2 is rejected", data: []byte{0, 1, 2, 3, 4, 5, 6}, wantErr: true},
		{name: "too long cookie2 is rejected", data: bytes.Repeat([]byte{0xa5}, maxCookieNotifyDataLength+1), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			responsePayloads, action, err := buildInformationalResponsePayloads(informationalState{}, []ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeCookie2, Data: tt.data},
			}, "")

			if tt.wantErr {
				if err == nil {
					t.Fatal("buildInformationalResponsePayloads() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("buildInformationalResponsePayloads() error = %v", err)
			}
			if action.deleteIKE || action.deleteChild || action.reactivationRequested || action.pcscfReselection {
				t.Fatalf("action = %+v, want zero value", action)
			}
			if len(responsePayloads) != 1 {
				t.Fatalf("response payload count = %d, want 1", len(responsePayloads))
			}
			notify, ok := responsePayloads[0].(*ike.NotifyPayload)
			if !ok {
				t.Fatalf("response payload type = %T, want *ike.NotifyPayload", responsePayloads[0])
			}
			if notify.ProtocolID != protocolIDUnset || notify.NotifyType != notifyTypeCookie2 {
				t.Fatalf("response notify = protocol %d type %d, want COOKIE2", notify.ProtocolID, notify.NotifyType)
			}
			if !bytes.Equal(notify.Data, tt.data) {
				t.Fatalf("response COOKIE2 data = %x, want %x", notify.Data, tt.data)
			}
		})
	}
}

func TestBuildDeviceIdentityResponsePayload(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		identity string
		wantData []byte
		wantOK   bool
	}{
		{
			name:     "informational request uses one byte identity type",
			request:  []byte{0x01},
			identity: "123456789123456",
			wantData: []byte{0x00, 0x09, 0x01, 0x21, 0x43, 0x65, 0x87, 0x19, 0x32, 0x54, 0xf6},
			wantOK:   true,
		},
		{
			name:     "nonempty identity request is not answered",
			request:  []byte{0x00, 0x09, 0x01, 0x21, 0x43, 0x65, 0x87, 0x19, 0x32, 0x54, 0xf6},
			identity: "123456789123456",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, ok, err := buildDeviceIdentityResponsePayload([]ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeDeviceIdentity, Data: tt.request},
			}, tt.identity)
			if err != nil {
				t.Fatalf("buildDeviceIdentityResponsePayload() error = %v", err)
			}
			if ok != tt.wantOK {
				t.Fatalf("buildDeviceIdentityResponsePayload() ok = %t, want %t", ok, tt.wantOK)
			}
			if !tt.wantOK {
				if payload != nil {
					t.Fatalf("payload = %+v, want nil", payload)
				}
				return
			}
			if payload == nil || payload.NotifyType != notifyTypeDeviceIdentity || !bytes.Equal(payload.Data, tt.wantData) {
				t.Fatalf("payload = %+v, want DEVICE_IDENTITY % X", payload, tt.wantData)
			}
		})
	}
}

func TestAcquireIKERequestSerializesOutboundWindow(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "second request waits for first request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			release, err := session.acquireIKERequest(context.Background(), "first request")
			if err != nil {
				t.Fatalf("first acquireIKERequest() error = %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
			defer cancel()
			if _, err := session.acquireIKERequest(ctx, "second request"); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("second acquireIKERequest() error = %v, want context deadline exceeded", err)
			}

			release()
			release, err = session.acquireIKERequest(context.Background(), "second request")
			if err != nil {
				t.Fatalf("second acquireIKERequest() after release error = %v", err)
			}
			release()
		})
	}
}

func TestRekeyDoesNotAllocateMessageIDBeforeOutboundWindow(t *testing.T) {
	tests := []struct {
		name      string
		prepare   func(*Session)
		rekey     func(context.Context, *Session) error
		rekeyFlag func(*Session) bool
	}{
		{
			name: "child sa",
			prepare: func(session *Session) {
				tsi, tsr := testChildSATrafficSelectors()
				session.connected = true
				session.tunnel = Info{
					ESPInitiatorSPI:           0x01020304,
					ESPResponderSPI:           0x10203040,
					Encryption:                transformENCRAESCBC,
					EncryptionKeyLen:          128,
					Integrity:                 transformINTEGHMACSHA196,
					InitiatorTrafficSelectors: tsi,
					ResponderTrafficSelectors: tsr,
				}
			},
			rekey: func(ctx context.Context, session *Session) error {
				return session.RekeyChildSA(ctx)
			},
			rekeyFlag: func(session *Session) bool {
				return session.childSARekeying
			},
		},
		{
			name: "ike sa",
			rekey: func(ctx context.Context, session *Session) error {
				return session.RekeyIKESA(ctx)
			},
			rekeyFlag: func(session *Session) bool {
				return session.ikeSARekeying
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			defer session.Close()

			session.mu.Lock()
			session.ike = testIKECrypto()
			session.ikeLocalInitiator = true
			session.initiatorSPI = 0x0102030405060708
			session.responderSPI = 0x1112131415161718
			session.nextMessageID = 41
			if tt.prepare != nil {
				tt.prepare(session)
			}
			session.mu.Unlock()

			release, err := session.acquireIKERequest(context.Background(), "holding request window")
			if err != nil {
				t.Fatalf("acquireIKERequest() error = %v", err)
			}
			defer release()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			if err := tt.rekey(ctx, session); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("rekey error = %v, want context deadline exceeded", err)
			}

			session.mu.RLock()
			nextMessageID := session.nextMessageID
			rekeying := tt.rekeyFlag(session)
			session.mu.RUnlock()
			if nextMessageID != 41 {
				t.Fatalf("nextMessageID = %d, want 41 while outbound window is unavailable", nextMessageID)
			}
			if rekeying {
				t.Fatal("rekey flag still set after request window timeout")
			}
		})
	}
}

func TestRekeyLoopFailsSecurityAssociationsAfterIncompleteRequest(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*Session)
		run     func(*Session)
	}{
		{
			name: "child sa",
			prepare: func(session *Session) {
				tsi, tsr := testChildSATrafficSelectors()
				session.connected = true
				session.childSARekeyAt = time.Now().Add(-time.Second)
				session.childSAExpiresAt = time.Now().Add(time.Hour)
				session.tunnel = Info{
					ESPInitiatorSPI:           0x01020304,
					ESPResponderSPI:           0x10203040,
					Encryption:                transformENCRAESCBC,
					EncryptionKeyLen:          128,
					Integrity:                 transformINTEGHMACSHA196,
					InitiatorTrafficSelectors: tsi,
					ResponderTrafficSelectors: tsr,
				}
			},
			run: func(session *Session) {
				session.childSARekeyLoop()
			},
		},
		{
			name: "ike sa",
			prepare: func(session *Session) {
				session.ikeSARekeyAt = time.Now().Add(-time.Second)
				session.ikeSAExpiresAt = time.Now().Add(time.Hour)
			},
			run: func(session *Session) {
				session.ikeSARekeyLoop()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.mu.Lock()
			session.cfg.IKERetransmitDelays = []time.Duration{time.Millisecond}
			session.ike = testIKECrypto()
			session.ikeLocalInitiator = true
			session.initiatorSPI = 0x0102030405060708
			session.responderSPI = 0x1112131415161718
			tt.prepare(session)
			session.mu.Unlock()

			done := make(chan struct{})
			session.wg.Add(1)
			go func() {
				tt.run(session)
				close(done)
			}()

			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("rekey loop did not exit after incomplete request")
			}
			if err := session.closeCtx.Err(); !errors.Is(err, context.Canceled) {
				t.Fatalf("closeCtx error = %v, want canceled after incomplete request", err)
			}
		})
	}
}

func TestCacheInformationalResponseEvictsOldEntries(t *testing.T) {
	tests := []struct {
		name    string
		startID uint32
		count   int
		evicted uint32
		kept    uint32
	}{
		{name: "small ids", startID: 1, count: informationalResponseCacheWindow + 1, evicted: 1, kept: informationalResponseCacheWindow + 1},
		{name: "near max ids", startID: maxIKEMessageID - informationalResponseCacheWindow, count: informationalResponseCacheWindow + 1, evicted: maxIKEMessageID - informationalResponseCacheWindow, kept: maxIKEMessageID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{}

			for i := range tt.count {
				id := tt.startID + uint32(i)
				session.cacheInformationalResponse(id, nil, []byte{byte(id)})
			}

			if _, ok := session.cachedInformationalResponse(tt.evicted, nil); ok {
				t.Fatalf("cachedInformationalResponse(%d) = ok, want evicted entry", tt.evicted)
			}
			if wire, ok := session.cachedInformationalResponse(tt.kept, nil); !ok || len(wire) != 1 || wire[0] != byte(tt.kept) {
				t.Fatalf("cachedInformationalResponse(%d) = %v, %t", tt.kept, wire, ok)
			}
		})
	}
}

func TestCachedInformationalResponseRequiresMatchingRequest(t *testing.T) {
	tests := []struct {
		name    string
		request []byte
		lookup  []byte
		wantOK  bool
	}{
		{name: "bitwise retransmit", request: []byte{0x01, 0x02}, lookup: []byte{0x01, 0x02}, wantOK: true},
		{name: "same message id different request", request: []byte{0x01, 0x02}, lookup: []byte{0x01, 0x03}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{}
			session.cacheInformationalResponse(4, tt.request, []byte{0xaa})

			wire, ok := session.cachedInformationalResponse(4, tt.lookup)

			if ok != tt.wantOK {
				t.Fatalf("cachedInformationalResponse() ok = %t, want %t", ok, tt.wantOK)
			}
			if tt.wantOK && !bytes.Equal(wire, []byte{0xaa}) {
				t.Fatalf("cachedInformationalResponse() wire = %x, want aa", wire)
			}
		})
	}
}

func TestInformationalWaitersAreScopedByIKESA(t *testing.T) {
	tests := []struct {
		name         string
		oldKey       ikeMessageKey
		newKey       ikeMessageKey
		responseData []byte
	}{
		{
			name:         "same message id on old and new ike sa",
			oldKey:       ikeMessageKeyForSPIs(0x0102030405060708, 0x1112131415161718, 0),
			newKey:       ikeMessageKeyForSPIs(0x2122232425262728, 0x3132333435363738, 0),
			responseData: []byte{0xaa},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{}
			oldWaiter := session.registerInformationalWaiter(tt.oldKey)
			newWaiter := session.registerInformationalWaiter(tt.newKey)

			if !session.deliverInformationalWaiter(tt.newKey, inboundIKE{data: tt.responseData}) {
				t.Fatal("deliverInformationalWaiter(new) = false, want true")
			}

			select {
			case got := <-newWaiter:
				if !bytes.Equal(got.data, tt.responseData) {
					t.Fatalf("new waiter data = %x, want %x", got.data, tt.responseData)
				}
			default:
				t.Fatal("new waiter was not notified")
			}
			select {
			case got := <-oldWaiter:
				t.Fatalf("old waiter received response for new IKE SA: %+v", got)
			default:
			}

			session.mu.RLock()
			_, oldStillWaiting := session.informWaiters[tt.oldKey]
			_, newStillWaiting := session.informWaiters[tt.newKey]
			session.mu.RUnlock()
			if !oldStillWaiting {
				t.Fatal("old waiter was removed by new IKE SA response")
			}
			if newStillWaiting {
				t.Fatal("new waiter still registered after delivery")
			}
		})
	}
}

func TestHandleProtectedResponseWithoutWaiterDoesNotCountAsTraffic(t *testing.T) {
	tests := []struct {
		name         string
		exchangeType byte
		handle       func(*Session, informationalState, ike.IKEPacket, []byte, net.Addr) (bool, error)
	}{
		{
			name:         "informational",
			exchangeType: exchangeTypeInformational,
			handle:       (*Session).handleInformationalResponse,
		},
		{
			name:         "create child sa",
			exchangeType: exchangeTypeCreateChildSA,
			handle:       (*Session).handleCreateChildSAResponse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crypto := testIKECrypto()
			wire := protectedIKEWire(t, crypto, tt.exchangeType, flagResponse, 4, nil, false)
			var packet ike.IKEPacket
			if err := packet.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			oldRx := time.Now().Add(-time.Minute)
			session := &Session{
				logger:             testLogger(),
				closeCtx:           context.Background(),
				ike:                crypto,
				lastProtectedRx:    oldRx,
				ikeSAByteExpiresAt: 1,
			}
			state := informationalState{
				ike:            crypto,
				localInitiator: true,
				initiatorSPI:   packet.Header.InitiatorSPI,
				responderSPI:   packet.Header.ResponderSPI,
			}

			handled, err := tt.handle(session, state, packet, wire, nil)
			if err != nil {
				t.Fatalf("handle response error = %v", err)
			}
			if !handled {
				t.Fatal("handle response = false, want true")
			}
			if !session.lastProtectedRx.Equal(oldRx) {
				t.Fatalf("lastProtectedRx = %s, want unchanged %s", session.lastProtectedRx, oldRx)
			}
			if session.ikeSAInboundBytes != 0 {
				t.Fatalf("ikeSAInboundBytes = %d, want 0", session.ikeSAInboundBytes)
			}
		})
	}
}
