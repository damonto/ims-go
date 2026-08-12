package tunnel

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/damonto/ims-go/swu/ike"
)

func TestIKEFragmentReassemblyRoundTrip(t *testing.T) {
	crypto := testIKECrypto()
	wantData := bytes.Repeat([]byte{0xab}, 1800)
	payloads := []ike.Payload{&ike.NotifyPayload{NotifyType: notifyTypeTemporaryFailure, Data: wantData}}
	header := ike.Header{
		InitiatorSPI: 0x0102030405060708,
		ResponderSPI: 0x1112131415161718,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeIKEAuth,
		Flags:        flagInitiator,
		MessageID:    3,
	}

	packets, err := crypto.SealIKEFragments(header, payloads, true, 320)
	if err != nil {
		t.Fatalf("SealIKEFragments() error = %v", err)
	}
	if len(packets) < 2 {
		t.Fatalf("fragment count = %d, want multiple fragments", len(packets))
	}

	reassembly := ikeFragmentReassembly{}
	var firstPacket []byte
	for i, wire := range packets {
		var packet ike.Packet
		if err := packet.UnmarshalBinary(wire); err != nil {
			t.Fatalf("fragment %d UnmarshalBinary() error = %v", i+1, err)
		}
		fragmentPayload, ok := packet.Payloads[0].(*ike.EncryptedFragmentPayload)
		if !ok {
			t.Fatalf("fragment %d payload = %T, want *ike.EncryptedFragmentPayload", i+1, packet.Payloads[0])
		}
		if int(fragmentPayload.FragmentNumber) != i+1 {
			t.Fatalf("fragment number = %d, want %d", fragmentPayload.FragmentNumber, i+1)
		}
		fragment, err := crypto.OpenIKEFragment(packet, true)
		if err != nil {
			t.Fatalf("OpenIKEFragment(%d) error = %v", i+1, err)
		}
		gotPayloads, gotFirstPacket, complete, stored, err := reassembly.add(fragment, packet.Raw)
		if err != nil {
			t.Fatalf("reassembly.add(%d) error = %v", i+1, err)
		}
		if !stored {
			t.Fatalf("reassembly.add(%d) stored = false, want true", i+1)
		}
		if i+1 < len(packets) && complete {
			t.Fatalf("reassembly completed after fragment %d, want incomplete", i+1)
		}
		if i+1 == len(packets) {
			if !complete {
				t.Fatal("reassembly did not complete after final fragment")
			}
			firstPacket = gotFirstPacket
			notify := ike.FindNotifyPayload(gotPayloads, notifyTypeTemporaryFailure)
			if notify == nil {
				t.Fatalf("reassembled payloads = %T, want TEMPORARY_FAILURE notify", gotPayloads)
			}
			if !bytes.Equal(notify.Data, wantData) {
				t.Fatalf("notify data length = %d, want %d", len(notify.Data), len(wantData))
			}
		}
	}
	if !bytes.Equal(firstPacket, packets[0]) {
		t.Fatalf("reassembled first packet = %x, want first fragment %x", firstPacket, packets[0])
	}
}

func TestDefaultIKEFragmentSizeFitsRFC7383DatagramThresholds(t *testing.T) {
	crypto := testIKECrypto()
	payloads := []ike.Payload{
		&ike.NotifyPayload{NotifyType: notifyTypeTemporaryFailure, Data: bytes.Repeat([]byte{0xab}, 1800)},
	}
	packets, err := crypto.SealIKEFragments(ike.Header{
		InitiatorSPI: 0x0102030405060708,
		ResponderSPI: 0x1112131415161718,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeInformational,
		Flags:        flagInitiator,
		MessageID:    3,
	}, payloads, true, defaultIKEFragmentSize)
	if err != nil {
		t.Fatalf("SealIKEFragments() error = %v", err)
	}
	if len(packets) < 2 {
		t.Fatalf("fragment count = %d, want multiple fragments", len(packets))
	}

	tests := []struct {
		name         string
		ipHeaderSize int
		threshold    int
	}{
		{name: "ipv4", ipHeaderSize: 20, threshold: 576},
		{name: "ipv6", ipHeaderSize: 40, threshold: 1280},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const udpHeaderSize = 8
			for i, packet := range packets {
				wire := buildIKEWire(packet, true)
				got := tt.ipHeaderSize + udpHeaderSize + len(wire)
				if got > tt.threshold {
					t.Fatalf("fragment %d IP datagram size = %d, threshold = %d", i+1, got, tt.threshold)
				}
			}
		})
	}
}

func TestIKEFragmentReassemblySilentlyDiscardsInvalidFragments(t *testing.T) {
	tests := []struct {
		name      string
		existing  []ikeFragment
		incoming  ikeFragment
		wantTotal uint16
		wantCount int
	}{
		{
			name:     "zero fragment number",
			incoming: ikeFragment{firstPayload: payloadTypeNone, number: 0, total: 2},
		},
		{
			name:     "fragment number exceeds total",
			incoming: ikeFragment{firstPayload: payloadTypeNone, number: 3, total: 2},
		},
		{
			name: "smaller total after reassembly started",
			existing: []ikeFragment{
				{firstPayload: payloadTypeNone, number: 1, total: 3, data: []byte{0x01}},
			},
			incoming:  ikeFragment{firstPayload: payloadTypeNone, number: 1, total: 2, data: []byte{0x02}},
			wantTotal: 3,
			wantCount: 1,
		},
		{
			name: "replayed fragment",
			existing: []ikeFragment{
				{firstPayload: payloadTypeNone, number: 1, total: 3, data: []byte{0x01}},
			},
			incoming:  ikeFragment{firstPayload: payloadTypeNone, number: 1, total: 3, data: []byte{0x02}},
			wantTotal: 3,
			wantCount: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reassembly := ikeFragmentReassembly{}
			for i, fragment := range tt.existing {
				if _, _, complete, stored, err := reassembly.add(fragment, []byte{byte(i + 1)}); err != nil || complete || !stored {
					t.Fatalf("seed add(%d) complete = %t, stored = %t, err = %v", i, complete, stored, err)
				}
			}

			_, _, complete, stored, err := reassembly.add(tt.incoming, []byte{0xff})
			if err != nil {
				t.Fatalf("reassembly.add() error = %v, want silent discard", err)
			}
			if stored {
				t.Fatal("reassembly.add() stored = true, want false")
			}
			if complete {
				t.Fatal("reassembly.add() complete = true, want false")
			}
			if reassembly.total != tt.wantTotal {
				t.Fatalf("total = %d, want %d", reassembly.total, tt.wantTotal)
			}
			if len(reassembly.fragments) != tt.wantCount {
				t.Fatalf("fragment count = %d, want %d", len(reassembly.fragments), tt.wantCount)
			}
		})
	}
}

func TestIKEMessageKeysSeparateDirections(t *testing.T) {
	tests := []struct {
		name string
		a    ikeMessageKey
		b    ikeMessageKey
	}{
		{
			name: "request and response share message id",
			a:    ikeMessageKeyForSPIs(1, 2, exchangeTypeInformational, 0, 7),
			b:    ikeMessageKeyForSPIs(1, 2, exchangeTypeInformational, flagResponse, 7),
		},
		{
			name: "different exchange types share message id",
			a:    ikeMessageKeyForSPIs(1, 2, exchangeTypeInformational, flagResponse, 7),
			b:    ikeMessageKeyForSPIs(1, 2, exchangeTypeCreateChildSA, flagResponse, 7),
		},
		{
			name: "original initiator flag disambiguates peer direction",
			a:    ikeMessageKeyForSPIs(1, 2, exchangeTypeCreateChildSA, flagResponse, 7),
			b:    ikeMessageKeyForSPIs(1, 2, exchangeTypeCreateChildSA, flagResponse|flagInitiator, 7),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.a == tt.b {
				t.Fatalf("keys are equal: %+v", tt.a)
			}
		})
	}
}

func TestIKEFragmentQueuesAreScopedByDirection(t *testing.T) {
	tests := []struct {
		name       string
		keptKey    ikeMessageKey
		clearedKey ikeMessageKey
	}{
		{
			name:       "response queue survives request clear",
			keptKey:    ikeMessageKeyForSPIs(1, 2, exchangeTypeInformational, flagResponse, 9),
			clearedKey: ikeMessageKeyForSPIs(1, 2, exchangeTypeInformational, 0, 9),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{}
			if _, _, complete, stored, err := session.addIKEFragment(tt.keptKey, ikeFragment{firstPayload: payloadTypeNone, number: 1, total: 2, data: []byte{0x01}}, []byte{0x01}); err != nil || complete || !stored {
				t.Fatalf("addIKEFragment() complete = %t, stored = %t, err = %v", complete, stored, err)
			}

			session.clearIKEFragments(tt.clearedKey)

			session.mu.RLock()
			_, ok := session.ikeFragments[tt.keptKey]
			session.mu.RUnlock()
			if !ok {
				t.Fatal("kept direction fragment queue was cleared")
			}
		})
	}
}

func TestIKEFragmentQueuesExpireBeforeAddingNewFragment(t *testing.T) {
	session := &Session{cfg: Config{IKERetransmitDelays: []time.Duration{time.Millisecond}}}
	expiredKey := ikeMessageKeyForSPIs(1, 2, exchangeTypeInformational, 0, 1)
	keptKey := ikeMessageKeyForSPIs(1, 2, exchangeTypeInformational, 0, 2)
	if _, _, complete, stored, err := session.addIKEFragment(expiredKey, ikeFragment{firstPayload: payloadTypeNone, number: 1, total: 2, data: []byte{0x01}}, []byte{0x01}); err != nil || complete || !stored {
		t.Fatalf("addIKEFragment(expired seed) complete = %t, stored = %t, err = %v", complete, stored, err)
	}
	session.mu.Lock()
	session.ikeFragments[expiredKey].expiresAt = time.Now().Add(-time.Nanosecond)
	session.mu.Unlock()

	if _, _, complete, stored, err := session.addIKEFragment(keptKey, ikeFragment{firstPayload: payloadTypeNone, number: 1, total: 2, data: []byte{0x02}}, []byte{0x02}); err != nil || complete || !stored {
		t.Fatalf("addIKEFragment(kept) complete = %t, stored = %t, err = %v", complete, stored, err)
	}

	session.mu.RLock()
	_, expiredQueued := session.ikeFragments[expiredKey]
	_, keptQueued := session.ikeFragments[keptKey]
	session.mu.RUnlock()
	if expiredQueued {
		t.Fatal("expired fragment queue was not pruned")
	}
	if !keptQueued {
		t.Fatal("new fragment queue was not kept")
	}
}

func TestIKEFragmentReassemblyLimits(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "byte cap",
			run: func(t *testing.T) {
				reassembly := ikeFragmentReassembly{}
				now := time.Now()
				if _, _, complete, stored, err := reassembly.addAt(ikeFragment{firstPayload: payloadTypeNone, number: 1, total: 2, data: []byte{0x01, 0x02}}, []byte{0x01}, now, time.Minute, 3); err != nil || complete || !stored {
					t.Fatalf("seed addAt() complete = %t, stored = %t, err = %v", complete, stored, err)
				}
				_, _, complete, stored, err := reassembly.addAt(ikeFragment{firstPayload: payloadTypeNone, number: 2, total: 2, data: []byte{0x03, 0x04}}, []byte{0x02}, now, time.Minute, 3)
				if !errors.Is(err, errIKEFragmentReassemblyTooLarge) {
					t.Fatalf("addAt() err = %v, want %v", err, errIKEFragmentReassemblyTooLarge)
				}
				if complete || stored {
					t.Fatalf("addAt() complete = %t, stored = %t, want false/false", complete, stored)
				}
			},
		},
		{
			name: "queue cap",
			run: func(t *testing.T) {
				session := &Session{}
				for i := range maxIKEFragmentReassemblyQueues {
					key := ikeMessageKeyForSPIs(1, 2, exchangeTypeInformational, 0, uint32(i))
					if _, _, complete, stored, err := session.addIKEFragment(key, ikeFragment{firstPayload: payloadTypeNone, number: 1, total: 2, data: []byte{byte(i)}}, []byte{byte(i)}); err != nil || complete || !stored {
						t.Fatalf("seed addIKEFragment(%d) complete = %t, stored = %t, err = %v", i, complete, stored, err)
					}
				}
				key := ikeMessageKeyForSPIs(1, 2, exchangeTypeInformational, 0, maxIKEFragmentReassemblyQueues)
				_, _, complete, stored, err := session.addIKEFragment(key, ikeFragment{firstPayload: payloadTypeNone, number: 1, total: 2, data: []byte{0xff}}, []byte{0xff})
				if !errors.Is(err, errIKEFragmentReassemblyTooLarge) {
					t.Fatalf("addIKEFragment() err = %v, want %v", err, errIKEFragmentReassemblyTooLarge)
				}
				if complete || stored {
					t.Fatalf("addIKEFragment() complete = %t, stored = %t, want false/false", complete, stored)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

func TestPostAuthIKEWiresFollowNATTState(t *testing.T) {
	crypto := testIKECrypto()
	packet := protectedIKEWire(t, crypto, exchangeTypeInformational, flagInitiator, 7, []ike.Payload{&ike.NotifyPayload{NotifyType: notifyTypeCookie2}}, true)
	tests := []struct {
		name       string
		useNATT    bool
		peer       *net.UDPAddr
		wantMarker bool
		write      func(context.Context, *Session, *ikeCrypto, *net.UDPAddr, bool, [][]byte) error
	}{
		{
			name:       "informational udp 500",
			peer:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 500},
			wantMarker: false,
			write: func(ctx context.Context, session *Session, crypto *ikeCrypto, peer *net.UDPAddr, useNATT bool, wires [][]byte) error {
				state := informationalState{ike: crypto, peer: peer, useNATT: useNATT}
				return session.writeInformationalRequest(ctx, state, wires, ikeActionTestInformational, false)
			},
		},
		{
			name:       "informational udp 4500",
			useNATT:    true,
			peer:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500},
			wantMarker: true,
			write: func(ctx context.Context, session *Session, crypto *ikeCrypto, peer *net.UDPAddr, useNATT bool, wires [][]byte) error {
				state := informationalState{ike: crypto, peer: peer, useNATT: useNATT}
				return session.writeInformationalRequest(ctx, state, wires, ikeActionTestInformational, false)
			},
		},
		{
			name:       "protected exchange udp 500",
			peer:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 500},
			wantMarker: false,
			write: func(ctx context.Context, session *Session, crypto *ikeCrypto, peer *net.UDPAddr, useNATT bool, wires [][]byte) error {
				return session.writeProtectedRequest(ctx, protectedExchange{action: ikeActionTestProtected, crypto: crypto, peer: peer, useNATT: useNATT, wires: wires})
			},
		},
		{
			name:       "protected exchange udp 4500",
			useNATT:    true,
			peer:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500},
			wantMarker: true,
			write: func(ctx context.Context, session *Session, crypto *ikeCrypto, peer *net.UDPAddr, useNATT bool, wires [][]byte) error {
				return session.writeProtectedRequest(ctx, protectedExchange{action: ikeActionTestProtected, crypto: crypto, peer: peer, useNATT: useNATT, wires: wires})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session := mustDialSession(t, conn)

			if err := tt.write(t.Context(), session, crypto, tt.peer, tt.useNATT, [][]byte{packet}); err != nil {
				t.Fatalf("write() error = %v", err)
			}

			if len(conn.writes) != 1 {
				t.Fatalf("writes = %d, want 1", len(conn.writes))
			}
			if got := hasNonESPMarker(conn.writes[0]); got != tt.wantMarker {
				t.Fatalf("hasNonESPMarker() = %t, want %t", got, tt.wantMarker)
			}
		})
	}
}

func TestPostAuthProtectedMessagesUseNegotiatedFragmentation(t *testing.T) {
	largeNotify := []ike.Payload{&ike.NotifyPayload{NotifyType: notifyTypeTemporaryFailure, Data: bytes.Repeat([]byte{0xee}, 1800)}}
	selectors := make([]ike.TrafficSelector, 0, 80)
	for range 40 {
		selectors = append(selectors, ike.TrafficSelectorsAny()...)
	}
	tests := []struct {
		name         string
		buildPackets func(*testing.T, *ikeCrypto) [][]byte
		exchangeType byte
		marked       bool
	}{
		{
			name: "informational initiator request",
			buildPackets: func(t *testing.T, crypto *ikeCrypto) [][]byte {
				t.Helper()
				state := informationalState{
					ike:                       crypto,
					localInitiator:            true,
					ikeFragmentationSupported: true,
					initiatorSPI:              0x0102030405060708,
					responderSPI:              0x1112131415161718,
				}
				packets, err := state.sealInitiatorRequest(8, largeNotify)
				if err != nil {
					t.Fatalf("sealInitiatorRequest() error = %v", err)
				}
				return packets
			},
			exchangeType: exchangeTypeInformational,
		},
		{
			name: "informational response",
			buildPackets: func(t *testing.T, crypto *ikeCrypto) [][]byte {
				t.Helper()
				session := &Session{}
				state := informationalState{
					ike:                       crypto,
					localInitiator:            true,
					ikeFragmentationSupported: true,
					useNATT:                   true,
					initiatorSPI:              0x0102030405060708,
					responderSPI:              0x1112131415161718,
				}
				packets, err := session.sealInformationalResponse(state, 8, largeNotify)
				if err != nil {
					t.Fatalf("sealInformationalResponse() error = %v", err)
				}
				return packets
			},
			exchangeType: exchangeTypeInformational,
			marked:       true,
		},
		{
			name: "child sa rekey request",
			buildPackets: func(t *testing.T, crypto *ikeCrypto) [][]byte {
				t.Helper()
				state := childSARekeyState{
					ike:                       crypto,
					info:                      Info{EncryptionKeyLen: 128, Integrity: transformINTEGHMACSHA196, InitiatorTrafficSelectors: selectors, ResponderTrafficSelectors: selectors},
					initiatorSPI:              0x0102030405060708,
					responderSPI:              0x1112131415161718,
					localInitiator:            true,
					ikeFragmentationSupported: true,
					inboundSPI:                0x01020304,
					outboundSPI:               0x10203040,
				}
				packets, err := state.sealChildSARekeyRequest(8, 0x20304050, testNonce("child rekey"), nil)
				if err != nil {
					t.Fatalf("sealChildSARekeyRequest() error = %v", err)
				}
				return packets
			},
			exchangeType: exchangeTypeCreateChildSA,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packets := tt.buildPackets(t, testIKECrypto())
			if len(packets) < 2 {
				t.Fatalf("fragment count = %d, want multiple fragments", len(packets))
			}
			wire := packets[0]
			if tt.marked {
				wire = normalizeIKEPacket(wire, true)
			}
			var packet ike.Packet
			if err := packet.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary(first fragment) error = %v", err)
			}
			if packet.Header.ExchangeType != tt.exchangeType {
				t.Fatalf("exchange type = %d, want %d", packet.Header.ExchangeType, tt.exchangeType)
			}
			if _, ok := packet.Payloads[0].(*ike.EncryptedFragmentPayload); !ok {
				t.Fatalf("payload = %T, want *ike.EncryptedFragmentPayload", packet.Payloads[0])
			}
		})
	}
}

func TestCachedResponseMatchesFirstFragmentOnly(t *testing.T) {
	tests := []struct {
		name       string
		lookup     []byte
		wantCached bool
	}{
		{name: "first fragment retransmit", lookup: []byte{0x01}, wantCached: true},
		{name: "non first fragment retransmit", lookup: []byte{0x02}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{}
			session.cacheInformationalResponse(3, []byte{0x01}, [][]byte{{0xaa}, {0xbb}})

			got, ok := session.cachedInformationalResponse(3, tt.lookup)

			if ok != tt.wantCached {
				t.Fatalf("cachedInformationalResponse() ok = %t, want %t", ok, tt.wantCached)
			}
			if tt.wantCached && (len(got) != 2 || !bytes.Equal(got[0], []byte{0xaa}) || !bytes.Equal(got[1], []byte{0xbb})) {
				t.Fatalf("cached packets = %x, want aa/bb", got)
			}
		})
	}
}

func TestFragmentedRequestRetransmitFirstFragmentResendsCachedResponse(t *testing.T) {
	const messageID uint32 = 3
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
	responsePayloads := []ike.Payload{&ike.NotifyPayload{NotifyType: notifyTypeTemporaryFailure, Data: bytes.Repeat([]byte{0xee}, 3000)}}
	tests := []struct {
		name          string
		exchangeType  byte
		responseWires func(*testing.T, *Session, *ikeCrypto, uint32, []ike.Payload) [][]byte
		handle        func(*testing.T, *Session, *ikeCrypto, *net.UDPAddr, ike.Packet)
	}{
		{
			name:         "informational",
			exchangeType: exchangeTypeInformational,
			responseWires: func(t *testing.T, session *Session, crypto *ikeCrypto, messageID uint32, payloads []ike.Payload) [][]byte {
				t.Helper()
				state := informationalState{
					ike:                       crypto,
					localInitiator:            true,
					ikeFragmentationSupported: true,
					useNATT:                   true,
					initiatorSPI:              0x0102030405060708,
					responderSPI:              0x1112131415161718,
				}
				wires, err := session.sealInformationalResponse(state, messageID, payloads)
				if err != nil {
					t.Fatalf("sealInformationalResponse() error = %v", err)
				}
				return wires
			},
			handle: func(t *testing.T, session *Session, crypto *ikeCrypto, peer *net.UDPAddr, packet ike.Packet) {
				t.Helper()
				state := informationalState{
					ike:                       crypto,
					localInitiator:            true,
					ikeFragmentationSupported: true,
					useNATT:                   true,
					initiatorSPI:              0x0102030405060708,
					responderSPI:              0x1112131415161718,
					peer:                      peer,
				}
				ok, err := session.handleInformationalRequest(state, packet, peer)
				if !ok || err != nil {
					t.Fatalf("handleInformationalRequest() = (%t, %v), want handled without error", ok, err)
				}
			},
		},
		{
			name:         "create child sa",
			exchangeType: exchangeTypeCreateChildSA,
			responseWires: func(t *testing.T, _ *Session, crypto *ikeCrypto, messageID uint32, payloads []ike.Payload) [][]byte {
				t.Helper()
				state := createChildSARequestState{
					ike:                       crypto,
					localInitiator:            true,
					ikeFragmentationSupported: true,
					useNATT:                   true,
					initiatorSPI:              0x0102030405060708,
					responderSPI:              0x1112131415161718,
				}
				wires, err := sealIKEPackets(crypto, createChildSAResponseHeader(state, messageID), payloads, state.localInitiator, state.ikeFragmentationSupported)
				if err != nil {
					t.Fatalf("sealIKEPackets(create child response) error = %v", err)
				}
				return buildIKEWires(wires, state.useNATT)
			},
			handle: func(t *testing.T, session *Session, crypto *ikeCrypto, peer *net.UDPAddr, packet ike.Packet) {
				t.Helper()
				state := createChildSARequestState{
					ike:                       crypto,
					localInitiator:            true,
					ikeFragmentationSupported: true,
					useNATT:                   true,
					initiatorSPI:              0x0102030405060708,
					responderSPI:              0x1112131415161718,
					peer:                      peer,
				}
				ok, err := session.handleCreateChildSARequest(state, packet, peer)
				if !ok || err != nil {
					t.Fatalf("handleCreateChildSARequest() = (%t, %v), want handled without error", ok, err)
				}
			},
		},
	}
	fragments := []struct {
		name       string
		index      int
		wantWrites bool
	}{
		{name: "first fragment", index: 0, wantWrites: true},
		{name: "non first fragment", index: 1},
	}
	for _, tt := range tests {
		for _, fragment := range fragments {
			t.Run(tt.name+"/"+fragment.name, func(t *testing.T) {
				conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
				session := mustDialSession(t, conn)
				crypto := testIKECrypto()
				requests := fragmentedPeerRequestPackets(t, crypto, tt.exchangeType, messageID)
				responses := tt.responseWires(t, session, crypto, messageID, responsePayloads)
				if len(responses) < 2 {
					t.Fatalf("cached response fragment count = %d, want multiple packets", len(responses))
				}
				session.cacheInformationalResponse(messageID, requests[0], responses)
				session.mu.Lock()
				session.ike = crypto
				session.ikeLocalInitiator = true
				session.ikeFragmentationSupported = true
				session.initiatorSPI = 0x0102030405060708
				session.responderSPI = 0x1112131415161718
				session.outerNAT = cloneUDPAddr(peer)
				session.nextPeerMessageID = messageID + 1
				session.mu.Unlock()
				var packet ike.Packet
				if err := packet.UnmarshalBinary(requests[fragment.index]); err != nil {
					t.Fatalf("UnmarshalBinary(request fragment) error = %v", err)
				}

				tt.handle(t, session, crypto, peer, packet)

				if !fragment.wantWrites {
					if len(conn.writes) != 0 {
						t.Fatalf("writes = %d, want no cached response", len(conn.writes))
					}
					return
				}
				if len(conn.writes) != len(responses) {
					t.Fatalf("writes = %d, want %d cached response packets", len(conn.writes), len(responses))
				}
				for i, response := range responses {
					if !bytes.Equal(conn.writes[i], response) {
						t.Fatalf("write %d = %x, want cached response %x", i, conn.writes[i], response)
					}
				}
				conn.writes = nil
				var nextPacket ike.Packet
				if err := nextPacket.UnmarshalBinary(requests[1]); err != nil {
					t.Fatalf("UnmarshalBinary(next request fragment) error = %v", err)
				}
				tt.handle(t, session, crypto, peer, nextPacket)
				if len(conn.writes) != 0 {
					t.Fatalf("writes after non-first fragment = %d, want no cached response", len(conn.writes))
				}
			})
		}
	}
}

func TestFragmentedProtectedErrorResponseCachesFirstFragment(t *testing.T) {
	const messageID uint32 = 0
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
	tests := []struct {
		name         string
		exchangeType byte
		handle       func(*testing.T, *Session, *ikeCrypto, *net.UDPAddr, ike.Packet)
	}{
		{
			name:         "informational",
			exchangeType: exchangeTypeInformational,
			handle: func(t *testing.T, session *Session, crypto *ikeCrypto, peer *net.UDPAddr, packet ike.Packet) {
				t.Helper()
				state := informationalState{
					ike:                       crypto,
					localInitiator:            true,
					ikeFragmentationSupported: true,
					initiatorSPI:              0x0102030405060708,
					responderSPI:              0x1112131415161718,
					peer:                      peer,
				}
				ok, err := session.handleInformationalRequest(state, packet, peer)
				if !ok || err != nil {
					t.Fatalf("handleInformationalRequest() = (%t, %v), want handled without error", ok, err)
				}
			},
		},
		{
			name:         "create child sa",
			exchangeType: exchangeTypeCreateChildSA,
			handle: func(t *testing.T, session *Session, crypto *ikeCrypto, peer *net.UDPAddr, packet ike.Packet) {
				t.Helper()
				state := createChildSARequestState{
					ike:                       crypto,
					localInitiator:            true,
					ikeFragmentationSupported: true,
					initiatorSPI:              0x0102030405060708,
					responderSPI:              0x1112131415161718,
					peer:                      peer,
				}
				ok, err := session.handleCreateChildSARequest(state, packet, peer)
				if !ok || err != nil {
					t.Fatalf("handleCreateChildSARequest() = (%t, %v), want handled without error", ok, err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session := mustDialSession(t, conn)
			crypto := testIKECrypto()
			session.mu.Lock()
			session.connected = true
			session.ike = crypto
			session.ikeLocalInitiator = true
			session.ikeFragmentationSupported = true
			session.initiatorSPI = 0x0102030405060708
			session.responderSPI = 0x1112131415161718
			session.outerNAT = cloneUDPAddr(peer)
			session.nextPeerMessageID = messageID
			session.mu.Unlock()
			requests := fragmentedPeerRawPlainPackets(t, crypto, tt.exchangeType, messageID, (&ike.NotifyPayload{}).Type(), []byte{0x00, 0x00, 0x00, 0x04})
			for i, wire := range requests {
				var packet ike.Packet
				if err := packet.UnmarshalBinary(wire); err != nil {
					t.Fatalf("UnmarshalBinary(fragment %d) error = %v", i+1, err)
				}
				tt.handle(t, session, crypto, peer, packet)
				if i == 0 && len(conn.writes) != 0 {
					t.Fatalf("writes after first fragment = %d, want none before reassembly completes", len(conn.writes))
				}
			}
			if len(conn.writes) != 1 {
				t.Fatalf("writes = %d, want INVALID_SYNTAX response", len(conn.writes))
			}
			cached, ok := session.cachedInformationalResponse(messageID, requests[0])
			if !ok {
				t.Fatal("response was not cached under the first fragment")
			}
			if _, ok := session.cachedInformationalResponse(messageID, requests[1]); ok {
				t.Fatal("response was cached under the final fragment")
			}
			if len(cached) != len(conn.writes) || !bytes.Equal(cached[0], conn.writes[0]) {
				t.Fatalf("cached response = %x, want written response %x", cached, conn.writes)
			}
			conn.writes = nil
			var first ike.Packet
			if err := first.UnmarshalBinary(requests[0]); err != nil {
				t.Fatalf("UnmarshalBinary(first fragment retransmit) error = %v", err)
			}

			tt.handle(t, session, crypto, peer, first)

			if len(conn.writes) != len(cached) {
				t.Fatalf("retransmit writes = %d, want %d cached packets", len(conn.writes), len(cached))
			}
			for i, response := range cached {
				if !bytes.Equal(conn.writes[i], response) {
					t.Fatalf("retransmit write %d = %x, want cached response %x", i, conn.writes[i], response)
				}
			}
		})
	}
}

func TestNonCurrentFragmentedRequestsDoNotTouchReassembly(t *testing.T) {
	const expectedMessageID uint32 = 6
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
	tests := []struct {
		name         string
		exchangeType byte
		messageID    uint32
		fragment     int
		wantWrites   bool
		handle       func(*testing.T, *Session, *ikeCrypto, *net.UDPAddr, ike.Packet)
	}{
		{
			name:         "informational future first fragment",
			exchangeType: exchangeTypeInformational,
			messageID:    expectedMessageID + 1,
			fragment:     0,
			wantWrites:   true,
			handle: func(t *testing.T, session *Session, crypto *ikeCrypto, peer *net.UDPAddr, packet ike.Packet) {
				t.Helper()
				state := informationalState{
					ike:                       crypto,
					localInitiator:            true,
					ikeFragmentationSupported: true,
					initiatorSPI:              0x0102030405060708,
					responderSPI:              0x1112131415161718,
					peer:                      peer,
				}
				ok, err := session.handleInformationalRequest(state, packet, peer)
				if !ok || err != nil {
					t.Fatalf("handleInformationalRequest() = (%t, %v), want handled without error", ok, err)
				}
			},
		},
		{
			name:         "informational old non-first fragment",
			exchangeType: exchangeTypeInformational,
			messageID:    expectedMessageID - 1,
			fragment:     1,
			handle: func(t *testing.T, session *Session, crypto *ikeCrypto, peer *net.UDPAddr, packet ike.Packet) {
				t.Helper()
				state := informationalState{
					ike:                       crypto,
					localInitiator:            true,
					ikeFragmentationSupported: true,
					initiatorSPI:              0x0102030405060708,
					responderSPI:              0x1112131415161718,
					peer:                      peer,
				}
				ok, err := session.handleInformationalRequest(state, packet, peer)
				if !ok || err != nil {
					t.Fatalf("handleInformationalRequest() = (%t, %v), want handled without error", ok, err)
				}
			},
		},
		{
			name:         "create child future first fragment",
			exchangeType: exchangeTypeCreateChildSA,
			messageID:    expectedMessageID + 1,
			fragment:     0,
			wantWrites:   true,
			handle: func(t *testing.T, session *Session, crypto *ikeCrypto, peer *net.UDPAddr, packet ike.Packet) {
				t.Helper()
				state := createChildSARequestState{
					ike:                       crypto,
					localInitiator:            true,
					ikeFragmentationSupported: true,
					initiatorSPI:              0x0102030405060708,
					responderSPI:              0x1112131415161718,
					peer:                      peer,
				}
				ok, err := session.handleCreateChildSARequest(state, packet, peer)
				if !ok || err != nil {
					t.Fatalf("handleCreateChildSARequest() = (%t, %v), want handled without error", ok, err)
				}
			},
		},
		{
			name:         "create child old non-first fragment",
			exchangeType: exchangeTypeCreateChildSA,
			messageID:    expectedMessageID - 1,
			fragment:     1,
			handle: func(t *testing.T, session *Session, crypto *ikeCrypto, peer *net.UDPAddr, packet ike.Packet) {
				t.Helper()
				state := createChildSARequestState{
					ike:                       crypto,
					localInitiator:            true,
					ikeFragmentationSupported: true,
					initiatorSPI:              0x0102030405060708,
					responderSPI:              0x1112131415161718,
					peer:                      peer,
				}
				ok, err := session.handleCreateChildSARequest(state, packet, peer)
				if !ok || err != nil {
					t.Fatalf("handleCreateChildSARequest() = (%t, %v), want handled without error", ok, err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session := mustDialSession(t, conn)
			session.invalidMessageIDNotifyTimeout = time.Millisecond
			crypto := testIKECrypto()
			session.mu.Lock()
			session.connected = true
			session.ike = crypto
			session.ikeLocalInitiator = true
			session.ikeFragmentationSupported = true
			session.initiatorSPI = 0x0102030405060708
			session.responderSPI = 0x1112131415161718
			session.outerNAT = cloneUDPAddr(peer)
			session.nextPeerMessageID = expectedMessageID
			session.mu.Unlock()
			requests := fragmentedPeerRequestPackets(t, crypto, tt.exchangeType, tt.messageID)
			var packet ike.Packet
			if err := packet.UnmarshalBinary(requests[tt.fragment]); err != nil {
				t.Fatalf("UnmarshalBinary(fragment) error = %v", err)
			}

			tt.handle(t, session, crypto, peer, packet)

			key := ikeMessageKeyForHeader(packet.Header)
			session.mu.RLock()
			_, queued := session.ikeFragments[key]
			session.mu.RUnlock()
			if queued {
				t.Fatal("non-current fragment was queued for reassembly")
			}
			if tt.wantWrites {
				if len(conn.writes) == 0 {
					t.Fatal("writes = 0, want INVALID_MESSAGE_ID notification")
				}
				return
			}
			if len(conn.writes) != 0 {
				t.Fatalf("writes = %d, want old non-first fragment to be ignored", len(conn.writes))
			}
		})
	}
}

func fragmentedPeerRequestPackets(t *testing.T, crypto *ikeCrypto, exchangeType byte, messageID uint32) [][]byte {
	t.Helper()
	packets, err := crypto.SealIKEFragments(ike.Header{
		InitiatorSPI: 0x0102030405060708,
		ResponderSPI: 0x1112131415161718,
		Version:      ikeVersion20,
		ExchangeType: exchangeType,
		MessageID:    messageID,
	}, []ike.Payload{&ike.NotifyPayload{NotifyType: notifyTypeTemporaryFailure, Data: bytes.Repeat([]byte{0xcd}, 1600)}}, false, 320)
	if err != nil {
		t.Fatalf("SealIKEFragments(request) error = %v", err)
	}
	if len(packets) < 2 {
		t.Fatalf("request fragment count = %d, want multiple packets", len(packets))
	}
	return packets
}

func fragmentedPeerRawPlainPackets(t *testing.T, crypto *ikeCrypto, exchangeType byte, messageID uint32, firstPayload byte, plain []byte) [][]byte {
	t.Helper()
	if len(plain) < 2 {
		t.Fatalf("plain length = %d, want at least two bytes", len(plain))
	}
	chunks := [][]byte{plain[:len(plain)/2], plain[len(plain)/2:]}
	header := ike.Header{
		InitiatorSPI: 0x0102030405060708,
		ResponderSPI: 0x1112131415161718,
		Version:      ikeVersion20,
		ExchangeType: exchangeType,
		MessageID:    messageID,
	}
	packets := make([][]byte, 0, len(chunks))
	for i, chunk := range chunks {
		nextPayload := byte(payloadTypeNone)
		if i == 0 {
			nextPayload = firstPayload
		}
		raw, err := crypto.sealIKEPayloadBody(chunk, false)
		if err != nil {
			t.Fatalf("sealIKEPayloadBody(fragment %d) error = %v", i+1, err)
		}
		container := &ike.EncryptedFragmentPayload{
			NextPayload:    nextPayload,
			FragmentNumber: uint16(i + 1),
			TotalFragments: uint16(len(chunks)),
			Raw:            raw,
		}
		packet, err := crypto.sealIKEContainer(header, container, false)
		if err != nil {
			t.Fatalf("sealIKEContainer(fragment %d) error = %v", i+1, err)
		}
		packets = append(packets, packet)
	}
	return packets
}

func TestOpenIKEFragmentSilentlyDiscardsAuthenticationFailure(t *testing.T) {
	crypto := testIKECrypto()
	packets, err := crypto.SealIKEFragments(ike.Header{
		InitiatorSPI: 0x0102030405060708,
		ResponderSPI: 0x1112131415161718,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeIKEAuth,
		Flags:        flagResponse,
		MessageID:    4,
	}, []ike.Payload{&ike.NotifyPayload{NotifyType: notifyTypeTemporaryFailure, Data: bytes.Repeat([]byte{0xcd}, 1600)}}, false, 320)
	if err != nil {
		t.Fatalf("SealIKEFragments() error = %v", err)
	}
	bad := append([]byte(nil), packets[0]...)
	bad[len(bad)-1] ^= 0xff
	var packet ike.Packet
	if err := packet.UnmarshalBinary(bad); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	reassembly := ikeFragmentReassembly{}

	payloads, complete, err := openIKEPacketMaybeFragmented(crypto, packet, false, true, &reassembly)

	if err != nil {
		t.Fatalf("openIKEPacketMaybeFragmented() error = %v, want silent discard", err)
	}
	if complete {
		t.Fatal("openIKEPacketMaybeFragmented() complete = true, want false")
	}
	if payloads != nil {
		t.Fatalf("payloads = %T, want nil", payloads)
	}
}

func TestExchangeProtectedIKEReassemblesFragmentedResponse(t *testing.T) {
	crypto := testIKECrypto()
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 500}
	request := protectedIKEWire(t, crypto, exchangeTypeIKEAuth, flagInitiator, 4, []ike.Payload{&ike.NotifyPayload{NotifyType: notifyTypeCookie2, Data: []byte{1, 2, 3, 4}}}, true)
	responsePayloads := []ike.Payload{&ike.NotifyPayload{NotifyType: notifyTypeTemporaryFailure, Data: bytes.Repeat([]byte{0xcd}, 1600)}}
	responses, err := crypto.SealIKEFragments(ike.Header{
		InitiatorSPI: 0x0102030405060708,
		ResponderSPI: 0x1112131415161718,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeIKEAuth,
		Flags:        flagResponse,
		MessageID:    4,
	}, responsePayloads, false, 320)
	if err != nil {
		t.Fatalf("SealIKEFragments(response) error = %v", err)
	}
	readResults := make([]readResult, 0, len(responses))
	for _, response := range responses {
		readResults = append(readResults, readResult{data: response, addr: peer})
	}
	conn := &fakePacketConn{
		local:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
		readResults: readResults,
	}
	session := mustDialSession(t, conn)
	session.cfg.IKERetransmitDelays = []time.Duration{time.Second}

	gotPayloads, gotPeer, err := session.exchangeProtectedIKE(t.Context(), protectedIKEExchange{
		peer:                   peer,
		requests:               [][]byte{request},
		messageID:              4,
		crypto:                 crypto,
		fragmentationSupported: true,
		action:                 ikeActionTestFragmentedResponse,
	})
	if err != nil {
		t.Fatalf("exchangeProtectedIKE() error = %v", err)
	}
	if !sameUDPAddr(gotPeer, peer) {
		t.Fatalf("peer = %s, want %s", gotPeer, peer)
	}
	if notify := ike.FindNotifyPayload(gotPayloads, notifyTypeTemporaryFailure); notify == nil {
		t.Fatalf("payloads = %T, want TEMPORARY_FAILURE notify", gotPayloads)
	}
}
