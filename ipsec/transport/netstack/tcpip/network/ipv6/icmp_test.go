package ipv6

import (
	"encoding/binary"
	"testing"

	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/stack"
)

func TestICMPTransportErrorFromMessage(t *testing.T) {
	tests := []struct {
		name     string
		typ      byte
		code     byte
		mtu      uint32
		wantKind stack.TransportErrorKind
		wantInfo uint32
		wantOK   bool
	}{
		{name: "packet too big", typ: icmpv6PacketTooBig, mtu: 1500, wantKind: stack.PacketTooBigTransportError, wantInfo: 1460, wantOK: true},
		{name: "packet too big clamps to IPv6 minimum", typ: icmpv6PacketTooBig, mtu: 1000, wantKind: stack.PacketTooBigTransportError, wantInfo: 1240, wantOK: true},
		{name: "packet too big rejects non-zero code", typ: icmpv6PacketTooBig, code: 1, mtu: 1500},
		{name: "time exceeded", typ: icmpv6TimeExceeded, code: icmpv6HopLimitExceeded, wantKind: stack.TimeExceededTransportError, wantOK: true},
		{name: "parameter problem", typ: icmpv6ParameterProblem, code: icmpv6UnrecognizedNextHeader, wantKind: stack.ParameterProblemTransportError, wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := make([]byte, 8)
			message[0] = tt.typ
			message[1] = tt.code
			binary.BigEndian.PutUint32(message[4:8], tt.mtu)
			got, ok := icmpTransportErrorFromMessage(message)
			if ok != tt.wantOK {
				t.Fatalf("icmpTransportErrorFromMessage() ok = %t, want %t", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if got.Kind() != tt.wantKind || got.Info() != tt.wantInfo {
				t.Fatalf("transport error = kind %d info %d, want %d/%d", got.Kind(), got.Info(), tt.wantKind, tt.wantInfo)
			}
		})
	}
}
