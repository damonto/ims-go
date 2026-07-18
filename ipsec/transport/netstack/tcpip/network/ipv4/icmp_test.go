package ipv4

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
		mtu      uint16
		wantKind stack.TransportErrorKind
		wantInfo uint32
		wantOK   bool
	}{
		{name: "fragmentation needed", typ: icmpv4DestinationUnreachable, code: icmpv4FragmentationNeeded, mtu: 1500, wantKind: stack.PacketTooBigTransportError, wantInfo: 1480, wantOK: true},
		{name: "legacy zero MTU is ignored", typ: icmpv4DestinationUnreachable, code: icmpv4FragmentationNeeded},
		{name: "time exceeded", typ: icmpv4TimeExceeded, code: icmpv4TTLExceeded, wantKind: stack.TimeExceededTransportError, wantOK: true},
		{name: "parameter problem", typ: icmpv4ParameterProblem, code: icmpv4BadLength, wantKind: stack.ParameterProblemTransportError, wantOK: true},
		{name: "unknown time exceeded code", typ: icmpv4TimeExceeded, code: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := make([]byte, 8)
			message[0] = tt.typ
			message[1] = tt.code
			binary.BigEndian.PutUint16(message[6:8], tt.mtu)
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
