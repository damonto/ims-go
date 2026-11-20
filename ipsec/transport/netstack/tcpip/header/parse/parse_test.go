package parse

import (
	"bytes"
	"testing"

	"github.com/damonto/ims-go/ipsec/transport/netstack/buffer"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/header"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/stack"
)

func TestUDPLength(t *testing.T) {
	for _, tt := range []struct {
		name   string
		length uint16
		want   string
		wantOK bool
	}{
		{name: "padding", length: header.UDPMinimumSize + 2, want: "ab", wantOK: true},
		{name: "empty payload", length: header.UDPMinimumSize, wantOK: true},
		{name: "length shorter than header", length: header.UDPMinimumSize - 1},
		{name: "truncated payload", length: header.UDPMinimumSize + 5},
	} {
		t.Run(tt.name, func(t *testing.T) {
			wire := make([]byte, header.UDPMinimumSize)
			header.UDP(wire).SetLength(tt.length)
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(append(wire, "abcd"...)),
			})
			defer pkt.DecRef()
			if got := UDP(pkt); got != tt.wantOK {
				t.Fatalf("UDP() = %t, want %t", got, tt.wantOK)
			}
			if tt.wantOK {
				var data bytes.Buffer
				if _, err := pkt.Data().ReadTo(&data, true); err != nil {
					t.Fatal(err)
				}
				if got := data.String(); got != tt.want {
					t.Errorf("UDP payload = %q, want %q", got, tt.want)
				}
			}
		})
	}
}

func TestIPv6PayloadLengthIncludesExtensionHeader(t *testing.T) {
	const extSize = 8
	const payloadSize = extSize + header.UDPMinimumSize
	wire := make([]byte, header.IPv6MinimumSize+payloadSize+4)
	ip := header.IPv6(wire)
	ip.SetPayloadLength(payloadSize)
	ip.SetNextHeader(uint8(header.IPv6DestinationOptionsExtHdrIdentifier))
	wire[header.IPv6MinimumSize] = uint8(header.UDPProtocolNumber)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(wire)})
	defer pkt.DecRef()

	proto, _, _, _, ok := IPv6(pkt)
	if !ok || proto != header.UDPProtocolNumber {
		t.Fatalf("IPv6() protocol = %d, ok = %t, want UDP and true", proto, ok)
	}
	if got := pkt.Data().Size(); got != header.UDPMinimumSize {
		t.Errorf("payload after the extension header = %d bytes, want %d", got, header.UDPMinimumSize)
	}
}
