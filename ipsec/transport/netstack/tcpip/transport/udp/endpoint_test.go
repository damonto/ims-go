package udp

import (
	"bytes"
	"testing"

	"github.com/damonto/ims-go/ipsec/transport/netstack/buffer"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/header"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/stack"
)

type readDuringPeek func([]byte) (int, error)

func (f readDuringPeek) Write(p []byte) (int, error) { return f(p) }

func TestReadPreservesDatagramDuringPeek(t *testing.T) {
	payload := buffer.MakeWithData([]byte("first"))
	tail := buffer.MakeWithData([]byte("second"))
	payload.Merge(&tail)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: payload})
	e := endpoint{rcvBufSize: pkt.MemSize()}
	e.rcvList.PushBack(&udpPacket{netProto: header.IPv4ProtocolNumber, pkt: pkt})

	var peeked, read bytes.Buffer
	writer := readDuringPeek(func(p []byte) (int, error) {
		if peeked.Len() == 0 {
			if _, err := e.Read(&read, tcpip.ReadOptions{}); err != nil {
				t.Errorf("consuming read: %s", err)
			}
		}
		return peeked.Write(p)
	})
	if _, err := e.Read(writer, tcpip.ReadOptions{Peek: true}); err != nil {
		t.Fatalf("peek: %s", err)
	}
	const want = "firstsecond"
	if read.String() != want || peeked.String() != want {
		t.Errorf("read = %q, peek = %q, want both %q", read.String(), peeked.String(), want)
	}
}
