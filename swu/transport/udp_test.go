package transport

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestUDPConnReadPacketUnblocksOnHandleError(t *testing.T) {
	conn := &UDPConn{
		readCh: make(chan inboundPacket, 1),
		done:   make(chan struct{}),
	}
	cause := errors.New("session failed")
	conn.HandleError(cause)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, _, err := conn.ReadPacket(ctx)
	if err == nil {
		t.Fatal("ReadPacket() error = nil, want terminal error")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("ReadPacket() error = %v, want wrapped %v", err, cause)
	}
}
