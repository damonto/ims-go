package tunnel

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/damonto/ims-client/swu/ike"
)

func TestRetransmitDelays(t *testing.T) {
	tests := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{name: "ike attempt 0", got: ikeRetransmitDelay(0), want: 500 * time.Millisecond},
		{name: "ike capped", got: ikeRetransmitDelay(9), want: 8 * time.Second},
		{name: "informational grows longer", got: informationalRetransmitDelay(5), want: 16 * time.Second},
		{name: "informational capped", got: informationalRetransmitDelay(9), want: 32 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("delay = %v, want %v", tt.got, tt.want)
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
