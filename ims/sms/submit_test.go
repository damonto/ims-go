package sms

import (
	"log/slog"
	"testing"

	"github.com/damonto/vowifi-go/ims/sip"
)

func TestCompletePendingRequiresInReplyToForSIPURI(t *testing.T) {
	tests := []struct {
		name      string
		inReplyTo string
		want      bool
	}{
		{name: "missing"},
		{name: "wrong", inReplyTo: "call-other"},
		{name: "matched", inReplyTo: "call-1", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reportCh := make(chan rpMessage, 1)
			svc := &Service{
				logger: slog.Default(),
				pending: map[string]pendingEntry{
					"call-1": {
						rpRef:    7,
						reportCh: reportCh,
						segment:  outboundSegment{to: "sip:bob@example.net"},
					},
				},
				submitted: make(map[string]submittedEntry),
			}
			msg := submitReportMessage(tt.inReplyTo)
			got := svc.completePending(msg, rpMessage{Type: rpAckNetworkToMS, Reference: 7})
			if got != tt.want {
				t.Fatalf("completePending() = %t, want %t", got, tt.want)
			}
			select {
			case <-reportCh:
				if !tt.want {
					t.Fatal("report channel received unexpected report")
				}
			default:
				if tt.want {
					t.Fatal("report channel did not receive report")
				}
			}
		})
	}
}

func TestCompletePendingAllowsReferenceFallbackForTelURI(t *testing.T) {
	reportCh := make(chan rpMessage, 1)
	svc := &Service{
		logger: slog.Default(),
		pending: map[string]pendingEntry{
			"call-1": {
				rpRef:    7,
				reportCh: reportCh,
				segment:  outboundSegment{to: "tel:+15551234567"},
			},
		},
		submitted: make(map[string]submittedEntry),
	}
	if !svc.completePending(submitReportMessage(""), rpMessage{Type: rpAckNetworkToMS, Reference: 7}) {
		t.Fatal("completePending() = false, want true")
	}
}

func submitReportMessage(inReplyTo string) sip.Message {
	msg := sip.NewRequest("MESSAGE", "sip:alice@example.net")
	msg.Headers.Add("Call-ID", "submit-report")
	msg.Headers.Add("CSeq", "1 MESSAGE")
	if inReplyTo != "" {
		msg.Headers.Add("In-Reply-To", inReplyTo)
	}
	return msg
}
