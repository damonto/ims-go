package sms

import (
	"log/slog"
	"testing"
	"time"

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

func TestReserveReferenceSkipsRetainedSubmittedReferences(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name          string
		rpRefs        map[byte]struct{}
		submitted     map[string]submittedEntry
		want          byte
		wantSubmitted int
	}{
		{
			name: "retained submitted",
			submitted: map[string]submittedEntry{
				"call-1": {rpRef: 7, expiresAt: now.Add(time.Minute), completed: true},
			},
			want:          8,
			wantSubmitted: 1,
		},
		{
			name:   "active reference",
			rpRefs: map[byte]struct{}{7: {}},
			want:   8,
		},
		{
			name: "expired submitted",
			submitted: map[string]submittedEntry{
				"call-1": {rpRef: 7, expiresAt: now.Add(-time.Minute), completed: true},
			},
			want: 7,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &Service{
				rpRef:     6,
				rpRefs:    tt.rpRefs,
				submitted: tt.submitted,
			}
			if svc.rpRefs == nil {
				svc.rpRefs = make(map[byte]struct{})
			}
			if svc.submitted == nil {
				svc.submitted = make(map[string]submittedEntry)
			}
			got, err := svc.reserveReference()
			if err != nil {
				t.Fatalf("reserveReference() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("reserveReference() = %d, want %d", got, tt.want)
			}
			if _, ok := svc.rpRefs[got]; !ok {
				t.Fatalf("rpRefs[%d] missing after reserveReference()", got)
			}
			if len(svc.submitted) != tt.wantSubmitted {
				t.Fatalf("len(submitted) = %d, want %d", len(svc.submitted), tt.wantSubmitted)
			}
		})
	}
}

func TestMOTransferStateMachine(t *testing.T) {
	tests := []struct {
		name  string
		steps func(*testing.T, *Service)
	}{
		{
			name: "send without pending returns idle",
			steps: func(t *testing.T, svc *Service) {
				if err := svc.beginMOTransfer(); err != nil {
					t.Fatalf("beginMOTransfer() error = %v", err)
				}
				if svc.moState != moTransferSending {
					t.Fatalf("moState after begin = %v, want %v", svc.moState, moTransferSending)
				}
				if err := svc.beginMOTransfer(); err == nil {
					t.Fatal("second beginMOTransfer() error = nil, want in-progress error")
				}
				svc.finishMOSend()
				if svc.moState != moTransferIdle {
					t.Fatalf("moState after finish = %v, want %v", svc.moState, moTransferIdle)
				}
			},
		},
		{
			name: "send stays busy until finish",
			steps: func(t *testing.T, svc *Service) {
				if err := svc.beginMOTransfer(); err != nil {
					t.Fatalf("beginMOTransfer() error = %v", err)
				}
				if err := svc.beginMOTransfer(); err == nil {
					t.Fatal("second beginMOTransfer() error = nil, want in-progress error")
				}
				svc.finishMOSend()
				if svc.moState != moTransferIdle {
					t.Fatalf("moState after finish = %v, want %v", svc.moState, moTransferIdle)
				}
			},
		},
		{
			name: "closed rejects begin",
			steps: func(t *testing.T, svc *Service) {
				svc.closed = true
				if err := svc.beginMOTransfer(); err == nil {
					t.Fatal("beginMOTransfer() error = nil, want closed error")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.steps(t, &Service{})
		})
	}
}

func TestMTTransferStateMachine(t *testing.T) {
	tests := []struct {
		name   string
		closed bool
		want   bool
		state  mtTransferState
	}{
		{name: "idle starts", want: true, state: mtTransferActive},
		{name: "closed rejects", closed: true, state: mtTransferIdle},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &Service{closed: tt.closed}
			if got := svc.beginMTTransfer(); got != tt.want {
				t.Fatalf("beginMTTransfer() = %t, want %t", got, tt.want)
			}
			if svc.mtState != tt.state {
				t.Fatalf("mtState after begin = %v, want %v", svc.mtState, tt.state)
			}
			if tt.want && svc.beginMTTransfer() {
				t.Fatal("second beginMTTransfer() = true, want false")
			}
			svc.endMTTransfer()
			if svc.mtState != mtTransferIdle {
				t.Fatalf("mtState after end = %v, want %v", svc.mtState, mtTransferIdle)
			}
		})
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
