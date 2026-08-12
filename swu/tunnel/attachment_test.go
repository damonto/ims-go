package tunnel

import (
	"errors"
	"testing"
	"time"

	ipsecbase "github.com/damonto/ims-go/ipsec"
	"github.com/damonto/ims-go/ipsec/packet"
)

type attachmentClosingInnerPacketProcessor struct {
	attachment ipsecbase.Attachment
	errCh      chan error
}

func (h *attachmentClosingInnerPacketProcessor) HandleInnerPacket(packet.InnerPacket) bool {
	return false
}

func (h *attachmentClosingInnerPacketProcessor) HandleError(err error) {
	h.errCh <- err
	if closeErr := h.attachment.Close(); closeErr != nil {
		h.errCh <- closeErr
	}
}

func TestSessionAttachmentFailClosesBeforeNotifyingProcessor(t *testing.T) {
	tests := []struct {
		name       string
		failCalls  int
		wantErrors int
	}{
		{
			name:       "processor closes same attachment",
			failCalls:  1,
			wantErrors: 1,
		},
		{
			name:       "repeated fail is ignored",
			failCalls:  2,
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cause := errors.New("liveness check timed out")
			processor := &attachmentClosingInnerPacketProcessor{
				errCh: make(chan error, 2*tt.failCalls),
			}
			attachment := &sessionAttachment{processor: processor}
			processor.attachment = attachment

			done := make(chan struct{})
			go func() {
				defer close(done)
				for range tt.failCalls {
					attachment.fail(cause)
				}
			}()

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("fail() did not return")
			}

			if !attachment.isClosed() {
				t.Fatal("attachment is open, want closed")
			}

			var got []error
			for len(processor.errCh) > 0 {
				got = append(got, <-processor.errCh)
			}
			if len(got) != tt.wantErrors {
				t.Fatalf("HandleError() calls = %d, want %d", len(got), tt.wantErrors)
			}
			for _, err := range got {
				if !errors.Is(err, cause) {
					t.Fatalf("HandleError() error = %v, want %v", err, cause)
				}
			}
		})
	}
}

func TestSessionAttachConcurrentWithSecurityAssociationFailure(t *testing.T) {
	tests := []struct {
		name string
		fail func(*Session, error)
	}{
		{name: "IKE SA failure", fail: (*Session).failSecurityAssociations},
		{name: "child SA failure", fail: (*Session).discardChildSecurityAssociations},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for range 100 {
				session := &Session{closeCh: make(chan struct{})}
				session.mu.Lock()
				session.connected = true
				session.mu.Unlock()
				processor := &recordingInnerPacketProcessor{errCh: make(chan error, 1)}
				cause := errors.New("security association stopped")
				start := make(chan struct{})
				attachDone := make(chan error, 1)
				failDone := make(chan struct{})

				go func() {
					<-start
					_, err := session.Attach(processor)
					attachDone <- err
				}()
				go func() {
					<-start
					tt.fail(session, cause)
					close(failDone)
				}()
				close(start)

				attachErr := <-attachDone
				<-failDone
				if attachErr == nil {
					select {
					case err := <-processor.errCh:
						if !errors.Is(err, cause) {
							t.Fatalf("HandleError() error = %v, want %v", err, cause)
						}
					default:
						t.Fatal("successful Attach() missed security association failure")
					}
				}
				session.attachmentsMu.RLock()
				remaining := len(session.attachments)
				session.attachmentsMu.RUnlock()
				if remaining != 0 {
					t.Fatalf("attachments remaining after failure = %d, want 0", remaining)
				}
			}
		})
	}
}
