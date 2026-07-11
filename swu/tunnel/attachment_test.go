package tunnel

import (
	"errors"
	"testing"
	"time"

	"github.com/damonto/ims-go/ipsec/packet"
)

type attachmentClosingInnerHandler struct {
	attachment Attachment
	errCh      chan error
}

func (h *attachmentClosingInnerHandler) HandleInnerPacket(packet.InnerPacket) bool {
	return false
}

func (h *attachmentClosingInnerHandler) HandleError(err error) {
	h.errCh <- err
	_ = h.attachment.Close()
}

func TestSessionAttachmentFailClosesBeforeNotifyingHandler(t *testing.T) {
	tests := []struct {
		name       string
		failCalls  int
		wantErrors int
	}{
		{
			name:       "handler closes same attachment",
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
			handler := &attachmentClosingInnerHandler{
				errCh: make(chan error, tt.failCalls),
			}
			attachment := &sessionAttachment{handler: handler}
			handler.attachment = attachment

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
			for len(handler.errCh) > 0 {
				got = append(got, <-handler.errCh)
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
