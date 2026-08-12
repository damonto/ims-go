package session

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/damonto/ims-go/ims/sip"
)

type closingSessionProcessor struct {
	sess       *Stack
	errCh      chan error
	closeErrCh chan error
}

func (h *closingSessionProcessor) HandleRequest(context.Context, Request) (bool, error) {
	return false, nil
}

func (h *closingSessionProcessor) HandleError(err error) {
	h.errCh <- err
	h.closeErrCh <- h.sess.Close()
}

type concurrentProcessor struct {
	requests  atomic.Int64
	responses atomic.Int64
}

func (h *concurrentProcessor) HandleRequest(context.Context, Request) (bool, error) {
	h.requests.Add(1)
	return true, nil
}

func (h *concurrentProcessor) HandleResponse(context.Context, sip.Message) (bool, error) {
	h.responses.Add(1)
	return true, nil
}

func (h *concurrentProcessor) HandleError(error) {}

func TestNotifyProcessorsOnceAllowsProcessorToCloseSession(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "processor closes session during error notification"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, err := Open(Config{}, newStubTransport(5062, 5060))
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			processor := &closingSessionProcessor{
				sess:       sess,
				errCh:      make(chan error, 1),
				closeErrCh: make(chan error, 1),
			}
			if _, err := sess.Attach(processor); err != nil {
				t.Fatalf("Attach() error = %v", err)
			}

			cause := errors.New("read failed")
			done := make(chan struct{})
			go func() {
				defer close(done)
				sess.notifyProcessorsOnce(sess.processorSnapshot(), cause)
			}()

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("notifyProcessorsOnce() did not return")
			}

			select {
			case got := <-processor.errCh:
				if !errors.Is(got, cause) {
					t.Fatalf("HandleError() error = %v, want %v", got, cause)
				}
			default:
				t.Fatal("HandleError() was not called")
			}

			select {
			case err := <-processor.closeErrCh:
				if err != nil {
					t.Fatalf("Close() from HandleError() error = %v", err)
				}
			default:
				t.Fatal("Close() from HandleError() was not called")
			}
		})
	}
}

func TestProcessorAttachmentCloseConcurrentWithDispatch(t *testing.T) {
	tests := []struct {
		name     string
		dispatch func(context.Context, *Stack, *stubTransport) error
	}{
		{
			name: "request",
			dispatch: func(ctx context.Context, sess *Stack, transport *stubTransport) error {
				_, err := sess.dispatchRequest(ctx, Request{
					Message:   newInboundRequest("MESSAGE", "processor-race", "1 MESSAGE"),
					Transport: transport,
					PeerAddr:  transport.RemoteAddr(),
				})
				return err
			},
		},
		{
			name: "response",
			dispatch: func(ctx context.Context, sess *Stack, _ *stubTransport) error {
				req := newInboundRequest("INVITE", "processor-race", "1 INVITE")
				return sess.handleInboundResponse(ctx, newResponse(req, 180, "Ringing"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, err := Open(Config{}, newStubTransport(5062, 5060))
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			transport := newStubTransport(6062, 6060)

			for range 100 {
				processor := &concurrentProcessor{}
				attachment, err := sess.Attach(processor)
				if err != nil {
					t.Fatalf("Attach() error = %v", err)
				}

				var wg sync.WaitGroup
				dispatchErr := make(chan error, 1)
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range 20 {
						if err := tt.dispatch(t.Context(), sess, transport); err != nil {
							dispatchErr <- err
							return
						}
					}
				}()

				if err := attachment.Close(); err != nil {
					t.Fatalf("attachment.Close() error = %v", err)
				}
				wg.Wait()
				select {
				case err := <-dispatchErr:
					t.Fatalf("dispatch error = %v", err)
				default:
				}
			}
		})
	}
}

func TestTransportRegistrationRejectsDuplicateOwnership(t *testing.T) {
	tests := []struct {
		name string
		run  func(*Stack, *stubTransport) error
	}{
		{
			name: "add primary",
			run: func(sess *Stack, primary *stubTransport) error {
				_, err := sess.AddTransport(primary)
				return err
			},
		},
		{
			name: "replace primary with active auxiliary",
			run: func(sess *Stack, _ *stubTransport) error {
				aux := newStubTransport(15062, 15060)
				if _, err := sess.AddTransport(aux); err != nil {
					return err
				}
				return sess.ReplacePrimary(aux)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := newStubTransport(5062, 5060)
			sess, err := Open(Config{}, primary)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			closeStackAfterTest(t, sess)

			if err := tt.run(sess, primary); err == nil {
				t.Fatal("transport registration error = nil, want duplicate ownership error")
			}
		})
	}
}

func TestPromotePrimaryTransfersAttachmentOwnership(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "promoted transport ignores stale auxiliary attachment"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := newStubTransport(5062, 5060)
			next := newStubTransport(15062, 15060)
			sess, err := Open(Config{}, primary)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			closeStackAfterTest(t, sess)

			staleAttachment, err := sess.AddTransport(next)
			if err != nil {
				t.Fatalf("AddTransport() error = %v", err)
			}
			oldPrimaryAttachment, err := sess.PromotePrimary(next)
			if err != nil {
				t.Fatalf("PromotePrimary() error = %v", err)
			}
			if oldPrimaryAttachment == nil {
				t.Fatal("PromotePrimary() old attachment = nil, want non-nil")
			}

			if err := staleAttachment.Close(); err != nil {
				t.Fatalf("stale attachment Close() error = %v", err)
			}
			if !sess.isTransportActive(next) {
				t.Fatal("promoted transport became inactive after closing stale attachment")
			}
			next.mu.Lock()
			nextCloseCount := next.closeCount
			next.mu.Unlock()
			if nextCloseCount != 0 {
				t.Fatalf("promoted transport close count = %d, want 0", nextCloseCount)
			}

			if err := oldPrimaryAttachment.Close(); err != nil {
				t.Fatalf("old primary attachment Close() error = %v", err)
			}
			if sess.isTransportActive(primary) {
				t.Fatal("old primary transport is still active after closing its attachment")
			}
			primary.mu.Lock()
			primaryCloseCount := primary.closeCount
			primary.mu.Unlock()
			if primaryCloseCount != 1 {
				t.Fatalf("old primary close count = %d, want 1", primaryCloseCount)
			}
		})
	}
}

func TestDialogAttachmentCloseConcurrentWithLookup(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "dialog lookup while closing attachment"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, err := Open(Config{}, newStubTransport(5062, 5060))
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			msg := newInboundRequest("INFO", "dialog-race", "1 INFO")
			id := sip.DialogID{CallID: "dialog-race"}

			for range 100 {
				attachment, err := sess.RegisterDialog(id, "dialog-key")
				if err != nil {
					t.Fatalf("RegisterDialog() error = %v", err)
				}

				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range 20 {
						sess.LookupDialogKey(msg)
					}
				}()

				if err := attachment.Close(); err != nil {
					t.Fatalf("attachment.Close() error = %v", err)
				}
				wg.Wait()
			}
		})
	}
}
