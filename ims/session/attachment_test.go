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

type closingSessionHandler struct {
	sess       *Session
	errCh      chan error
	closeErrCh chan error
}

func (h *closingSessionHandler) HandleRequest(context.Context, Request) (bool, error) {
	return false, nil
}

func (h *closingSessionHandler) HandleError(err error) {
	h.errCh <- err
	h.closeErrCh <- h.sess.Close()
}

type concurrentHandler struct {
	requests  atomic.Int64
	responses atomic.Int64
}

func (h *concurrentHandler) HandleRequest(context.Context, Request) (bool, error) {
	h.requests.Add(1)
	return true, nil
}

func (h *concurrentHandler) HandleResponse(context.Context, sip.Message) (bool, error) {
	h.responses.Add(1)
	return true, nil
}

func (h *concurrentHandler) HandleError(error) {}

func TestNotifyHandlersOnceAllowsHandlerToCloseSession(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "handler closes session during error notification"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, err := Open(Config{}, newStubTransport(5062, 5060))
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			handler := &closingSessionHandler{
				sess:       sess,
				errCh:      make(chan error, 1),
				closeErrCh: make(chan error, 1),
			}
			if _, err := sess.Attach(handler); err != nil {
				t.Fatalf("Attach() error = %v", err)
			}

			cause := errors.New("read failed")
			done := make(chan struct{})
			go func() {
				defer close(done)
				sess.notifyHandlersOnce(sess.handlerSnapshot(), cause)
			}()

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("notifyHandlersOnce() did not return")
			}

			select {
			case got := <-handler.errCh:
				if !errors.Is(got, cause) {
					t.Fatalf("HandleError() error = %v, want %v", got, cause)
				}
			default:
				t.Fatal("HandleError() was not called")
			}

			select {
			case err := <-handler.closeErrCh:
				if err != nil {
					t.Fatalf("Close() from HandleError() error = %v", err)
				}
			default:
				t.Fatal("Close() from HandleError() was not called")
			}
		})
	}
}

func TestHandlerAttachmentCloseConcurrentWithDispatch(t *testing.T) {
	tests := []struct {
		name     string
		dispatch func(*Session, *stubTransport)
	}{
		{
			name: "request",
			dispatch: func(sess *Session, transport *stubTransport) {
				_, _ = sess.dispatchRequest(context.Background(), Request{
					Message:   newInboundRequest("MESSAGE", "handler-race", "1 MESSAGE"),
					Transport: transport,
					PeerAddr:  transport.RemoteAddr(),
				})
			},
		},
		{
			name: "response",
			dispatch: func(sess *Session, _ *stubTransport) {
				req := newInboundRequest("INVITE", "handler-race", "1 INVITE")
				_ = sess.handleInboundResponse(context.Background(), newResponse(req, 180, "Ringing"))
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
				handler := &concurrentHandler{}
				attachment, err := sess.Attach(handler)
				if err != nil {
					t.Fatalf("Attach() error = %v", err)
				}

				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range 20 {
						tt.dispatch(sess, transport)
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
