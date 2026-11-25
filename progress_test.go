package ims

import (
	"context"
	"errors"
	"testing"
	"time"

	imssession "github.com/damonto/ims-go/ims/session"
	usimcard "github.com/damonto/wwan-go/sim/card"
)

func TestConnectionProgressRetainsFailedStageAcrossRetry(t *testing.T) {
	client := newStandaloneClient(t)
	first := client.beginConnectionProgress(stageEPDGResolve)
	client.connectionStage(first, stageEPDGIKEInit)
	client.finishConnectionProgress(first, context.DeadlineExceeded)
	client.waitConnectionProgress(first, stageRetryWait, time.Minute)
	waiting := client.ConnectionProgress()
	if waiting.Status != "waiting" || waiting.RetryAt == nil || waiting.LastFailure == nil ||
		waiting.LastFailure.Stage != stageEPDGIKEInit || waiting.LastFailure.Code != "timeout" {
		t.Fatalf("waiting progress = %+v, want IKE timeout and a retry deadline", waiting)
	}
	second := client.beginConnectionProgress(stageEPDGResolve)
	client.connectionStage(first, stagePCSCF)
	client.connectionStage(second, stageIMSStarting)
	client.finishConnectionProgress(second, nil)
	ready := client.ConnectionProgress()
	if ready.Attempt != first+1 || ready.Stage != stageIMSStarting || ready.Status != "ready" ||
		ready.LastFailure == nil || ready.LastFailure.Attempt != first || len(ready.Steps) != 2 {
		t.Fatalf("ready progress = %+v, want completed second attempt and failure from first", ready)
	}
}

func TestConnectionProgressReportsSIPTimeout(t *testing.T) {
	client := newStandaloneClient(t)
	attempt := client.beginConnectionProgress("ims_register_final")
	client.finishConnectionProgress(attempt, &imssession.TransactionTimeoutError{Method: "REGISTER", Timer: "F"})
	failure := client.ConnectionProgress().LastFailure
	if failure == nil || failure.Code != "timeout" {
		t.Fatalf("REGISTER timeout reported as %+v", failure)
	}
}

func TestConnectReportsProgressWhileLoadingSIM(t *testing.T) {
	entered := make(chan struct{})
	reader := &readerStub{listApplications: func(ctx context.Context) ([]usimcard.Application, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	client, err := New(reader, &Config{Terminal: TerminalInfo{ID: testIMEI}, Access: VoWiFi(VoWiFiConfig{})})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("Close() = %v", err)
		}
	})
	events := client.Events()
	defer events.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- client.Connect(ctx) }()

	select {
	case <-entered:
	case err := <-result:
		t.Fatalf("Connect returned before loading SIM: %v", err)
	case <-ctx.Done():
		t.Fatal("Connect did not reach SIM loading")
	}
	select {
	case <-events.ConnectionProgressChanged:
	default:
		t.Fatal("missing progress notification during SIM loading")
	}
	if progress := client.ConnectionProgress(); progress.Stage != stageSIMSetup || progress.Status != "running" {
		t.Fatalf("progress during SIM loading = %+v", progress)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Connect() = %v, want cancellation", err)
	}
	if progress := client.ConnectionProgress(); progress.Stage != "" || progress.LastFailure != nil {
		t.Fatalf("canceled progress = %+v, want no stage or failure", progress)
	}
}
