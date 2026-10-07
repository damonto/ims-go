package ims

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	imssip "github.com/damonto/ims-go/ims/sip"
	"github.com/damonto/ims-go/lte"
)

func TestRegistrationSnapshotsAndChanges(t *testing.T) {
	tests := []struct {
		name   string
		access AccessConfig
	}{
		{name: "VoWiFi", access: VoWiFi(VoWiFiConfig{})},
		{name: "VoLTE", access: VoLTE(lte.Config{AccessNetworkInfo: testVoLTEPANI})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			client := newReadyClient(t, Config{Logger: testLogger(), Terminal: TerminalInfo{ID: testIMEI}, Access: tt.access})
			t.Cleanup(func() {
				if err := client.Close(); err != nil {
					t.Errorf("Close() = %v", err)
				}
			})
			events := client.Events()
			defer events.Close()
			other := client.Events()
			defer other.Close()
			if got := client.Registration(); got.Registered || got.MSISDN != "" {
				t.Fatalf("initial Registration = %+v", got)
			}

			transport := newGatedCancelTransport(5062, 5060)
			setup := &connectSetup{scope: newConnectionScope(), imsCfg: client.cfg.IMS, access: smsStartupProbeAccess{transport}}
			t.Cleanup(func() {
				if err := setup.closeIMS(); err != nil {
					t.Errorf("closeIMS() = %v", err)
				}
			})
			associated := "<sip:310260123456789@ims.example.test>,<tel:+15551234567>"
			registers := 0
			transport.onWrite = func(data []byte) {
				req, err := imssip.ParseMessage(data)
				if err != nil {
					t.Errorf("ParseMessage() = %v", err)
					return
				}
				if !req.IsRequest() {
					return
				}
				resp := newIMSResponse(req, 200, "OK")
				if req.Method() == "REGISTER" {
					registers++
					if registers == 1 {
						transport.queueRead(newUnauthorizedRegisterResponse(req, testNonce()))
						return
					}
					if associated != "" {
						resp.Headers.Add("P-Associated-URI", associated)
					}
				}
				transport.queueRead(resp)
			}
			if err := client.openIMS(ctx, setup); err != nil {
				t.Fatalf("openIMS() = %v", err)
			}
			reg := setup.ims.reg
			if _, err := client.commitConnect(setup); err != nil {
				t.Fatalf("commitConnect() = %v", err)
			}
			client.emitStatus(StatusRegistered)
			<-events.State
			<-other.State
			if got := client.Registration(); !got.Registered || got.MSISDN != "+15551234567" {
				t.Fatalf("Registration = %+v", got)
			}
			copy := client.Registration()
			copy.AssociatedURIs[1] = "tel:+15557654321"
			state := reg.State()
			state.AssociatedURIs[1] = "tel:+15550000000"
			if got := client.Registration().MSISDN; got != "+15551234567" {
				t.Fatalf("snapshot mutated client: %q", got)
			}

			// Notifications stay bounded while every read observes the newest refresh.
			for i := range 25 {
				associated = fmt.Sprintf("<tel:+1555123%04d>", i)
				if err := reg.Refresh(ctx); err != nil {
					t.Fatalf("Refresh() = %v", err)
				}
			}
			for _, stream := range []<-chan struct{}{events.RegistrationChanged, other.RegistrationChanged} {
				select {
				case <-stream:
				default:
					t.Fatal("missing registration notification")
				}
				select {
				case <-stream:
					t.Fatal("registration changes did not coalesce")
				default:
				}
			}
			if got := client.Registration().MSISDN; got != "+15551230024" {
				t.Fatalf("latest MSISDN = %q", got)
			}
			select {
			case state := <-events.State:
				t.Fatalf("refresh emitted connection transition: %+v", state)
			default:
			}

			for _, value := range []string{"", "<tel:+15551234567>,<tel:+15557654321>"} {
				associated = value
				if err := reg.Refresh(ctx); err != nil {
					t.Fatalf("Refresh() = %v", err)
				}
				select {
				case <-events.RegistrationChanged:
				default:
					t.Fatal("missing identity invalidation")
				}
				if got := client.Registration(); !got.Registered || got.MSISDN != "" {
					t.Fatalf("Registration after invalidation = %+v", got)
				}
			}
			if err := client.Close(); err != nil {
				t.Fatalf("Close() = %v", err)
			}
			if got := client.Registration(); got.Registered || len(got.AssociatedURIs) != 0 || got.MSISDN != "" {
				t.Fatalf("Registration after close = %+v", got)
			}
		})
	}
}

func TestRegistrationConcurrentIMSCleanup(t *testing.T) {
	tests := []struct {
		name  string
		close func(*Client, *activeConn) error
	}{
		{name: "P-CSCF restoration", close: (*Client).closeIMS},
		{name: "close active connection", close: (*Client).closeActive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newStandaloneClient(t)
			active := &activeConn{}
			setClientActive(t, client, active)
			var wg sync.WaitGroup
			wg.Go(func() {
				for range 1000 {
					client.Registration()
					if _, err := client.currentSMSClient(); !errors.Is(err, ErrClientNotConnected) {
						t.Errorf("currentSMSClient() = %v, want ErrClientNotConnected", err)
					}
				}
			})
			wg.Go(func() {
				for range 1000 {
					if err := tt.close(client, active); err != nil {
						t.Errorf("close IMS = %v", err)
					}
					if err := client.state.restoreIMS(active, imsStack{}, nil); err != nil {
						t.Errorf("restoreIMS() = %v", err)
					}
				}
			})
			wg.Wait()
			runner := connectionRunner{client: client, active: active}
			if err := runner.runIMS(); !errors.Is(err, ErrClientNotConnected) {
				t.Fatalf("runIMS() after cleanup = %v, want ErrClientNotConnected", err)
			}
			if err := client.Close(); err != nil {
				t.Fatalf("Close() = %v", err)
			}
		})
	}
}
