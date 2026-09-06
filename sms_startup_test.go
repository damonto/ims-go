package ims

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	imssession "github.com/damonto/ims-go/ims/session"
	imssip "github.com/damonto/ims-go/ims/sip"
)

type smsStartupProbeAccess struct {
	transport *gatedCancelTransport
}

func (a smsStartupProbeAccess) OpenIMS(context.Context, accessIMSConfig) (imsAccess, error) {
	return imsAccess{
		SIP: a.transport,
		Security: imsSecurity{
			DialSecureTCP: func(context.Context, imssession.SecureTCPConfig) (imssession.Transport, error) {
				return a.transport, nil
			},
		},
	}, nil
}

func (smsStartupProbeAccess) Close() error { return nil }

func TestSMSStartupDelivery(t *testing.T) {
	tests := []struct {
		name  string
		early bool
	}{
		{name: "during registration subscription", early: true},
		{name: "after IMS setup"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			client := newReadyClient(t, Config{
				Logger:   testLogger(),
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoWiFi(VoWiFiConfig{}),
			})
			t.Cleanup(client.events.close)
			events := client.SMS().Events()
			defer events.Close()

			transport := newGatedCancelTransport(5062, 5060)
			setup := &connectSetup{imsCfg: client.cfg.IMS, access: smsStartupProbeAccess{transport}}
			t.Cleanup(func() {
				if err := setup.closeIMS(); err != nil {
					t.Errorf("closeIMS() = %v", err)
				}
			})

			incoming := imssip.NewRequest("MESSAGE", "sip:test@127.0.0.1:5062")
			incoming.Headers = imssip.Headers{
				{Name: "Via", Value: "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-sms-startup"},
				{Name: "From", Value: "<sip:ipsmgw.example.test>;tag=origin"},
				{Name: "To", Value: "<sip:test@example.test>"},
				{Name: "P-Asserted-Identity", Value: "<sip:ipsmgw.example.test>"},
				{Name: "Call-ID", Value: "sms-startup-probe"},
				{Name: "CSeq", Value: "1 MESSAGE"},
				{Name: "Content-Type", Value: "application/vnd.3gpp.sms"},
			}
			var err error
			incoming.Body, err = hex.DecodeString("017707915155000000f0001404038154f600006290600100000005e8329bfd06")
			if err != nil {
				t.Fatal(err)
			}
			replies := make(chan int, 1)
			var pending imssip.Message
			registers := 0
			transport.onWrite = func(data []byte) {
				msg, err := imssip.ParseMessage(data)
				if err != nil {
					t.Errorf("ParseMessage() = %v", err)
					return
				}
				if !msg.IsRequest() {
					if msg.Header("Call-ID") == "sms-startup-probe" {
						replies <- msg.StatusCode()
						transport.queueRead(newIMSResponse(pending, 200, "OK"))
					}
					return
				}
				switch msg.Method() {
				case "REGISTER":
					registers++
					if registers == 1 {
						transport.queueRead(newUnauthorizedRegisterResponse(msg, testNonce()))
						return
					}
					transport.queueRead(newIMSResponse(msg, 200, "OK"))
				case "SUBSCRIBE":
					if tt.early {
						pending = msg
						transport.queueRead(incoming)
						return
					}
					transport.queueRead(newIMSResponse(msg, 200, "OK"))
				case "OPTIONS":
					pending = msg
					transport.queueRead(incoming)
				case "MESSAGE":
					transport.queueRead(newIMSResponse(msg, 202, "Accepted"))
				}
			}

			if err := client.openIMS(ctx, setup); err != nil {
				t.Fatalf("openIMS() = %v", err)
			}
			if !tt.early {
				req := imssip.NewRequest("OPTIONS", "sip:example.test")
				req.Headers = imssip.Headers{
					{Name: "Via", Value: "SIP/2.0/TCP 127.0.0.1:5062;branch=z9hG4bK-options-probe"},
					{Name: "From", Value: "<sip:test@example.test>;tag=local"},
					{Name: "To", Value: "<sip:example.test>"},
					{Name: "Call-ID", Value: "options-startup-probe"},
					{Name: "CSeq", Value: "1 OPTIONS"},
				}
				if _, err := setup.ims.sip.Exchange(ctx, req); err != nil {
					t.Fatalf("Exchange() = %v", err)
				}
			}

			select {
			case got := <-replies:
				if got != 200 {
					t.Fatalf("SMS response = %d, want 200", got)
				}
			case <-ctx.Done():
				t.Fatal("missing SMS response")
			}
			select {
			case got := <-events.Incoming:
				if got.From != "456" || got.Text != "hello" {
					t.Errorf("SMS = %+v, want hello from 456", got)
				}
			case <-ctx.Done():
				t.Fatal("SMS never reached Incoming")
			}
		})
	}
}
