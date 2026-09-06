package ussd

import (
	"context"
	"net/textproto"
	"testing"
	"time"

	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
)

func TestIncomingInviteAcceptsCarrierPayload(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name: "zero error with request",
			body: `<ussd-data><error-code>0</error-code><language>en-US</language><ussd-string>Enter PIN</ussd-string><anyExt><UnstructuredSS-Request/></anyExt></ussd-data>`,
		},
		{
			name:    "nonzero error rejected",
			body:    `<ussd-data><error-code>3</error-code><language>en-US</language><ussd-string>Enter PIN</ussd-string><anyExt><UnstructuredSS-Request/></anyExt></ussd-data>`,
			wantErr: true,
		},
		{
			name:    "zero error without string rejected",
			body:    `<ussd-data><error-code>0</error-code><language>en-US</language><anyExt><UnstructuredSS-Request/></anyExt></ussd-data>`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := validateIncomingInvite(carrierInvite(t, tt.body))
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateIncomingInvite() error = %v, wantErr %t", err, tt.wantErr)
			}
			want := Message{Text: "Enter PIN", Language: "en-US", Request: true}
			if err == nil && got != want {
				t.Fatalf("validateIncomingInvite() = %+v, want %+v", got, want)
			}
		})
	}
}

func TestUSSDCarrierDialogFlows(t *testing.T) {
	tests := []struct {
		name             string
		networkInitiated bool
	}{
		{name: "user initiated"},
		{name: "network initiated", networkInitiated: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			transport := newTransport()
			stack, reg := registeredService(t, transport)
			svc, err := New(Config{Logger: testLogger(), NetworkInitiatedSupported: true}, stack, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			closeServiceAfterTest(t, svc, reg, stack)
			transport.onWrite = func(data []byte) {
				req, err := sip.ParseMessage(data)
				if err != nil {
					t.Errorf("ParseMessage() error = %v", err)
					return
				}
				switch req.Method() {
				case "INVITE":
					transport.queue(newUSSDResponse(req, 200, "OK", []byte(testSDP),
						sip.Header{Name: "To", Value: req.Header("To") + ";tag=remote"},
						sip.Header{Name: "Contact", Value: "<sip:network@example.com>"},
						sip.Header{Name: "Recv-Info", Value: infoPackage},
						sip.Header{Name: "Accept", Value: acceptHeader},
						sip.Header{Name: "Content-Type", Value: sdpContentType},
					))
				case "INFO":
					transport.queue(newUSSDResponse(req, 200, "OK", nil))
				}
			}

			deliver := func(req sip.Message) {
				t.Helper()
				handled, err := svc.HandleRequest(ctx, session.Request{Message: req, Transport: transport})
				if err != nil || !handled {
					t.Fatalf("HandleRequest(%s) = %t, %v", req.Method(), handled, err)
				}
				if req.Method() != "ACK" {
					resp := mustParseUSSDMessage(t, transport.lastWrite())
					if resp.StatusCode() != 200 {
						t.Fatalf("response to %s = %s", req.Method(), resp.StartLine)
					}
				}
			}

			marker := ""
			if tt.networkInitiated {
				marker = "<anyExt><UnstructuredSS-Request/></anyExt>"
			}
			var us *Session
			if !tt.networkInitiated {
				us, err = svc.Start(ctx, "#225#")
				if err != nil {
					t.Fatalf("Start() error = %v", err)
				}
			}
			rounds := []struct {
				language string
				prompt   string
				reply    string
				cseq     string
			}{
				{language: "en-US", prompt: "Select an option", reply: "1", cseq: "2 INFO"},
				{language: "en-GB", prompt: "Confirm selection", reply: "2", cseq: "3 INFO"},
			}
			for i, round := range rounds {
				body := "<ussd-data><error-code>0</error-code><language>" + round.language + "</language><ussd-string>" + round.prompt + "</ussd-string>" + marker + "</ussd-data>"
				if tt.networkInitiated && i == 0 {
					invite := carrierInvite(t, body)
					deliver(invite)
					us = svc.lookupSessionByCallID(invite.Header("Call-ID"))
					if us == nil {
						t.Fatal("incoming USSD session was not registered")
					}
					deliver(newDialogRequest("ACK", us.localURI, us.remoteTo, sip.WithTag(invite.Header("To"), "", us.localTag), us.callID, "1 ACK"))
				} else {
					info := newDialogRequest("INFO", us.localURI, us.remoteTo, sip.WithTag("", us.localURI, us.localTag), us.callID, round.cseq)
					info.Headers.Add("Info-Package", infoPackage)
					info.Headers.Add("Content-Disposition", infoPackageDisposition)
					info.Headers.Add("Content-Type", xmlContentType)
					info.Body = []byte(body)
					deliver(info)
				}
				want := Message{Text: round.prompt, Language: round.language, Request: tt.networkInitiated}
				select {
				case got := <-us.Events():
					if got != want {
						t.Fatalf("round %d event = %+v, want %+v", i, got, want)
					}
				case <-ctx.Done():
					t.Fatalf("round %d event: %v", i, ctx.Err())
				}
				if err := us.Reply(ctx, round.reply); err != nil {
					t.Fatalf("round %d Reply() error = %v", i, err)
				}
				reply := mustParseUSSDMessage(t, transport.lastWrite())
				got, err := decodePayload(reply)
				if err != nil {
					t.Fatalf("decodePayload(reply) error = %v", err)
				}
				want.Text = round.reply
				if reply.Method() != "INFO" || got != want {
					t.Fatalf("round %d reply = %s %+v, want INFO %+v", i, reply.Method(), got, want)
				}
			}

			bye := newDialogRequest("BYE", us.localURI, us.remoteTo, sip.WithTag("", us.localURI, us.localTag), us.callID, "4 BYE")
			bye.Headers.Add("Content-Type", xmlContentType)
			bye.Body = []byte(`<ussd-data><error-code>0</error-code><language>en-GB</language><ussd-string>Done</ussd-string></ussd-data>`)
			deliver(bye)
			want := Message{Text: "Done", Language: "en-GB", Final: true}
			if got, ok := <-us.Events(); !ok || got != want {
				t.Fatalf("final event = %+v, %t; want %+v, true", got, ok, want)
			}
			if _, ok := <-us.Events(); ok {
				t.Fatal("USSD events remain open after BYE")
			}
			if !us.isClosed() || svc.hasActiveSession() {
				t.Fatal("USSD session remains active after BYE")
			}
		})
	}
}

func carrierInvite(t *testing.T, xmlBody string) sip.Message {
	t.Helper()
	invite := buildNetworkUSSDInvite(t)
	body, err := (multipartBody{
		Boundary: "invite",
		Parts: []multipartBodyPart{
			{Header: textproto.MIMEHeader{"Content-Type": {sdpContentType}}, Body: []byte(testSDP)},
			{Header: textproto.MIMEHeader{"Content-Type": {xmlContentType}}, Body: []byte(xmlBody)},
		},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	invite.Body = body
	return invite
}
