package ims

import (
	"testing"

	imsvoice "github.com/damonto/ims-go/ims/voice"
)

func TestVoiceDTMFSubscription(t *testing.T) {
	for _, name := range []string{"delivery and close"} {
		t.Run(name, func(t *testing.T) {
			client := &Client{events: newEventHub()}
			voice := &VoiceClient{client: client}
			first, second := voice.Events(), voice.Events()
			defer second.Close()
			event := imsvoice.DTMFEvent{CallID: "call", Digit: "5"}
			client.handleVoiceDTMF(event)
			for _, sub := range []*VoiceEvents{first, second} {
				select {
				case got := <-sub.DTMF:
					if got != event {
						t.Errorf("event = %+v, want %+v", got, event)
					}
				default:
					t.Fatal("no dtmf notification")
				}
			}
			first.Close()
			if _, ok := <-first.DTMF; ok {
				t.Fatal("subscription still open")
			}
			client.events.close()
			if _, ok := <-second.DTMF; ok {
				t.Fatal("hub still open")
			}
		})
	}
}
