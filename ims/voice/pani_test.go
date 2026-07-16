package voice

import (
	"testing"

	"github.com/damonto/ims-go/ims/sip"
)

func TestResponseCanCarryAccessNetworkInfo(t *testing.T) {
	tests := []struct {
		name   string
		method string
		want   bool
	}{
		{name: "dialog response", method: "INVITE", want: true},
		{name: "standalone response", method: "MESSAGE", want: true},
		{name: "cancel response", method: "CANCEL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := sip.NewResponse(200, "OK")
			resp.Headers.Add("CSeq", "1 "+tt.method)
			if got := responseCanCarryAccessNetworkInfo(resp); got != tt.want {
				t.Fatalf("responseCanCarryAccessNetworkInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}
