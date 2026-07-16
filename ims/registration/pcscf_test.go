package registration

import (
	"testing"
	"time"

	"github.com/damonto/ims-go/ims/sip"
)

func TestPCSCFFailoverRequired(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		retryAfter string
		marker     bool
		want       bool
	}{
		{name: "use proxy marker", status: sipStatusUseProxy, marker: true, want: true},
		{name: "server timeout", status: sipStatusServerTimeout, want: true},
		{name: "service unavailable without retry after", status: sipStatusServiceUnavailable, want: true},
		{name: "service unavailable longer than timer F", status: sipStatusServiceUnavailable, retryAfter: "33", want: true},
		{name: "service unavailable equal to timer F", status: sipStatusServiceUnavailable, retryAfter: "32"},
		{name: "service unavailable shorter than timer F", status: sipStatusServiceUnavailable, retryAfter: "10"},
		{name: "client error without retry after", status: sipStatusForbidden, want: true},
		{name: "server error without retry after", status: sipStatusServerInternalError, want: true},
		{name: "global error without retry after", status: 600, want: true},
		{name: "ordinary server error with retry after", status: sipStatusServerInternalError, retryAfter: "10"},
		{name: "redirection response", status: 302},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := sip.NewResponse(tt.status, "test response")
			if tt.retryAfter != "" {
				resp.Headers.Add("Retry-After", tt.retryAfter)
			}
			err := initialRegistrationRequiredError(resp)
			if tt.marker {
				err = pcscfReselectionRequiredError(resp)
			}
			if got := PCSCFFailoverRequired(err, 32*time.Second); got != tt.want {
				t.Fatalf("PCSCFFailoverRequired() = %v, want %v", got, tt.want)
			}
		})
	}
}
