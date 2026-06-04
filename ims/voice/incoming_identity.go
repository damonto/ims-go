package voice

import (
	"github.com/damonto/vowifi-go/ims/identity"
	"github.com/damonto/vowifi-go/ims/sip"
)

func incomingCallerNumber(msg sip.Message) string {
	for _, header := range []string{"P-Asserted-Identity", "Remote-Party-ID", "From"} {
		for _, value := range msg.HeadersByName(header) {
			for _, part := range sip.SplitHeaderList(value) {
				if number := identity.MSISDN(part); number != "" {
					return number
				}
			}
		}
	}
	return ""
}
