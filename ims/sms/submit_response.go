package sms

import (
	"fmt"
	"strings"

	"github.com/damonto/vowifi-go/ims/sip"
)

func submitResponseFromMessage(resp sip.Message) submitResponse {
	statusCode := resp.StatusCode()
	return submitResponse{
		statusCode:   statusCode,
		reasonPhrase: strings.TrimSpace(strings.TrimPrefix(resp.StartLine, fmt.Sprintf("SIP/2.0 %d", statusCode))),
	}
}
