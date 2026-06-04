package voice

import (
	"strings"

	"github.com/damonto/vowifi-go/ims/sip"
)

func isReliableProvisional(msg sip.Message) bool {
	if msg.StatusCode() <= sipStatusTrying || msg.StatusCode() >= sipStatusOK {
		return false
	}
	if strings.TrimSpace(msg.Header("RSeq")) == "" {
		return false
	}
	return tokenHeaderContains(msg, "Require", reliableProvisionalOption)
}

func hasEarlyMediaHeader(msg sip.Message) bool {
	for _, value := range msg.HeadersByName("P-Early-Media") {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func earlyMediaAuthorized(msg sip.Message) bool {
	for _, value := range msg.HeadersByName("P-Early-Media") {
		for _, token := range strings.FieldsFunc(value, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t'
		}) {
			switch strings.ToLower(strings.TrimSpace(token)) {
			case "sendrecv", "sendonly":
				return true
			}
		}
	}
	return false
}

func tokenHeaderContains(msg sip.Message, name string, want string) bool {
	for _, value := range msg.HeadersByName(name) {
		if sip.TokenListContains(value, want) {
			return true
		}
	}
	return false
}

func routeSetFromResponse(msg sip.Message) []string {
	routes := reverseValues(msg.HeadersByName("Record-Route"))
	if routes == nil {
		return []string{}
	}
	return routes
}

func cloneSIPMessage(msg sip.Message) sip.Message {
	msg.Headers = msg.Headers.Clone()
	msg.Body = append([]byte(nil), msg.Body...)
	return msg
}
