package voice

import (
	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Service) canSendReliableProvisional(msg sip.Message) bool {
	return s.cfg.ReliableProvisional &&
		(tokenHeaderContains(msg, "Supported", reliableProvisionalOption) ||
			tokenHeaderContains(msg, "Require", reliableProvisionalOption))
}

func (s *Service) usesPreconditions(msg sip.Message) bool {
	return s.cfg.Preconditions &&
		(tokenHeaderContains(msg, "Supported", preconditionOption) ||
			tokenHeaderContains(msg, "Require", preconditionOption))
}

func sdpUsesPreconditions(body []byte) bool {
	offer, err := parseSDP(body)
	return err == nil && offer.Preconditions
}

func (s *Service) unsupportedRequiredReliableProvisional(msg sip.Message) bool {
	return !s.cfg.ReliableProvisional && tokenHeaderContains(msg, "Require", reliableProvisionalOption)
}
