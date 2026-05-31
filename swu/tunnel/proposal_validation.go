package tunnel

import (
	"bytes"
	"fmt"

	"github.com/damonto/vowifi-go/swu/ike"
)

func validateNegotiatedProposalFromRequests(action string, response ike.Proposal, requests []ike.Proposal) error {
	if len(requests) == 0 {
		return nil
	}
	if response.Number == 0 || int(response.Number) > len(requests) {
		return fmt.Errorf("%s: invalid negotiated proposal number %d", action, response.Number)
	}
	request := requests[int(response.Number)-1]
	if response.ProtocolID != request.ProtocolID {
		return fmt.Errorf("%s: negotiated protocol id %d does not match request proposal %d protocol id %d", action, response.ProtocolID, response.Number, request.ProtocolID)
	}
	for _, transform := range response.Transforms {
		if !proposalContainsTransform(request, transform) {
			return fmt.Errorf("%s: negotiated transform type %d id %d was not requested in proposal %d", action, transform.TransformType, transform.ID, response.Number)
		}
	}
	return nil
}

func proposalContainsTransform(proposal ike.Proposal, want ike.Transform) bool {
	for _, candidate := range proposal.Transforms {
		if transformNegotiatedFrom(want, candidate) {
			return true
		}
	}
	return false
}

func transformNegotiatedFrom(response, request ike.Transform) bool {
	if response.TransformType != request.TransformType || response.ID != request.ID {
		return false
	}
	for _, attr := range response.Attributes {
		if !transformContainsAttribute(request, attr) {
			return false
		}
	}
	return true
}

func transformContainsAttribute(transform ike.Transform, want ike.Attribute) bool {
	for _, attr := range transform.Attributes {
		if attr.Format != want.Format || attr.Type != want.Type {
			continue
		}
		if wantValue, ok := want.Uint16(); ok {
			if attrValue, ok := attr.Uint16(); ok && attrValue == wantValue {
				return true
			}
			continue
		}
		if bytes.Equal(attr.Value, want.Value) {
			return true
		}
	}
	return false
}
