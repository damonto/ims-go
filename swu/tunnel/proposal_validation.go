package tunnel

import (
	"bytes"
	"fmt"

	"github.com/damonto/ims-go/swu/ike"
)

func validateNegotiatedProposalFromRequests(response ike.Proposal, requests []ike.Proposal) error {
	if len(requests) == 0 {
		return nil
	}
	if response.Number == 0 || int(response.Number) > len(requests) {
		return fmt.Errorf("invalid negotiated proposal number %d", response.Number)
	}
	request := requests[int(response.Number)-1]
	if response.ProtocolID != request.ProtocolID {
		return fmt.Errorf("negotiated protocol id %d does not match request proposal %d protocol id %d", response.ProtocolID, response.Number, request.ProtocolID)
	}
	for _, transform := range response.Transforms {
		if !proposalContainsTransform(request, transform) {
			return fmt.Errorf("negotiated transform type %d id %d was not requested in proposal %d", transform.TransformType, transform.ID, response.Number)
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
