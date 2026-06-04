package tunnel

import (
	"fmt"

	"github.com/damonto/vowifi-go/eapaka"
)

func (f *akaAuthFlow) biddingDownRejectResponse(message eapaka.AKAMessage) (akaResponse, bool, error) {
	if message.EAPType != eapTypeAKA {
		return akaResponse{}, false, nil
	}
	attr := eapaka.FindAttribute(message.Attributes, akaAttrBidding)
	if attr == nil {
		return akaResponse{}, false, nil
	}
	bidding, err := eapaka.BiddingFromAttribute(attr)
	if err != nil {
		response, responseErr := f.clientErrorResponse(message.Identifier, "parsing aka bidding", err)
		return response, true, responseErr
	}
	if !bidding.SupportsAKAPrime {
		return akaResponse{}, false, nil
	}
	data, err := eapaka.BuildAKAAuthenticationReject(message.Identifier)
	if err != nil {
		return akaResponse{}, true, fmt.Errorf("connecting swu session: building aka authentication reject: %w", err)
	}
	return akaResponse{data: data}, true, nil
}
