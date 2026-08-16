package tunnel

type ikeAction uint8

const (
	ikeActionSendInvalidMessageIDNotification ikeAction = iota
	ikeActionSendInformational
	ikeActionCloseSWUSession
	ikeActionDeleteOldIKESA
	ikeActionDeleteRedundantIKESA
	ikeActionRekeyIKESA
	ikeActionRekeyChildSA
	ikeActionCreateChildSA
	ikeActionWriteInformationalResponse
	ikeActionWriteCreateChildSAResponse
	ikeActionOpenFinalIKEAuthResponse
	ikeActionConnectOpenAKAResponseMessage
	ikeActionOpenAKAResponseMessage
	ikeActionOpenIKEAuthChallenge
	ikeActionTestInformational
	ikeActionTestProtected
	ikeActionTestFragmentedResponse
	ikeActionTestProtectedExchange
	ikeActionFirstRequest
	ikeActionSecondRequest
	ikeActionHoldingRequestWindow
	ikeActionTestSend
)

func (a ikeAction) String() string {
	switch a {
	case ikeActionSendInvalidMessageIDNotification:
		return "sending invalid message id notification"
	case ikeActionSendInformational:
		return "sending informational"
	case ikeActionCloseSWUSession:
		return "closing swu session"
	case ikeActionDeleteOldIKESA:
		return "deleting old ike sa"
	case ikeActionDeleteRedundantIKESA:
		return "deleting redundant ike sa"
	case ikeActionRekeyIKESA:
		return "exchanging ike sa rekey"
	case ikeActionRekeyChildSA:
		return "exchanging child sa rekey"
	case ikeActionCreateChildSA:
		return "creating child sa"
	case ikeActionWriteInformationalResponse:
		return "writing informational response"
	case ikeActionWriteCreateChildSAResponse:
		return "writing create_child_sa response"
	case ikeActionOpenFinalIKEAuthResponse:
		return "opening final ike_auth response"
	case ikeActionConnectOpenAKAResponseMessage:
		return "opening aka response message"
	case ikeActionOpenAKAResponseMessage:
		return "opening aka response message"
	case ikeActionOpenIKEAuthChallenge:
		return "opening ike_auth challenge"
	case ikeActionTestInformational:
		return "test informational"
	case ikeActionTestProtected:
		return "test protected"
	case ikeActionTestFragmentedResponse:
		return "test fragmented response"
	case ikeActionTestProtectedExchange:
		return "testing protected exchange"
	case ikeActionFirstRequest:
		return "first request"
	case ikeActionSecondRequest:
		return "second request"
	case ikeActionHoldingRequestWindow:
		return "holding request window"
	case ikeActionTestSend:
		return "test ike send"
	default:
		return "handling ike exchange"
	}
}
