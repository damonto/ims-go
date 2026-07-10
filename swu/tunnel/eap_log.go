package tunnel

import (
	"fmt"
	"log/slog"

	"github.com/damonto/ims-go/eapaka"
)

func (f *akaAuthFlow) logger() *slog.Logger {
	return f.session.logger
}

func logEAPPacket(logger *slog.Logger, msg, direction string, messageID uint32, data []byte) {
	var packet eapaka.EAPPacket
	if err := packet.UnmarshalBinary(data); err != nil {
		logger.Debug(msg, "direction", direction, "message_id", messageID, "parse_err", err)
		return
	}
	attrs := []string(nil)
	akaSubtype := ""
	if packet.HasType && (packet.Type == eapTypeAKA || packet.Type == eapTypeAKAPrime) {
		var message eapaka.AKAMessage
		if err := message.UnmarshalBinary(data); err == nil {
			akaSubtype = akaSubtypeName(message.Subtype)
			attrs = summarizeAKAAttributes(message.Attributes)
		}
	}
	logger.Debug(
		msg,
		"direction", direction,
		"message_id", messageID,
		"eap_code", eapCodeName(packet.Code),
		"eap_identifier", packet.Identifier,
		"eap_type", eapTypeName(packet),
		"aka_subtype", akaSubtype,
		"aka_attrs", attrs,
	)
}

func eapCodeName(code byte) string {
	switch code {
	case eapCodeRequest:
		return "request"
	case eapCodeResponse:
		return "response"
	case eapCodeSuccess:
		return "success"
	case eapCodeFailure:
		return "failure"
	default:
		return fmt.Sprintf("unknown(%d)", code)
	}
}

func eapTypeName(packet eapaka.EAPPacket) string {
	if !packet.HasType {
		return ""
	}
	switch packet.Type {
	case eapTypeIdentity:
		return "identity"
	case eapTypeNotification:
		return "notification"
	case eapTypeNak:
		return "nak"
	case eapTypeAKA:
		return "aka"
	case eapTypeAKAPrime:
		return "aka_prime"
	default:
		return fmt.Sprintf("unknown(%d)", packet.Type)
	}
}

func akaSubtypeName(subtype byte) string {
	switch subtype {
	case akaSubtypeChallenge:
		return "challenge"
	case akaSubtypeAuthenticationReject:
		return "authentication_reject"
	case akaSubtypeSynchronizationFailure:
		return "synchronization_failure"
	case akaSubtypeIdentity:
		return "identity"
	case akaSubtypeNotification:
		return "notification"
	case akaSubtypeReauthentication:
		return "reauthentication"
	case akaSubtypeClientError:
		return "client_error"
	default:
		return fmt.Sprintf("unknown(%d)", subtype)
	}
}

func summarizeAKAAttributes(attrs []eapaka.AKAAttribute) []string {
	summary := make([]string, 0, len(attrs))
	for _, attr := range attrs {
		summary = append(summary, fmt.Sprintf("%s(%d)", akaAttributeName(attr.Type), len(attr.Value)))
	}
	return summary
}

func akaAttributeName(attrType byte) string {
	switch attrType {
	case akaAttrRAND:
		return "AT_RAND"
	case akaAttrAUTN:
		return "AT_AUTN"
	case akaAttrRES:
		return "AT_RES"
	case akaAttrAUTS:
		return "AT_AUTS"
	case akaAttrPadding:
		return "AT_PADDING"
	case akaAttrPermanentIDReq:
		return "AT_PERMANENT_ID_REQ"
	case akaAttrMAC:
		return "AT_MAC"
	case akaAttrNotification:
		return "AT_NOTIFICATION"
	case akaAttrAnyIDReq:
		return "AT_ANY_ID_REQ"
	case akaAttrIdentity:
		return "AT_IDENTITY"
	case akaAttrFullAuthIDReq:
		return "AT_FULLAUTH_ID_REQ"
	case akaAttrCounter:
		return "AT_COUNTER"
	case akaAttrCounterTooSmall:
		return "AT_COUNTER_TOO_SMALL"
	case akaAttrNonceS:
		return "AT_NONCE_S"
	case akaAttrClientErrorCode:
		return "AT_CLIENT_ERROR_CODE"
	case akaAttrKDFInput:
		return "AT_KDF_INPUT"
	case akaAttrKDF:
		return "AT_KDF"
	case akaAttrIV:
		return "AT_IV"
	case akaAttrEncryptedData:
		return "AT_ENCR_DATA"
	case akaAttrNextPseudonym:
		return "AT_NEXT_PSEUDONYM"
	case akaAttrNextReauthID:
		return "AT_NEXT_REAUTH_ID"
	case akaAttrCheckcode:
		return "AT_CHECKCODE"
	case akaAttrResultInd:
		return "AT_RESULT_IND"
	case akaAttrBidding:
		return "AT_BIDDING"
	case akaAttrIPMSInd:
		return "AT_IPMS_IND"
	case akaAttrIPMSRes:
		return "AT_IPMS_RES"
	default:
		return fmt.Sprintf("ATTR_%d", attrType)
	}
}

func ikeNotifyName(notifyType uint16) string {
	switch notifyType {
	case notifyTypeUnsupportedCriticalPayload:
		return "UNSUPPORTED_CRITICAL_PAYLOAD"
	case notifyTypeInvalidSyntax:
		return "INVALID_SYNTAX"
	case notifyTypeInvalidMessageID:
		return "INVALID_MESSAGE_ID"
	case notifyTypeInvalidSPI:
		return "INVALID_SPI"
	case notifyTypeNoProposalChosen:
		return "NO_PROPOSAL_CHOSEN"
	case notifyTypeInvalidKEPayload:
		return "INVALID_KE_PAYLOAD"
	case notifyTypeAuthenticationFailed:
		return "AUTHENTICATION_FAILED"
	case notifyTypeSinglePairRequired:
		return "SINGLE_PAIR_REQUIRED"
	case notifyTypeNoAdditionalSAs:
		return "NO_ADDITIONAL_SAS"
	case notifyTypeInternalAddressFailure:
		return "INTERNAL_ADDRESS_FAILURE"
	case notifyTypeFailedCPRequired:
		return "FAILED_CP_REQUIRED"
	case notifyTypeTSUnacceptable:
		return "TS_UNACCEPTABLE"
	case notifyTypeTemporaryFailure:
		return "TEMPORARY_FAILURE"
	case notifyTypeChildSANotFound:
		return "CHILD_SA_NOT_FOUND"
	case notifyTypePDNConnectionRejection:
		return "PDN_CONNECTION_REJECTION"
	case notifyTypeMaxConnectionReached:
		return "MAX_CONNECTION_REACHED"
	case notifyTypeNon3GPPAccessToEPCNotAllowed:
		return "NON_3GPP_ACCESS_TO_EPC_NOT_ALLOWED"
	case notifyTypeUserUnknown:
		return "USER_UNKNOWN"
	case notifyTypeNoAPNSubscription:
		return "NO_APN_SUBSCRIPTION"
	case notifyTypeAuthorizationRejected:
		return "AUTHORIZATION_REJECTED"
	case notifyTypeIllegalME:
		return "ILLEGAL_ME"
	case notifyTypeNetworkFailure:
		return "NETWORK_FAILURE"
	case notifyTypeRATTypeNotAllowed:
		return "RAT_TYPE_NOT_ALLOWED"
	case notifyTypeIMEINotAccepted:
		return "IMEI_NOT_ACCEPTED"
	case notifyTypePLMNNotAllowed:
		return "PLMN_NOT_ALLOWED"
	case notifyTypeUnauthenticatedEmergency:
		return "UNAUTHENTICATED_EMERGENCY_NOT_SUPPORTED"
	case notifyTypeReactivationRequestedCause:
		return "REACTIVATION_REQUESTED_CAUSE"
	case notifyTypeMOBIKESupported:
		return "MOBIKE_SUPPORTED"
	case notifyTypeIKEV2FragmentationSupported:
		return "IKEV2_FRAGMENTATION_SUPPORTED"
	case notifyTypeEAPOnlyAuthentication:
		return "EAP_ONLY_AUTHENTICATION"
	case notifyTypeBackoffTimer:
		return "BACKOFF_TIMER"
	case notifyTypePDNTypeIPv4OnlyAllowed:
		return "PDN_TYPE_IPv4_ONLY_ALLOWED"
	case notifyTypePDNTypeIPv6OnlyAllowed:
		return "PDN_TYPE_IPv6_ONLY_ALLOWED"
	case notifyTypePCSCFReselectionSupport:
		return "P-CSCF_RESELECTION_SUPPORT"
	case notifyTypeN1ModeCapability:
		return "N1_MODE_CAPABILITY"
	case notifyTypeN1ModeInformation:
		return "N1_MODE_INFORMATION"
	case notifyTypeN1ModeSNSSAIPlmnID:
		return "N1_MODE_S_NSSAI_PLMN_ID"
	default:
		return "UNKNOWN_NOTIFY"
	}
}
