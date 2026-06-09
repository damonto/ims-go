package tunnel

const (
	ikeVersion20 byte = 0x20

	exchangeTypeIKESAInit     byte = 34
	exchangeTypeIKEAuth       byte = 35
	exchangeTypeCreateChildSA byte = 36
	exchangeTypeInformational byte = 37
)

const (
	ikeHeaderLen           = 28
	ikePayloadHeaderLen    = 4
	ikeFragmentHeaderLen   = 4
	defaultIKEFragmentSize = 1280
	maxIKEFragments        = 65535
	nonESPMarkerLen        = 4
)

var nonESPMarker = [nonESPMarkerLen]byte{}

const (
	flagInitiator byte = 0x08
	flagResponse  byte = 0x20
)

const (
	transformENCRAESCBC      uint16 = 12
	transformPRFHMACMD5      uint16 = 1
	transformPRFHMACSHA1     uint16 = 2
	transformPRFHMACSHA256   uint16 = 5
	transformINTEGHMACMD596  uint16 = 1
	transformINTEGHMACSHA196 uint16 = 2
	transformINTEGHMACSHA256 uint16 = 12
	transformDH1024MODP      uint16 = 2
	transformDH2048MODP      uint16 = 14
	transformESNNoESN        uint16 = 0
)

const (
	payloadTypeNone              byte = 0
	payloadTypeSA                byte = 33
	payloadTypeKE                byte = 34
	payloadTypeIDi               byte = 35
	payloadTypeIDr               byte = 36
	payloadTypeAUTH              byte = 39
	payloadTypeNonce             byte = 40
	payloadTypeNotify            byte = 41
	payloadTypeDelete            byte = 42
	payloadTypeTSi               byte = 44
	payloadTypeTSr               byte = 45
	payloadTypeEncrypted         byte = 46
	payloadTypeCP                byte = 47
	payloadTypeEAP               byte = 48
	payloadTypeEncryptedFragment byte = 53
)

const (
	proposalProtocolIKE byte = 1
	proposalProtocolESP byte = 3
)

const (
	transformTypeENCR  byte = 1
	transformTypePRF   byte = 2
	transformTypeINTEG byte = 3
	transformTypeDH    byte = 4
	transformTypeESN   byte = 5
)

const transformAttrKeyLength uint16 = 14

const (
	idTypeIPv4Addr         byte = 1
	idTypeFQDN             byte = 2
	idTypeRFC822Addr       byte = 3
	idTypeIPv6Addr         byte = 5
	idTypeDERASN1DN        byte = 9
	idTypeKeyID            byte = 11
	authMethodSharedKeyMIC byte = 2
)

const (
	protocolIDUnset byte = 0
	protocolIDIKE   byte = 1
	protocolIDESP   byte = 3
)

const (
	notifyTypeUnsupportedCriticalPayload   uint16 = 1
	notifyTypeInvalidSyntax                uint16 = 7
	notifyTypeInvalidMessageID             uint16 = 9
	notifyTypeInvalidSPI                   uint16 = 11
	notifyTypeInvalidKEPayload             uint16 = 17
	notifyTypeNoProposalChosen             uint16 = 14
	notifyTypeAuthenticationFailed         uint16 = 24
	notifyTypeSinglePairRequired           uint16 = 34
	notifyTypeNoAdditionalSAs              uint16 = 35
	notifyTypeInternalAddressFailure       uint16 = 36
	notifyTypeFailedCPRequired             uint16 = 37
	notifyTypeTSUnacceptable               uint16 = 38
	notifyTypePDNConnectionRejection       uint16 = 8192
	notifyTypeMaxConnectionReached         uint16 = 8193
	notifyTypeNon3GPPAccessToEPCNotAllowed uint16 = 9000
	notifyTypeUserUnknown                  uint16 = 9001
	notifyTypeNoAPNSubscription            uint16 = 9002
	notifyTypeAuthorizationRejected        uint16 = 9003
	notifyTypeIllegalME                    uint16 = 9006
	notifyTypeNetworkFailure               uint16 = 10500
	notifyTypeRATTypeNotAllowed            uint16 = 11001
	notifyTypeIMEINotAccepted              uint16 = 11005
	notifyTypePLMNNotAllowed               uint16 = 11011
	notifyTypeUnauthenticatedEmergency     uint16 = 11055
	notifyTypeCookie                       uint16 = 16390
	notifyTypeRekeySA                      uint16 = 16393
	notifyTypeTemporaryFailure             uint16 = 43
	notifyTypeChildSANotFound              uint16 = 44
	notifyTypeNATDetectionSourceIP         uint16 = 16388
	notifyTypeNATDetectionDestIP           uint16 = 16389
	notifyTypeMOBIKESupported              uint16 = 16396
	notifyTypeCookie2                      uint16 = 16401
	notifyTypeEAPOnlyAuthentication        uint16 = 16417
	notifyTypeIKEV2FragmentationSupported  uint16 = 16430
	notifyTypeReactivationRequestedCause   uint16 = 40961
	notifyTypeBackoffTimer                 uint16 = 41041
	notifyTypeDeviceIdentity               uint16 = 41101
	notifyTypePCSCFReselectionSupport      uint16 = 41304
	notifyTypeN1ModeCapability             uint16 = 51015
	notifyTypeN1ModeInformation            uint16 = 51115
	notifyTypeN1ModeSNSSAIPlmnID           uint16 = 52216

	notifyTypeStatusMin uint16 = 16384
)

const (
	configTypeRequest byte = 1
	configTypeReply   byte = 2
)

const (
	configAttrInternalIPv4Address           uint16 = 1
	configAttrInternalIPv4DNS               uint16 = 3
	configAttrInternalIPv6Address           uint16 = 8
	configAttrInternalIPv6DNS               uint16 = 10
	configAttrInternalIPv6Subnet            uint16 = 15
	configAttrPCSCFIPv4Address              uint16 = 20
	configAttrPCSCFIPv6Address              uint16 = 21
	configAttrTimeoutPeriodForLivenessCheck uint16 = 24
)

const attributeFormatTLV byte = 0

const (
	eapCodeRequest      byte = 1
	eapCodeResponse     byte = 2
	eapCodeSuccess      byte = 3
	eapCodeFailure      byte = 4
	eapTypeIdentity     byte = 1
	eapTypeNotification byte = 2
	eapTypeNak          byte = 3
	eapTypeAKA          byte = 23
	eapTypeAKAPrime     byte = 50

	akaSubtypeAuthenticationReject   byte = 2
	akaSubtypeSynchronizationFailure byte = 4
	akaSubtypeChallenge              byte = 1
	akaSubtypeIdentity               byte = 5
	akaSubtypeNotification           byte = 12
	akaSubtypeReauthentication       byte = 13
	akaSubtypeClientError            byte = 14

	akaAttrRAND            byte = 1
	akaAttrAUTN            byte = 2
	akaAttrRES             byte = 3
	akaAttrAUTS            byte = 4
	akaAttrPadding         byte = 6
	akaAttrMAC             byte = 11
	akaAttrNotification    byte = 12
	akaAttrPermanentIDReq  byte = 10
	akaAttrAnyIDReq        byte = 13
	akaAttrIdentity        byte = 14
	akaAttrFullAuthIDReq   byte = 17
	akaAttrCounter         byte = 19
	akaAttrCounterTooSmall byte = 20
	akaAttrNonceS          byte = 21
	akaAttrClientErrorCode byte = 22
	akaAttrKDFInput        byte = 23
	akaAttrKDF             byte = 24
	akaAttrIV              byte = 129
	akaAttrEncryptedData   byte = 130
	akaAttrNextPseudonym   byte = 132
	akaAttrNextReauthID    byte = 133
	akaAttrCheckcode       byte = 134
	akaAttrResultInd       byte = 135
	akaAttrBidding         byte = 136
	akaAttrIPMSInd         byte = 137
	akaAttrIPMSRes         byte = 138
)

const (
	akaClientErrorUnableToProcessPacket uint16 = 0
	akaSkippableAttributeStart          byte   = 128
	akaNotificationSuccess              uint16 = 32768
	akaPrimeKDFDefault                  uint16 = 1
	akaPrimeMKLen                              = 208
	akaPrimeKReOffset                          = 48
	akaPrimeKReLen                             = 32
	akaPrimeSQNXorAKLen                        = 6
)
