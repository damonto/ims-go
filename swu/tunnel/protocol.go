package tunnel

const (
	ikeVersion20 byte = 0x20

	exchangeTypeIKESAInit     byte = 34
	exchangeTypeIKEAuth       byte = 35
	exchangeTypeInformational byte = 37
)

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
)

const (
	payloadTypeIDi byte = 35
	payloadTypeIDr byte = 36
	payloadTypeTSi byte = 44
	payloadTypeTSr byte = 45
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
	idTypeFQDN             byte = 2
	idTypeRFC822Addr       byte = 3
	authMethodSharedKeyMIC byte = 2
)

const (
	protocolIDIKE byte = 1
	protocolIDESP byte = 3
)

const (
	notifyTypeInvalidKEPayload      uint16 = 17
	notifyTypeCookie                uint16 = 16390
	notifyTypeNATDetectionSourceIP  uint16 = 16388
	notifyTypeNATDetectionDestIP    uint16 = 16389
	notifyTypeEAPOnlyAuthentication uint16 = 16417
	notifyTypeDeviceIdentity        uint16 = 41101
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
	configAttrPCSCFIPv4Address              uint16 = 20
	configAttrPCSCFIPv6Address              uint16 = 21
	configAttrTimeoutPeriodForLivenessCheck uint16 = 24
)

const attributeFormatTLV byte = 0

const (
	eapCodeRequest byte = 1
	eapCodeSuccess byte = 3
	eapCodeFailure byte = 4

	akaSubtypeChallenge        byte = 1
	akaSubtypeIdentity         byte = 5
	akaSubtypeNotification     byte = 12
	akaSubtypeReauthentication byte = 13

	akaAttrRAND           byte = 1
	akaAttrAUTN           byte = 2
	akaAttrMAC            byte = 11
	akaAttrPermanentIDReq byte = 10
	akaAttrAnyIDReq       byte = 13
	akaAttrIdentity       byte = 14
	akaAttrFullAuthIDReq  byte = 17
	akaAttrCounter        byte = 19
	akaAttrIV             byte = 129
	akaAttrEncryptedData  byte = 130
	akaAttrNextPseudonym  byte = 132
	akaAttrNextReauthID   byte = 133
	akaAttrCheckcode      byte = 134
	akaAttrResultInd      byte = 135
)

const akaClientErrorUnableToProcessPacket uint16 = 0
