package eapaka

import "errors"

const (
	CodeRequest  byte = eapCodeRequest
	CodeResponse byte = eapCodeResponse
	CodeSuccess  byte = eapCodeSuccess
	CodeFailure  byte = eapCodeFailure
	TypeAKA      byte = eapTypeAKA

	SubtypeChallenge              byte = akaSubtypeChallenge
	SubtypeAuthenticationReject   byte = akaSubtypeAuthenticationReject
	SubtypeSynchronizationFailure byte = akaSubtypeSynchronizationFailure
	SubtypeIdentity               byte = akaSubtypeIdentity
	SubtypeNotification           byte = akaSubtypeNotification
	SubtypeReauthentication       byte = akaSubtypeReauthentication

	AttrRAND          byte = akaAttrRAND
	AttrAUTN          byte = akaAttrAUTN
	AttrRES           byte = akaAttrRES
	AttrAUTS          byte = akaAttrAUTS
	AttrPadding       byte = akaAttrPadding
	AttrMAC           byte = akaAttrMAC
	AttrIV            byte = akaAttrIV
	AttrEncryptedData byte = akaAttrEncryptedData
)

var ErrEAPFailure = errors.New("eap failure")
