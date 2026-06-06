package eapaka

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

var (
	sha1DSSIncrement = big.NewInt(1)
	sha1DSSModulus   = new(big.Int).Lsh(big.NewInt(1), 160)
)

const (
	akaSubtypeNotification     byte = 12
	akaSubtypeReauthentication byte = 13
	akaSubtypeClientError      byte = 14
)

const (
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
	akaAttrNextPseudonym   byte = 132
	akaAttrNextReauthID    byte = 133
	akaAttrCheckcode       byte = 134
	akaAttrResultInd       byte = 135
	akaAttrBidding         byte = 136
	akaAttrIPMSInd         byte = 137
	akaAttrIPMSRes         byte = 138
)

const (
	akaNotificationSuccess uint16 = 32768

	akaNotificationSuccessMask      uint16 = 0x8000
	akaNotificationPreChallengeMask uint16 = 0x4000
	akaNotificationAttributeLen            = 2
	akaBiddingSupportsAKAPrimeMask  uint16 = 0x8000
	akaNetworkNameMaxLen                   = 253
)

const (
	akaPaddingMinLen = 4
	akaPaddingMaxLen = 12
)

type IPMSSupport byte

const (
	IPMSSupportNBMOnly IPMSSupport = 2
)

type IPMSSelection byte

const (
	IPMSSelectionDSMIPv6 IPMSSelection = 1
	IPMSSelectionNBM     IPMSSelection = 2
	IPMSSelectionMIPv4   IPMSSelection = 3
)

type IPMSIndication struct {
	Support IPMSSupport
}

func (i IPMSIndication) MarshalBinary() ([]byte, error) {
	if !validIPMSSupport(i.Support) {
		return nil, fmt.Errorf("marshalling ipms indication: invalid support %d", i.Support)
	}
	return AKAAttribute{Type: akaAttrIPMSInd, Value: []byte{0x00, byte(i.Support)}}.MarshalBinary()
}

type IPMSResult struct {
	Selection IPMSSelection
}

type Bidding struct {
	SupportsAKAPrime bool
}

type KDFInput struct {
	NetworkName []byte
}

type KDF struct {
	Version uint16
}

func (i KDFInput) MarshalBinary() ([]byte, error) {
	if len(i.NetworkName) > akaNetworkNameMaxLen {
		return nil, fmt.Errorf("marshalling kdf input: network name length %d exceeds %d", len(i.NetworkName), akaNetworkNameMaxLen)
	}
	value := make([]byte, akaAttributeReservedLen+len(i.NetworkName))
	binary.BigEndian.PutUint16(value[:2], uint16(len(i.NetworkName)))
	copy(value[akaAttributeReservedLen:], i.NetworkName)
	for (len(value)+akaAttributeReservedLen)%akaAttributeBlockSize != 0 {
		value = append(value, 0x00)
	}
	return AKAAttribute{Type: akaAttrKDFInput, Value: value}.MarshalBinary()
}

func (i *KDFInput) UnmarshalBinary(data []byte) error {
	var attr AKAAttribute
	if err := attr.UnmarshalBinary(data); err != nil {
		return err
	}
	parsed, err := KDFInputFromAttribute(&attr)
	if err != nil {
		return err
	}
	*i = parsed
	return nil
}

func (k KDF) MarshalBinary() ([]byte, error) {
	return buildAKAUint16Attribute(akaAttrKDF, k.Version).MarshalBinary()
}

func (k *KDF) UnmarshalBinary(data []byte) error {
	var attr AKAAttribute
	if err := attr.UnmarshalBinary(data); err != nil {
		return err
	}
	parsed, err := KDFFromAttribute(&attr)
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

func (b Bidding) MarshalBinary() ([]byte, error) {
	flags := uint16(0)
	if b.SupportsAKAPrime {
		flags = akaBiddingSupportsAKAPrimeMask
	}
	return buildAKAUint16Attribute(akaAttrBidding, flags).MarshalBinary()
}

func (b *Bidding) UnmarshalBinary(data []byte) error {
	var attr AKAAttribute
	if err := attr.UnmarshalBinary(data); err != nil {
		return err
	}
	parsed, err := BiddingFromAttribute(&attr)
	if err != nil {
		return err
	}
	*b = parsed
	return nil
}

func (r *IPMSResult) UnmarshalBinary(data []byte) error {
	var attr AKAAttribute
	if err := attr.UnmarshalBinary(data); err != nil {
		return err
	}
	if attr.Type != akaAttrIPMSRes {
		return fmt.Errorf("parsing ipms result: unexpected attribute %d", attr.Type)
	}
	selection, err := ipmsSelectionValue(&attr)
	if err != nil {
		return err
	}
	*r = IPMSResult{Selection: selection}
	return nil
}

type AKANotification struct {
	Code      uint16
	Success   bool
	Protected bool
}

type AKAReauthentication struct {
	Identifier   byte
	Counter      uint16
	NonceS       []byte
	NextReauthID string
	UseResultInd bool
}

type ChallengeResponseOptions struct {
	Identifier   byte
	EAPType      byte
	RES          []byte
	AUTKey       []byte
	UseResultInd bool
	Checkcode    []byte
	IPMSSupport  IPMSSupport
}

func FindAttribute(attrs []AKAAttribute, attrType byte) *AKAAttribute {
	for i := range attrs {
		if attrs[i].Type == attrType {
			return &attrs[i]
		}
	}
	return nil
}

func HasAttribute(attrs []AKAAttribute, attrType byte) bool {
	return FindAttribute(attrs, attrType) != nil
}

func isKnownAKAAttribute(attrType byte) bool {
	switch attrType {
	case akaAttrRAND,
		akaAttrAUTN,
		akaAttrRES,
		akaAttrAUTS,
		akaAttrPadding,
		akaAttrMAC,
		akaAttrNotification,
		akaAttrPermanentIDReq,
		akaAttrAnyIDReq,
		akaAttrIdentity,
		akaAttrFullAuthIDReq,
		akaAttrCounter,
		akaAttrCounterTooSmall,
		akaAttrNonceS,
		akaAttrClientErrorCode,
		akaAttrKDFInput,
		akaAttrKDF,
		akaAttrIV,
		akaAttrEncryptedData,
		akaAttrNextPseudonym,
		akaAttrNextReauthID,
		akaAttrCheckcode,
		akaAttrResultInd,
		akaAttrBidding,
		akaAttrIPMSInd,
		akaAttrIPMSRes:
		return true
	default:
		return false
	}
}

func rejectUnsupportedAKAAttributes(attrs []AKAAttribute) error {
	for _, attr := range attrs {
		if attr.Type < akaSkippableAttributeStart && !isKnownAKAAttribute(attr.Type) {
			return fmt.Errorf("unrecognized non-skippable attribute %d", attr.Type)
		}
	}
	return nil
}

func marshalAKAAttributes(attrs []AKAAttribute) ([]byte, error) {
	buf := make([]byte, 0)
	for _, attr := range attrs {
		encoded, err := attr.MarshalBinary()
		if err != nil {
			return nil, err
		}
		buf = append(buf, encoded...)
	}
	return buf, nil
}

func buildAKAUint16Attribute(attrType byte, value uint16) AKAAttribute {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, value)
	return AKAAttribute{Type: attrType, Value: buf}
}

func validIPMSSupport(value IPMSSupport) bool {
	return value >= 1 && value <= 14
}

func validIPMSSelection(value IPMSSelection) bool {
	switch value {
	case IPMSSelectionDSMIPv6, IPMSSelectionNBM, IPMSSelectionMIPv4:
		return true
	default:
		return false
	}
}

func buildIPMSIndicationAttribute(support IPMSSupport) (AKAAttribute, error) {
	if !validIPMSSupport(support) {
		return AKAAttribute{}, fmt.Errorf("building ipms indication: invalid support %d", support)
	}
	return buildAKAUint16Attribute(akaAttrIPMSInd, uint16(support)), nil
}

func BiddingFromAttribute(attr *AKAAttribute) (Bidding, error) {
	if attr == nil {
		return Bidding{}, errors.New("parsing aka bidding: AT_BIDDING is missing")
	}
	if attr.Type != akaAttrBidding {
		return Bidding{}, fmt.Errorf("parsing aka bidding: unexpected attribute %d", attr.Type)
	}
	flags, err := Uint16Value(attr)
	if err != nil {
		return Bidding{}, fmt.Errorf("parsing aka bidding: %w", err)
	}
	return Bidding{SupportsAKAPrime: flags&akaBiddingSupportsAKAPrimeMask != 0}, nil
}

func KDFInputFromAttribute(attr *AKAAttribute) (KDFInput, error) {
	if attr == nil {
		return KDFInput{}, errors.New("parsing kdf input: AT_KDF_INPUT is missing")
	}
	if attr.Type != akaAttrKDFInput {
		return KDFInput{}, fmt.Errorf("parsing kdf input: unexpected attribute %d", attr.Type)
	}
	networkName, err := BytesValue(attr)
	if err != nil {
		return KDFInput{}, fmt.Errorf("parsing kdf input: %w", err)
	}
	if len(networkName) > akaNetworkNameMaxLen {
		return KDFInput{}, fmt.Errorf("parsing kdf input: network name length %d exceeds %d", len(networkName), akaNetworkNameMaxLen)
	}
	return KDFInput{NetworkName: networkName}, nil
}

func KDFFromAttribute(attr *AKAAttribute) (KDF, error) {
	if attr == nil {
		return KDF{}, errors.New("parsing kdf: AT_KDF is missing")
	}
	if attr.Type != akaAttrKDF {
		return KDF{}, fmt.Errorf("parsing kdf: unexpected attribute %d", attr.Type)
	}
	version, err := Uint16Value(attr)
	if err != nil {
		return KDF{}, fmt.Errorf("parsing kdf: %w", err)
	}
	return KDF{Version: version}, nil
}

func ipmsSelectionValue(attr *AKAAttribute) (IPMSSelection, error) {
	if attr == nil {
		return 0, errors.New("parsing ipms result: AT_IPMS_RES is missing")
	}
	if len(attr.Value) != akaAttributeReservedLen {
		return 0, fmt.Errorf("parsing ipms result: invalid value length %d", len(attr.Value))
	}
	if attr.Value[0] != 0 {
		return 0, fmt.Errorf("parsing ipms result: reserved octet is %d, want 0", attr.Value[0])
	}
	selection := IPMSSelection(attr.Value[1])
	if !validIPMSSelection(selection) {
		return 0, fmt.Errorf("parsing ipms result: invalid selection %d", selection)
	}
	return selection, nil
}

func IPMSSelectionFromAttributes(attrs []AKAAttribute) (IPMSSelection, bool, error) {
	attr := FindAttribute(attrs, akaAttrIPMSRes)
	if attr == nil {
		return 0, false, nil
	}
	selection, err := ipmsSelectionValue(attr)
	if err != nil {
		return 0, true, err
	}
	return selection, true, nil
}

func Uint16Value(attr *AKAAttribute) (uint16, error) {
	if attr == nil {
		return 0, errors.New("parsing aka uint16 attribute: attribute is nil")
	}
	if len(attr.Value) != akaAttributeReservedLen {
		return 0, fmt.Errorf("parsing aka uint16 attribute: invalid value length %d", len(attr.Value))
	}
	return binary.BigEndian.Uint16(attr.Value[:2]), nil
}

func buildAKAStringAttribute(attrType byte, value string) AKAAttribute {
	length := len(value)
	buf := make([]byte, akaAttributeReservedLen+length)
	binary.BigEndian.PutUint16(buf[:2], uint16(length))
	copy(buf[akaAttributeReservedLen:], value)
	for (len(buf)+akaAttributeReservedLen)%akaAttributeBlockSize != 0 {
		buf = append(buf, 0x00)
	}
	return AKAAttribute{Type: attrType, Value: buf}
}

func StringValue(attr *AKAAttribute) (string, error) {
	value, err := BytesValue(attr)
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func BytesValue(attr *AKAAttribute) ([]byte, error) {
	if attr == nil {
		return nil, errors.New("parsing aka bytes attribute: attribute is nil")
	}
	if len(attr.Value) < 2 {
		return nil, errors.New("parsing aka bytes attribute: value too short")
	}
	length := int(binary.BigEndian.Uint16(attr.Value[:2]))
	if len(attr.Value) < 2+length {
		return nil, fmt.Errorf("parsing aka bytes attribute: value length %d is too short for %d", len(attr.Value), length)
	}
	return append([]byte(nil), attr.Value[2:2+length]...), nil
}

func (n *AKANotification) UnmarshalAttributes(attrs []AKAAttribute) error {
	if err := rejectUnsupportedAKAAttributes(attrs); err != nil {
		return fmt.Errorf("parsing aka notification: %w", err)
	}
	var attr *AKAAttribute
	for i := range attrs {
		if attrs[i].Type != akaAttrNotification {
			continue
		}
		if attr != nil {
			return errors.New("parsing aka notification: duplicate AT_NOTIFICATION")
		}
		attr = &attrs[i]
	}
	if attr == nil {
		return errors.New("parsing aka notification: AT_NOTIFICATION is missing")
	}
	if len(attr.Value) != akaNotificationAttributeLen {
		return fmt.Errorf("parsing aka notification: invalid AT_NOTIFICATION length %d", len(attr.Value))
	}
	code, err := Uint16Value(attr)
	if err != nil {
		return err
	}
	success := code&akaNotificationSuccessMask != 0
	preChallenge := code&akaNotificationPreChallengeMask != 0
	if success && preChallenge {
		return errors.New("parsing aka notification: success code cannot be pre-challenge")
	}
	*n = AKANotification{Code: code, Success: success, Protected: !preChallenge}
	return nil
}

func (r *AKAReauthentication) UnmarshalMessage(message AKAMessage, encrKey []byte) error {
	if message.Code != eapCodeRequest || message.Subtype != akaSubtypeReauthentication {
		return errors.New("parsing aka reauthentication: unsupported packet")
	}
	if err := rejectUnsupportedAKAAttributes(message.Attributes); err != nil {
		return fmt.Errorf("parsing aka reauthentication: %w", err)
	}
	if attr := FindAttribute(message.Attributes, akaAttrResultInd); attr != nil && len(attr.Value) != akaResultIndAttributeLen {
		return fmt.Errorf("parsing aka reauthentication: invalid result indication length %d", len(attr.Value))
	}
	nested, err := DecryptAttributes(message.Attributes, encrKey)
	if err != nil {
		return err
	}
	counter, err := Uint16Value(FindAttribute(nested, akaAttrCounter))
	if err != nil {
		return fmt.Errorf("parsing aka reauthentication: %w", err)
	}
	nonceAttr := FindAttribute(nested, akaAttrNonceS)
	if nonceAttr == nil {
		return errors.New("parsing aka reauthentication: AT_NONCE_S is missing")
	}
	if len(nonceAttr.Value) != akaVectorAttributeLen {
		return fmt.Errorf("parsing aka reauthentication: invalid AT_NONCE_S length %d", len(nonceAttr.Value))
	}
	req := AKAReauthentication{
		Identifier:   message.Identifier,
		Counter:      counter,
		NonceS:       append([]byte(nil), nonceAttr.Value[akaAttributeReservedLen:akaVectorAttributeLen]...),
		UseResultInd: HasAttribute(message.Attributes, akaAttrResultInd),
	}
	if attr := FindAttribute(nested, akaAttrNextReauthID); attr != nil {
		identity, err := StringValue(attr)
		if err != nil {
			return fmt.Errorf("parsing aka reauthentication: %w", err)
		}
		req.NextReauthID = identity
	}
	*r = req
	return nil
}

func buildAKAMessageWithType(code, identifier, eapType, subtype byte, attrs []AKAAttribute, autKey, extra []byte) ([]byte, error) {
	message := AKAMessage{Code: code, Identifier: identifier, EAPType: eapType, Subtype: subtype, Attributes: append([]AKAAttribute(nil), attrs...)}
	if eapType == eapTypeAKAPrime {
		return message.MarshalSignedSHA256(autKey, extra)
	}
	return message.MarshalSigned(autKey, extra)
}

func VerifyMessageMAC(data, autKey, extra []byte) error {
	var message AKAMessage
	if err := message.UnmarshalBinary(data); err != nil {
		return err
	}
	return message.VerifyMAC(autKey, extra)
}

func VerifyMessageMACSHA256(data, autKey, extra []byte) error {
	var message AKAMessage
	if err := message.UnmarshalBinary(data); err != nil {
		return err
	}
	return message.VerifyMACSHA256(autKey, extra)
}

func DecryptAttributes(attrs []AKAAttribute, encrKey []byte) ([]AKAAttribute, error) {
	ivAttr := FindAttribute(attrs, akaAttrIV)
	encrAttr := FindAttribute(attrs, akaAttrEncryptedData)
	if ivAttr == nil || encrAttr == nil {
		return nil, errors.New("decrypting aka attributes: AT_IV or AT_ENCR_DATA is missing")
	}
	if len(ivAttr.Value) != akaVectorAttributeLen {
		return nil, fmt.Errorf("decrypting aka attributes: invalid AT_IV length %d", len(ivAttr.Value))
	}
	if len(encrAttr.Value) < akaAttributeReservedLen {
		return nil, errors.New("decrypting aka attributes: AT_ENCR_DATA is truncated")
	}
	ciphertext := encrAttr.Value[akaAttributeReservedLen:]
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("decrypting aka attributes: ciphertext is not block aligned")
	}
	block, err := aes.NewCipher(encrKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting aka attributes: %w", err)
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, ivAttr.Value[akaAttributeReservedLen:akaVectorAttributeLen]).CryptBlocks(plain, ciphertext)
	parsed, err := decodeAKAAttributes(plain)
	if err != nil {
		return nil, fmt.Errorf("decrypting aka attributes: %w", err)
	}
	if err := rejectUnsupportedAKAAttributes(parsed); err != nil {
		return nil, fmt.Errorf("decrypting aka attributes: %w", err)
	}
	filtered := make([]AKAAttribute, 0, len(parsed))
	for i, attr := range parsed {
		if attr.Type != akaAttrPadding {
			filtered = append(filtered, attr)
			continue
		}
		attrLen := len(attr.Value) + akaAttributeReservedLen
		if attrLen < akaPaddingMinLen || attrLen > akaPaddingMaxLen {
			return nil, fmt.Errorf("decrypting aka attributes: invalid padding length %d", attrLen)
		}
		if i != len(parsed)-1 {
			return nil, errors.New("decrypting aka attributes: padding is not last")
		}
		for _, b := range attr.Value {
			if b != 0 {
				return nil, errors.New("decrypting aka attributes: padding is not zero")
			}
		}
	}
	return filtered, nil
}

func encryptAKAAttributes(attrs []AKAAttribute, encrKey []byte) ([]AKAAttribute, error) {
	plain, err := marshalAKAAttributes(attrs)
	if err != nil {
		return nil, err
	}
	if rem := len(plain) % aes.BlockSize; rem != 0 {
		padLen := aes.BlockSize - rem
		if padLen < akaPaddingMinLen || padLen > akaPaddingMaxLen || padLen%akaAttributeBlockSize != 0 {
			return nil, fmt.Errorf("encrypting aka attributes: unsupported padding length %d", padLen)
		}
		padding := AKAAttribute{Type: akaAttrPadding, Value: make([]byte, padLen-2)}
		encoded, err := padding.MarshalBinary()
		if err != nil {
			return nil, err
		}
		plain = append(plain, encoded...)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := crand.Read(iv); err != nil {
		return nil, fmt.Errorf("encrypting aka attributes: reading iv: %w", err)
	}
	block, err := aes.NewCipher(encrKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting aka attributes: %w", err)
	}
	ciphertext := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plain)
	return []AKAAttribute{
		{Type: akaAttrIV, Value: append([]byte{0x00, 0x00}, iv...)},
		{Type: akaAttrEncryptedData, Value: append([]byte{0x00, 0x00}, ciphertext...)},
	}, nil
}

func BuildChallengeResponsePacket(identifier byte, res, autKey []byte, useResultInd bool) ([]byte, error) {
	return BuildChallengeResponsePacketWithOptions(ChallengeResponseOptions{
		Identifier:   identifier,
		RES:          res,
		AUTKey:       autKey,
		UseResultInd: useResultInd,
	})
}

func BuildChallengeResponsePacketWithCheckcode(identifier byte, res, autKey []byte, useResultInd bool, checkcode []byte) ([]byte, error) {
	return BuildChallengeResponsePacketWithOptions(ChallengeResponseOptions{
		Identifier:   identifier,
		RES:          res,
		AUTKey:       autKey,
		UseResultInd: useResultInd,
		Checkcode:    checkcode,
	})
}

func BuildChallengeResponsePacketWithOptions(opts ChallengeResponseOptions) ([]byte, error) {
	resAttr, err := buildAKARESAttribute(opts.RES)
	if err != nil {
		return nil, err
	}
	attrs := []AKAAttribute{resAttr}
	if len(opts.Checkcode) != 0 {
		wantCheckcodeLen := akaCheckcodeSHA1Len
		if opts.EAPType == eapTypeAKAPrime {
			wantCheckcodeLen = akaCheckcodeSHA256Len
		}
		if len(opts.Checkcode) != akaCheckcodeEmptyLen && len(opts.Checkcode) != wantCheckcodeLen {
			return nil, fmt.Errorf("building aka response: invalid checkcode length %d", len(opts.Checkcode))
		}
		attrs = append(attrs, AKAAttribute{Type: akaAttrCheckcode, Value: append([]byte(nil), opts.Checkcode...)})
	}
	if opts.UseResultInd {
		attrs = append(attrs, buildAKAUint16Attribute(akaAttrResultInd, 0))
	}
	if opts.IPMSSupport != 0 {
		if !opts.UseResultInd {
			return nil, errors.New("building aka response: ipms indication requires result indication")
		}
		attr, err := buildIPMSIndicationAttribute(opts.IPMSSupport)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, attr)
	}
	message := AKAMessage{Code: eapCodeResponse, Identifier: opts.Identifier, EAPType: opts.EAPType, Subtype: akaSubtypeChallenge, Attributes: attrs}
	if opts.EAPType == eapTypeAKAPrime {
		return message.MarshalSignedSHA256(opts.AUTKey, nil)
	}
	return message.MarshalSigned(opts.AUTKey, nil)
}

func BuildReauthenticationResponsePacket(identifier byte, counter uint16, counterTooSmall bool, useResultInd bool, autKey, encrKey, nonceS []byte) ([]byte, error) {
	return BuildReauthenticationResponsePacketForType(identifier, eapTypeAKA, counter, counterTooSmall, useResultInd, autKey, encrKey, nonceS)
}

func BuildReauthenticationResponsePacketForType(identifier, eapType byte, counter uint16, counterTooSmall bool, useResultInd bool, autKey, encrKey, nonceS []byte) ([]byte, error) {
	nested := []AKAAttribute{}
	if counterTooSmall {
		nested = append(nested, buildAKAUint16Attribute(akaAttrCounterTooSmall, 0))
	}
	nested = append(nested, buildAKAUint16Attribute(akaAttrCounter, counter))
	encrypted, err := encryptAKAAttributes(nested, encrKey)
	if err != nil {
		return nil, err
	}
	attrs := append([]AKAAttribute(nil), encrypted...)
	if useResultInd {
		attrs = append(attrs, buildAKAUint16Attribute(akaAttrResultInd, 0))
	}
	return buildAKAMessageWithType(eapCodeResponse, identifier, eapType, akaSubtypeReauthentication, attrs, autKey, nonceS)
}

func BuildNotificationResponsePacket(identifier byte, notification AKANotification, fastReauth bool, counter uint16, autKey, encrKey []byte) ([]byte, error) {
	return BuildNotificationResponsePacketForType(identifier, eapTypeAKA, notification, fastReauth, counter, autKey, encrKey)
}

func BuildNotificationResponsePacketForType(identifier, eapType byte, notification AKANotification, fastReauth bool, counter uint16, autKey, encrKey []byte) ([]byte, error) {
	attrs := make([]AKAAttribute, 0, 2)
	if notification.Protected && fastReauth {
		encrypted, err := encryptAKAAttributes([]AKAAttribute{buildAKAUint16Attribute(akaAttrCounter, counter)}, encrKey)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, encrypted...)
	}
	if notification.Protected {
		return buildAKAMessageWithType(eapCodeResponse, identifier, eapType, akaSubtypeNotification, attrs, autKey, nil)
	}
	return buildAKAMessageWithType(eapCodeResponse, identifier, eapType, akaSubtypeNotification, attrs, nil, nil)
}

func BuildClientErrorPacket(identifier byte, code uint16) ([]byte, error) {
	return BuildClientErrorPacketForType(identifier, eapTypeAKA, code)
}

func BuildClientErrorPacketForType(identifier, eapType byte, code uint16) ([]byte, error) {
	return buildAKAMessageWithType(eapCodeResponse, identifier, eapType, akaSubtypeClientError, []AKAAttribute{buildAKAUint16Attribute(akaAttrClientErrorCode, code)}, nil, nil)
}

func DeriveFastReauthKeys(identity []byte, counter uint16, nonceS, mk []byte) ([]byte, []byte, error) {
	if len(identity) == 0 || len(nonceS) != akaVectorLen || len(mk) == 0 {
		return nil, nil, errors.New("deriving fast reauth keys: invalid inputs")
	}
	seed := make([]byte, 0, len(identity)+2+len(nonceS)+len(mk))
	seed = append(seed, identity...)
	seed = append(seed, byte(counter>>8), byte(counter))
	seed = append(seed, nonceS...)
	seed = append(seed, mk...)
	xkey := sha1.Sum(seed)
	result, err := sha1DSSExpand(xkey[:], 128)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), result[:64]...), append([]byte(nil), result[64:128]...), nil
}

func sha1DSSExpand(seed []byte, size int) ([]byte, error) {
	if len(seed) != sha1.Size {
		return nil, fmt.Errorf("sha1-dss expand: seed length %d", len(seed))
	}
	if size <= 0 {
		return nil, fmt.Errorf("sha1-dss expand: size %d", size)
	}
	x := new(big.Int).SetBytes(seed)
	result := make([]byte, 0, size)
	for len(result) < size {
		block, err := nextSHA1DSSBlock(x)
		if err != nil {
			return nil, err
		}
		result = append(result, block...)
	}
	return append([]byte(nil), result[:size]...), nil
}

func nextSHA1DSSBlock(x *big.Int) ([]byte, error) {
	block, err := sha1DSS(x.FillBytes(make([]byte, sha1.Size)))
	if err != nil {
		return nil, err
	}
	x.Add(x, new(big.Int).SetBytes(block))
	x.Add(x, sha1DSSIncrement)
	x.Mod(x, sha1DSSModulus)
	return block, nil
}

func sha1DSS(data []byte) ([]byte, error) {
	if len(data) != sha1.Size {
		return nil, fmt.Errorf("sha1-dss: input length %d", len(data))
	}
	words := make([]uint32, 80)
	block := make([]byte, 64)
	copy(block, data)
	for i := range 16 {
		words[i] = binary.BigEndian.Uint32(block[i*4 : i*4+4])
	}
	for i := 16; i < 80; i++ {
		words[i] = rol(words[i-3]^words[i-8]^words[i-14]^words[i-16], 1)
	}
	h0 := uint32(0x67452301)
	h1 := uint32(0xEFCDAB89)
	h2 := uint32(0x98BADCFE)
	h3 := uint32(0x10325476)
	h4 := uint32(0xC3D2E1F0)
	a, b, c, d, e := h0, h1, h2, h3, h4
	for i := range 80 {
		var f, k uint32
		switch {
		case i < 20:
			f = (b & c) | (^b & d)
			k = 0x5A827999
		case i < 40:
			f = b ^ c ^ d
			k = 0x6ED9EBA1
		case i < 60:
			f = (b & c) | (b & d) | (c & d)
			k = 0x8F1BBCDC
		default:
			f = b ^ c ^ d
			k = 0xCA62C1D6
		}
		temp := rol(a, 5) + f + e + k + words[i]
		e = d
		d = c
		c = rol(b, 30)
		b = a
		a = temp
	}
	h0 += a
	h1 += b
	h2 += c
	h3 += d
	h4 += e
	out := make([]byte, sha1.Size)
	binary.BigEndian.PutUint32(out[0:4], h0)
	binary.BigEndian.PutUint32(out[4:8], h1)
	binary.BigEndian.PutUint32(out[8:12], h2)
	binary.BigEndian.PutUint32(out[12:16], h3)
	binary.BigEndian.PutUint32(out[16:20], h4)
	return out, nil
}

func rol(value uint32, bits uint) uint32 {
	return value<<bits | value>>(32-bits)
}
