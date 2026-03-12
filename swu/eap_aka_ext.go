package swu

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
)

const (
	akaSubtypeNotification     byte = 12
	akaSubtypeReauthentication byte = 13
	akaSubtypeClientError      byte = 14
)

const (
	akaAttrPermanentIDReq  byte = 10
	akaAttrNotification    byte = 12
	akaAttrAnyIDReq        byte = 13
	akaAttrIdentity        byte = 14
	akaAttrFullAuthIDReq   byte = 17
	akaAttrCounter         byte = 19
	akaAttrCounterTooSmall byte = 20
	akaAttrNonceS          byte = 21
	akaAttrClientErrorCode byte = 22
	akaAttrNextPseudonym   byte = 132
	akaAttrNextReauthID    byte = 133
	akaAttrCheckcode       byte = 134
	akaAttrResultInd       byte = 135
)

const (
	akaNotificationGeneralFailureAfterAuth uint16 = 0
	akaNotificationGeneralFailure          uint16 = 16384
	akaNotificationSuccess                 uint16 = 32768
	akaClientErrorUnableToProcessPacket    uint16 = 0
)

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

func findAKAAttribute(attrs []AKAAttribute, attrType byte) *AKAAttribute {
	for i := range attrs {
		if attrs[i].Type == attrType {
			return &attrs[i]
		}
	}
	return nil
}

func hasAKAAttribute(attrs []AKAAttribute, attrType byte) bool {
	return findAKAAttribute(attrs, attrType) != nil
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

func akaUint16Value(attr *AKAAttribute) (uint16, error) {
	if attr == nil {
		return 0, fmt.Errorf("parsing aka uint16 attribute: attribute is nil")
	}
	if len(attr.Value) < 2 {
		return 0, fmt.Errorf("parsing aka uint16 attribute: value too short")
	}
	return binary.BigEndian.Uint16(attr.Value[:2]), nil
}

func buildAKAStringAttribute(attrType byte, value string) AKAAttribute {
	length := len(value)
	buf := make([]byte, 2+length)
	binary.BigEndian.PutUint16(buf[:2], uint16(length))
	copy(buf[2:], value)
	for (len(buf)+2)%4 != 0 {
		buf = append(buf, 0x00)
	}
	return AKAAttribute{Type: attrType, Value: buf}
}

func akaStringValue(attr *AKAAttribute) (string, error) {
	if attr == nil {
		return "", fmt.Errorf("parsing aka string attribute: attribute is nil")
	}
	if len(attr.Value) < 2 {
		return "", fmt.Errorf("parsing aka string attribute: value too short")
	}
	length := int(binary.BigEndian.Uint16(attr.Value[:2]))
	if len(attr.Value) < 2+length {
		return "", fmt.Errorf("parsing aka string attribute: value length %d is too short for %d", len(attr.Value), length)
	}
	return string(attr.Value[2 : 2+length]), nil
}

func (n *AKANotification) UnmarshalAttributes(attrs []AKAAttribute) error {
	attr := findAKAAttribute(attrs, akaAttrNotification)
	if attr == nil {
		return fmt.Errorf("parsing aka notification: AT_NOTIFICATION is missing")
	}
	code, err := akaUint16Value(attr)
	if err != nil {
		return err
	}
	*n = AKANotification{Code: code, Success: code&0x8000 != 0, Protected: code&0x4000 == 0}
	return nil
}

func decodeAKANotification(attrs []AKAAttribute) (AKANotification, error) {
	var notification AKANotification
	if err := notification.UnmarshalAttributes(attrs); err != nil {
		return AKANotification{}, err
	}
	return notification, nil
}

func (r *AKAReauthentication) UnmarshalMessage(message AKAMessage, encrKey []byte) error {
	if message.Code != eapCodeRequest || message.Subtype != akaSubtypeReauthentication {
		return fmt.Errorf("parsing aka reauthentication: unsupported packet")
	}
	nested, err := decryptAKAAttributes(message.Attributes, encrKey)
	if err != nil {
		return err
	}
	counter, err := akaUint16Value(findAKAAttribute(nested, akaAttrCounter))
	if err != nil {
		return fmt.Errorf("parsing aka reauthentication: %w", err)
	}
	nonceAttr := findAKAAttribute(nested, akaAttrNonceS)
	if nonceAttr == nil || len(nonceAttr.Value) < 18 {
		return fmt.Errorf("parsing aka reauthentication: AT_NONCE_S is missing")
	}
	req := AKAReauthentication{
		Identifier:   message.Identifier,
		Counter:      counter,
		NonceS:       append([]byte(nil), nonceAttr.Value[2:18]...),
		UseResultInd: hasAKAAttribute(message.Attributes, akaAttrResultInd),
	}
	if attr := findAKAAttribute(nested, akaAttrNextReauthID); attr != nil {
		identity, err := akaStringValue(attr)
		if err != nil {
			return fmt.Errorf("parsing aka reauthentication: %w", err)
		}
		req.NextReauthID = identity
	}
	*r = req
	return nil
}

func decodeAKAReauthentication(data []byte, encrKey []byte) (AKAReauthentication, error) {
	var message AKAMessage
	if err := message.UnmarshalBinary(data); err != nil {
		return AKAReauthentication{}, err
	}
	var req AKAReauthentication
	if err := req.UnmarshalMessage(message, encrKey); err != nil {
		return AKAReauthentication{}, err
	}
	return req, nil
}

func buildAKAMessage(code, identifier, subtype byte, attrs []AKAAttribute, autKey, extra []byte) ([]byte, error) {
	message := AKAMessage{Code: code, Identifier: identifier, Subtype: subtype, Attributes: append([]AKAAttribute(nil), attrs...)}
	return message.MarshalSigned(autKey, extra)
}

func verifyAKAMessageMAC(data, autKey, extra []byte) error {
	var message AKAMessage
	if err := message.UnmarshalBinary(data); err != nil {
		return err
	}
	return message.VerifyMAC(autKey, extra)
}

func decryptAKAAttributes(attrs []AKAAttribute, encrKey []byte) ([]AKAAttribute, error) {
	ivAttr := findAKAAttribute(attrs, akaAttrIV)
	encrAttr := findAKAAttribute(attrs, akaAttrEncryptedData)
	if ivAttr == nil || encrAttr == nil {
		return nil, fmt.Errorf("decrypting aka attributes: AT_IV or AT_ENCR_DATA is missing")
	}
	if len(ivAttr.Value) < 18 {
		return nil, fmt.Errorf("decrypting aka attributes: AT_IV is truncated")
	}
	if len(encrAttr.Value) < 2 {
		return nil, fmt.Errorf("decrypting aka attributes: AT_ENCR_DATA is truncated")
	}
	ciphertext := encrAttr.Value[2:]
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("decrypting aka attributes: ciphertext is not block aligned")
	}
	block, err := aes.NewCipher(encrKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting aka attributes: %w", err)
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, ivAttr.Value[2:18]).CryptBlocks(plain, ciphertext)
	parsed, err := decodeAKAAttributes(plain)
	if err != nil {
		return nil, fmt.Errorf("decrypting aka attributes: %w", err)
	}
	filtered := make([]AKAAttribute, 0, len(parsed))
	for _, attr := range parsed {
		if attr.Type != akaAttrPadding {
			filtered = append(filtered, attr)
			continue
		}
		for _, b := range attr.Value {
			if b != 0 {
				return nil, fmt.Errorf("decrypting aka attributes: padding is not zero")
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
		if padLen < 4 || padLen > 12 || padLen%4 != 0 {
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

func akaUint16Bytes(value uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, value)
	return buf
}

func buildAKAChallengeResponsePacket(identifier byte, res, autKey []byte, useResultInd bool) ([]byte, error) {
	attrs := []AKAAttribute{{Type: akaAttrRES, Value: append(akaUint16Bytes(uint16(len(res)*8)), res...)}}
	if useResultInd {
		attrs = append(attrs, buildAKAUint16Attribute(akaAttrResultInd, 0))
	}
	return buildAKAMessage(eapCodeResponse, identifier, akaSubtypeChallenge, attrs, autKey, nil)
}

func buildAKAReauthenticationResponsePacket(identifier byte, counter uint16, counterTooSmall bool, useResultInd bool, autKey, encrKey, nonceS []byte) ([]byte, error) {
	nested := []AKAAttribute{buildAKAUint16Attribute(akaAttrCounter, counter)}
	if counterTooSmall {
		nested = append(nested, buildAKAUint16Attribute(akaAttrCounterTooSmall, 0))
	}
	encrypted, err := encryptAKAAttributes(nested, encrKey)
	if err != nil {
		return nil, err
	}
	attrs := append([]AKAAttribute(nil), encrypted...)
	if useResultInd {
		attrs = append(attrs, buildAKAUint16Attribute(akaAttrResultInd, 0))
	}
	return buildAKAMessage(eapCodeResponse, identifier, akaSubtypeReauthentication, attrs, autKey, nonceS)
}

func buildAKANotificationResponsePacket(identifier byte, notification AKANotification, counter uint16, autKey, encrKey []byte) ([]byte, error) {
	attrs := make([]AKAAttribute, 0, 2)
	if notification.Protected && len(encrKey) != 0 {
		encrypted, err := encryptAKAAttributes([]AKAAttribute{buildAKAUint16Attribute(akaAttrCounter, counter)}, encrKey)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, encrypted...)
	}
	if notification.Protected {
		return buildAKAMessage(eapCodeResponse, identifier, akaSubtypeNotification, attrs, autKey, nil)
	}
	return buildAKAMessage(eapCodeResponse, identifier, akaSubtypeNotification, attrs, nil, nil)
}

func buildAKAClientErrorPacket(identifier byte, code uint16) ([]byte, error) {
	return buildAKAMessage(eapCodeResponse, identifier, akaSubtypeClientError, []AKAAttribute{buildAKAUint16Attribute(akaAttrClientErrorCode, code)}, nil, nil)
}

func deriveFastReauthKeys(identity []byte, counter uint16, nonceS, mk []byte) ([]byte, []byte, error) {
	if len(identity) == 0 || len(nonceS) != 16 || len(mk) == 0 {
		return nil, nil, fmt.Errorf("deriving fast reauth keys: invalid inputs")
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
