package eapaka

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
	"unicode/utf8"
)

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

	eapHeaderLen = 4
	eapTypeLen   = 1
	eapMaxLen    = 1<<16 - 1

	akaAttributeMaxWireLen = 255 * 4

	akaSubtypeChallenge              byte = 1
	akaSubtypeAuthenticationReject   byte = 2
	akaSubtypeSynchronizationFailure byte = 4
	akaSubtypeIdentity               byte = 5
)

const (
	akaAttrRAND          byte = 1
	akaAttrAUTN          byte = 2
	akaAttrRES           byte = 3
	akaAttrAUTS          byte = 4
	akaAttrPadding       byte = 6
	akaAttrMAC           byte = 11
	akaAttrIV            byte = 129
	akaAttrEncryptedData byte = 130
)

const (
	akaAttributeReservedLen    = 2
	akaVectorLen               = 16
	akaVectorAttributeLen      = akaAttributeReservedLen + akaVectorLen
	akaMACLen                  = 16
	akaMACAttributeLen         = akaAttributeReservedLen + akaMACLen
	akaRESMinLen               = 4
	akaRESMaxLen               = 16
	akaAUTSLen                 = 14
	akaAUTNAMFOffset           = 6
	akaAMFSeparationBitMask    = 0x80
	akaAttributeBlockSize      = 4
	akaCheckcodeEmptyLen       = akaAttributeReservedLen
	akaCheckcodeSHA1Len        = akaAttributeReservedLen + sha1.Size
	akaCheckcodeSHA256Len      = akaAttributeReservedLen + sha256.Size
	akaResultIndAttributeLen   = akaAttributeReservedLen
	akaSkippableAttributeStart = 128
)

var (
	_ encoding.BinaryMarshaler   = EAPPacket{}
	_ encoding.BinaryUnmarshaler = (*EAPPacket)(nil)
	_ encoding.BinaryMarshaler   = AKAAttribute{}
	_ encoding.BinaryUnmarshaler = (*AKAAttribute)(nil)
	_ encoding.BinaryMarshaler   = AKAMessage{}
	_ encoding.BinaryUnmarshaler = (*AKAMessage)(nil)
	_ encoding.BinaryUnmarshaler = (*AKAChallenge)(nil)
)

type EAPPacket struct {
	Code       byte
	Identifier byte
	Type       byte
	HasType    bool
	Data       []byte
}

func (p EAPPacket) IsIdentityRequest() bool {
	return p.Code == eapCodeRequest && p.HasType && p.Type == eapTypeIdentity
}

func (p EAPPacket) MarshalBinary() ([]byte, error) {
	switch p.Code {
	case eapCodeRequest, eapCodeResponse:
		if !p.HasType {
			return nil, errors.New("marshalling eap packet: request and response require type")
		}
	case eapCodeSuccess, eapCodeFailure:
		if p.HasType || len(p.Data) != 0 {
			return nil, errors.New("marshalling eap packet: success and failure must not include type data")
		}
	default:
		return nil, fmt.Errorf("marshalling eap packet: invalid code %d", p.Code)
	}

	length := eapHeaderLen + len(p.Data)
	if p.HasType {
		length += eapTypeLen
	}
	if length > eapMaxLen {
		return nil, fmt.Errorf("marshalling eap packet: length %d exceeds uint16", length)
	}
	buf := make([]byte, eapHeaderLen)
	buf[0] = p.Code
	buf[1] = p.Identifier
	binary.BigEndian.PutUint16(buf[2:eapHeaderLen], uint16(length))
	if p.HasType {
		buf = append(buf, p.Type)
	}
	buf = append(buf, p.Data...)
	return buf, nil
}

func (p *EAPPacket) UnmarshalBinary(data []byte) error {
	if len(data) < eapHeaderLen {
		return errors.New("parsing eap packet: packet too short")
	}
	length := int(binary.BigEndian.Uint16(data[2:eapHeaderLen]))
	if length < eapHeaderLen || len(data) < length {
		return fmt.Errorf("parsing eap packet: invalid length %d", length)
	}
	if len(data) != length {
		return fmt.Errorf("parsing eap packet: length %d does not match packet size %d", length, len(data))
	}
	packet := EAPPacket{Code: data[0], Identifier: data[1]}
	switch packet.Code {
	case eapCodeSuccess, eapCodeFailure:
		if length != eapHeaderLen {
			return fmt.Errorf("parsing eap packet: success and failure length %d, want %d", length, eapHeaderLen)
		}
		*p = packet
		return nil
	case eapCodeRequest, eapCodeResponse:
		if length < eapHeaderLen+eapTypeLen {
			return errors.New("parsing eap packet: missing type field")
		}
	default:
		return fmt.Errorf("parsing eap packet: invalid code %d", packet.Code)
	}
	packet.HasType = true
	packet.Type = data[4]
	packet.Data = append([]byte(nil), data[eapHeaderLen+eapTypeLen:length]...)
	*p = packet
	return nil
}

func BuildEAPIdentityResponse(id byte, identity string) ([]byte, error) {
	if identity == "" {
		return nil, errors.New("building eap identity response: identity is empty")
	}
	if !utf8.ValidString(identity) || strings.IndexByte(identity, 0) >= 0 {
		return nil, errors.New("building eap identity response: identity is not valid UTF-8 text")
	}
	packet := EAPPacket{
		Code:       eapCodeResponse,
		Identifier: id,
		Type:       eapTypeIdentity,
		HasType:    true,
		Data:       []byte(identity),
	}
	return packet.MarshalBinary()
}

func BuildEAPNakResponse(id byte, desiredTypes ...byte) ([]byte, error) {
	if len(desiredTypes) == 0 {
		return nil, errors.New("building eap nak response: desired types are empty")
	}
	packet := EAPPacket{
		Code:       eapCodeResponse,
		Identifier: id,
		Type:       eapTypeNak,
		HasType:    true,
		Data:       append([]byte(nil), desiredTypes...),
	}
	return packet.MarshalBinary()
}

func BuildEAPNotificationResponse(id byte) ([]byte, error) {
	packet := EAPPacket{
		Code:       eapCodeResponse,
		Identifier: id,
		Type:       eapTypeNotification,
		HasType:    true,
	}
	return packet.MarshalBinary()
}

type AKAAttribute struct {
	Type  byte
	Value []byte
}

func (a AKAAttribute) MarshalBinary() ([]byte, error) {
	wireLen := len(a.Value) + 2
	if wireLen%4 != 0 {
		return nil, fmt.Errorf("marshalling aka attribute: unaligned attribute length %d", wireLen)
	}
	if wireLen > akaAttributeMaxWireLen {
		return nil, fmt.Errorf("marshalling aka attribute: length %d exceeds encodable maximum %d", wireLen, akaAttributeMaxWireLen)
	}
	buf := []byte{a.Type, byte(wireLen / 4)}
	buf = append(buf, a.Value...)
	return buf, nil
}

func (a *AKAAttribute) UnmarshalBinary(data []byte) error {
	attr, size, err := decodeAKAAttribute(data)
	if err != nil {
		return err
	}
	if size != len(data) {
		return fmt.Errorf("parsing aka attribute: %d trailing bytes", len(data)-size)
	}
	*a = attr
	return nil
}

func decodeAKAAttribute(data []byte) (AKAAttribute, int, error) {
	if len(data) < 2 {
		return AKAAttribute{}, 0, errors.New("parsing aka attribute: truncated attribute")
	}
	length := (int(data[1]) * 4) - 2
	if length < 0 || len(data) < 2+length {
		return AKAAttribute{}, 0, fmt.Errorf("parsing aka attribute: invalid length %d", length)
	}
	attr := AKAAttribute{Type: data[0], Value: append([]byte(nil), data[2:2+length]...)}
	return attr, 2 + length, nil
}

func decodeAKAAttributes(data []byte) ([]AKAAttribute, error) {
	attrs := make([]AKAAttribute, 0)
	var seen [256]bool
	for len(data) > 0 {
		attr, size, err := decodeAKAAttribute(data)
		if err != nil {
			return nil, err
		}
		known := isKnownAKAAttribute(attr.Type)
		if known && seen[attr.Type] && !repeatableAKAAttributeType(attr.Type) {
			return nil, fmt.Errorf("parsing aka attributes: duplicate attribute %d", attr.Type)
		}
		if known {
			seen[attr.Type] = true
		}
		attrs = append(attrs, attr)
		data = data[size:]
	}
	return attrs, nil
}

func repeatableAKAAttributeType(attrType byte) bool {
	return attrType == akaAttrKDF
}

type AKAMessage struct {
	Code       byte
	Identifier byte
	EAPType    byte
	Subtype    byte
	Attributes []AKAAttribute
}

func (m AKAMessage) marshalWithAttributes(attrs []AKAAttribute) ([]byte, error) {
	clone := m
	clone.Attributes = attrs
	return clone.MarshalBinary()
}

func (m AKAMessage) zeroedMAC() (AKAMessage, []byte, bool, error) {
	clone := AKAMessage{Code: m.Code, Identifier: m.Identifier, EAPType: m.EAPType, Subtype: m.Subtype, Attributes: append([]AKAAttribute(nil), m.Attributes...)}
	for i := range clone.Attributes {
		if clone.Attributes[i].Type != akaAttrMAC {
			continue
		}
		if len(clone.Attributes[i].Value) != akaMACAttributeLen {
			return AKAMessage{}, nil, false, fmt.Errorf("verifying aka mac: AT_MAC length %d, want %d", len(clone.Attributes[i].Value), akaMACAttributeLen)
		}
		expected := append([]byte(nil), clone.Attributes[i].Value[akaAttributeReservedLen:akaMACAttributeLen]...)
		clone.Attributes[i].Value = append(make([]byte, akaAttributeReservedLen), make([]byte, akaMACLen)...)
		return clone, expected, true, nil
	}
	return clone, nil, false, nil
}

func (m AKAMessage) MarshalSigned(autKey, extra []byte) ([]byte, error) {
	return m.marshalSigned(autKey, extra, akaKAutLen, sha1.New)
}

func (m AKAMessage) MarshalSignedSHA256(autKey, extra []byte) ([]byte, error) {
	return m.marshalSigned(autKey, extra, akaPrimeKAutLen, sha256.New)
}

func (m AKAMessage) marshalSigned(autKey, extra []byte, wantKeyLen int, newHash func() hash.Hash) ([]byte, error) {
	if len(autKey) != wantKeyLen {
		return nil, fmt.Errorf("signing aka message: authentication key length %d, want %d", len(autKey), wantKeyLen)
	}
	if HasAttribute(m.Attributes, akaAttrMAC) {
		return nil, errors.New("signing aka message: AT_MAC is already present")
	}
	attrs := append([]AKAAttribute(nil), m.Attributes...)
	attrs = append(attrs, AKAAttribute{Type: akaAttrMAC, Value: append(make([]byte, akaAttributeReservedLen), make([]byte, akaMACLen)...)})
	packet, err := m.marshalWithAttributes(attrs)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(newHash, autKey)
	_, _ = mac.Write(packet)
	if len(extra) != 0 {
		_, _ = mac.Write(extra)
	}
	attrs[len(attrs)-1].Value = append(make([]byte, akaAttributeReservedLen), mac.Sum(nil)[:akaMACLen]...)
	return m.marshalWithAttributes(attrs)
}

func (m AKAMessage) VerifyMAC(autKey, extra []byte) error {
	return m.verifyMAC(autKey, extra, akaKAutLen, sha1.New)
}

func (m AKAMessage) VerifyMACSHA256(autKey, extra []byte) error {
	return m.verifyMAC(autKey, extra, akaPrimeKAutLen, sha256.New)
}

func (m AKAMessage) verifyMAC(autKey, extra []byte, wantKeyLen int, newHash func() hash.Hash) error {
	if len(autKey) != wantKeyLen {
		return fmt.Errorf("verifying aka mac: authentication key length %d, want %d", len(autKey), wantKeyLen)
	}
	zeroed, expected, ok, err := m.zeroedMAC()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("verifying aka mac: AT_MAC is missing")
	}
	packet, err := zeroed.MarshalBinary()
	if err != nil {
		return err
	}
	mac := hmac.New(newHash, autKey)
	_, _ = mac.Write(packet)
	if len(extra) != 0 {
		_, _ = mac.Write(extra)
	}
	if !hmac.Equal(expected, mac.Sum(nil)[:akaMACLen]) {
		return errors.New("verifying aka mac: mismatch")
	}
	return nil
}

func (m AKAMessage) MarshalBinary() ([]byte, error) {
	eapType, err := m.eapType()
	if err != nil {
		return nil, err
	}
	data := []byte{m.Subtype, 0x00, 0x00}
	var seen [256]bool
	for _, attr := range m.Attributes {
		known := isKnownAKAAttribute(attr.Type)
		if known && seen[attr.Type] && !repeatableAKAAttributeType(attr.Type) {
			return nil, fmt.Errorf("marshalling aka message: duplicate attribute %d", attr.Type)
		}
		if known {
			seen[attr.Type] = true
		}
		encoded, err := attr.MarshalBinary()
		if err != nil {
			return nil, err
		}
		data = append(data, encoded...)
	}
	packet := EAPPacket{Code: m.Code, Identifier: m.Identifier, Type: eapType, HasType: true, Data: data}
	return packet.MarshalBinary()
}

func (m AKAMessage) eapType() (byte, error) {
	switch m.EAPType {
	case 0, eapTypeAKA:
		return eapTypeAKA, nil
	case eapTypeAKAPrime:
		return eapTypeAKAPrime, nil
	default:
		return 0, fmt.Errorf("marshalling aka message: unsupported eap type %d", m.EAPType)
	}
}

func (m *AKAMessage) UnmarshalBinary(data []byte) error {
	var packet EAPPacket
	if err := packet.UnmarshalBinary(data); err != nil {
		return err
	}
	if !packet.HasType || packet.Type != eapTypeAKA && packet.Type != eapTypeAKAPrime {
		return fmt.Errorf("parsing aka message: unexpected eap type %d", packet.Type)
	}
	if len(packet.Data) < 3 {
		return errors.New("parsing aka message: payload too short")
	}
	attrs, err := decodeAKAAttributes(packet.Data[3:])
	if err != nil {
		return err
	}
	*m = AKAMessage{Code: packet.Code, Identifier: packet.Identifier, EAPType: packet.Type, Subtype: packet.Data[0], Attributes: attrs}
	return nil
}

type AKAChallenge struct {
	Identifier        byte
	EAPType           byte
	RAND              []byte
	AUTN              []byte
	KDF               uint16
	NetworkName       []byte
	IV                []byte
	EncryptedData     []byte
	TrustRelationship TrustRelationship
}

func (c AKAChallenge) IsAKAPrime() bool {
	return c.EAPType == eapTypeAKAPrime
}

func (c AKAChallenge) AMFSeparationBitSet() bool {
	return len(c.AUTN) == akaVectorLen && c.AUTN[akaAUTNAMFOffset]&akaAMFSeparationBitMask != 0
}

func (c *AKAChallenge) UnmarshalBinary(data []byte) error {
	var message AKAMessage
	if err := message.UnmarshalBinary(data); err != nil {
		return err
	}
	return c.UnmarshalMessage(message)
}

func AKAParametersFromChallenge(message AKAMessage) (AKAChallenge, error) {
	if message.Code != eapCodeRequest || message.Subtype != akaSubtypeChallenge {
		return AKAChallenge{}, errors.New("parsing aka challenge: unsupported packet")
	}
	challenge := AKAChallenge{Identifier: message.Identifier, EAPType: message.EAPType}
	seenRAND := false
	seenAUTN := false
	for _, attr := range message.Attributes {
		switch attr.Type {
		case akaAttrRAND:
			if seenRAND {
				return AKAChallenge{}, errors.New("parsing aka challenge: duplicate rand attribute")
			}
			if len(attr.Value) != akaVectorAttributeLen {
				return AKAChallenge{}, fmt.Errorf("parsing aka challenge: invalid rand length %d", len(attr.Value))
			}
			challenge.RAND = append([]byte(nil), attr.Value[akaAttributeReservedLen:]...)
			seenRAND = true
		case akaAttrAUTN:
			if seenAUTN {
				return AKAChallenge{}, errors.New("parsing aka challenge: duplicate autn attribute")
			}
			if len(attr.Value) != akaVectorAttributeLen {
				return AKAChallenge{}, fmt.Errorf("parsing aka challenge: invalid autn length %d", len(attr.Value))
			}
			challenge.AUTN = append([]byte(nil), attr.Value[akaAttributeReservedLen:]...)
			seenAUTN = true
		}
	}
	if !seenRAND || !seenAUTN {
		return AKAChallenge{}, errors.New("parsing aka challenge: missing rand or autn")
	}
	return challenge, nil
}

func AKAPrimeParametersFromChallenge(message AKAMessage) (AKAChallenge, error) {
	challenge, err := AKAParametersFromChallenge(message)
	if err != nil {
		return AKAChallenge{}, err
	}
	if message.EAPType != eapTypeAKAPrime {
		return AKAChallenge{}, errors.New("parsing aka prime challenge parameters: unexpected eap type")
	}
	seenKDFInput := false
	seenKDF := false
	for _, attr := range message.Attributes {
		switch attr.Type {
		case akaAttrKDFInput:
			if seenKDFInput {
				return AKAChallenge{}, fmt.Errorf("parsing aka prime challenge parameters: %w: duplicate kdf input", ErrAKAPrimeAuthenticationFailure)
			}
			kdfInput, err := KDFInputFromAttribute(&attr)
			if err != nil {
				return AKAChallenge{}, fmt.Errorf("parsing aka prime challenge parameters: %w: %w", ErrAKAPrimeAuthenticationFailure, err)
			}
			challenge.NetworkName = kdfInput.NetworkName
			seenKDFInput = true
		case akaAttrKDF:
			if seenKDF {
				return AKAChallenge{}, fmt.Errorf("parsing aka prime challenge parameters: %w: duplicate kdf", ErrAKAPrimeAuthenticationFailure)
			}
			kdf, err := KDFFromAttribute(&attr)
			if err != nil {
				return AKAChallenge{}, fmt.Errorf("parsing aka prime challenge parameters: %w: %w", ErrAKAPrimeAuthenticationFailure, err)
			}
			challenge.KDF = kdf.Version
			seenKDF = true
		}
	}
	if !seenKDF {
		return AKAChallenge{}, fmt.Errorf("parsing aka prime challenge parameters: %w: missing kdf", ErrAKAPrimeAuthenticationFailure)
	}
	if challenge.KDF != akaPrimeKDFDefault {
		return AKAChallenge{}, fmt.Errorf("parsing aka prime challenge parameters: %w: unsupported kdf %d", ErrAKAPrimeAuthenticationFailure, challenge.KDF)
	}
	if !seenKDFInput {
		return AKAChallenge{}, fmt.Errorf("parsing aka prime challenge parameters: %w: missing kdf input", ErrAKAPrimeAuthenticationFailure)
	}
	return challenge, nil
}

func (c *AKAChallenge) UnmarshalMessage(message AKAMessage) error {
	challenge, err := AKAParametersFromChallenge(message)
	if err != nil {
		return err
	}
	allowed := []byte{akaAttrRAND, akaAttrAUTN, akaAttrMAC, akaAttrIV, akaAttrEncryptedData, akaAttrCheckcode, akaAttrResultInd, akaAttrTrustInd}
	if message.EAPType == eapTypeAKAPrime {
		allowed = append(allowed, akaAttrKDFInput, akaAttrKDF)
	} else {
		allowed = append(allowed, akaAttrBidding)
	}
	if err := validateAKAAttributes(message.Attributes, allowed...); err != nil {
		return fmt.Errorf("parsing aka challenge: %w", err)
	}

	seenMAC := false
	seenKDFInput := false
	seenKDF := false
	seenIV := false
	seenEncryptedData := false
	seenResultInd := false
	for _, attr := range message.Attributes {
		switch attr.Type {
		case akaAttrRAND, akaAttrAUTN:
			continue
		case akaAttrMAC:
			if seenMAC {
				return errors.New("parsing aka challenge: duplicate mac attribute")
			}
			if len(attr.Value) != akaMACAttributeLen {
				return fmt.Errorf("parsing aka challenge: invalid mac length %d", len(attr.Value))
			}
			seenMAC = true
		case akaAttrKDFInput:
			if message.EAPType != eapTypeAKAPrime {
				return errors.New("parsing aka challenge: kdf input is only valid for aka prime")
			}
			if seenKDFInput {
				return errors.New("parsing aka challenge: duplicate kdf input attribute")
			}
			kdfInput, err := KDFInputFromAttribute(&attr)
			if err != nil {
				return fmt.Errorf("parsing aka challenge: %w: %w", ErrAKAPrimeAuthenticationFailure, err)
			}
			challenge.NetworkName = kdfInput.NetworkName
			seenKDFInput = true
		case akaAttrKDF:
			if message.EAPType != eapTypeAKAPrime {
				return errors.New("parsing aka challenge: kdf is only valid for aka prime")
			}
			if seenKDF {
				return fmt.Errorf("parsing aka challenge: %w: duplicate kdf attribute", ErrAKAPrimeAuthenticationFailure)
			}
			kdf, err := KDFFromAttribute(&attr)
			if err != nil {
				return fmt.Errorf("parsing aka challenge: %w", err)
			}
			challenge.KDF = kdf.Version
			seenKDF = true
		case akaAttrIV:
			if seenIV {
				return errors.New("parsing aka challenge: duplicate iv attribute")
			}
			if len(attr.Value) != akaVectorAttributeLen {
				return fmt.Errorf("parsing aka challenge: invalid iv length %d", len(attr.Value))
			}
			challenge.IV = append([]byte(nil), attr.Value[akaAttributeReservedLen:]...)
			seenIV = true
		case akaAttrEncryptedData:
			if seenEncryptedData {
				return errors.New("parsing aka challenge: duplicate encrypted data attribute")
			}
			if len(attr.Value) < akaAttributeReservedLen || (len(attr.Value)-akaAttributeReservedLen)%akaVectorLen != 0 {
				return fmt.Errorf("parsing aka challenge: invalid encrypted data length %d", len(attr.Value))
			}
			challenge.EncryptedData = append([]byte(nil), attr.Value[akaAttributeReservedLen:]...)
			seenEncryptedData = true
		case akaAttrCheckcode:
			switch {
			case message.EAPType == eapTypeAKAPrime && len(attr.Value) != akaCheckcodeEmptyLen && len(attr.Value) != akaCheckcodeSHA256Len:
				return fmt.Errorf("parsing aka challenge: invalid checkcode length %d", len(attr.Value))
			case message.EAPType != eapTypeAKAPrime && len(attr.Value) != akaCheckcodeEmptyLen && len(attr.Value) != akaCheckcodeSHA1Len:
				return fmt.Errorf("parsing aka challenge: invalid checkcode length %d", len(attr.Value))
			}
		case akaAttrResultInd:
			if seenResultInd {
				return errors.New("parsing aka challenge: duplicate result indication attribute")
			}
			if len(attr.Value) != akaResultIndAttributeLen {
				return fmt.Errorf("parsing aka challenge: invalid result indication length %d", len(attr.Value))
			}
			seenResultInd = true
		case akaAttrBidding:
			if _, err := BiddingFromAttribute(&attr); err != nil {
				return fmt.Errorf("parsing aka challenge: %w", err)
			}
		case akaAttrTrustInd:
			indication, err := TrustIndicationFromAttribute(&attr)
			if err != nil {
				return fmt.Errorf("parsing aka challenge: %w", err)
			}
			challenge.TrustRelationship = indication.Relationship
		default:
			// RFC 4187 section 8.1 requires peers to ignore unknown skippable
			// attributes (128..255) while still rejecting unknown
			// non-skippable ones.
			if attr.Type >= akaSkippableAttributeStart {
				continue
			}
			return fmt.Errorf("parsing aka challenge: unexpected attribute %d", attr.Type)
		}
	}
	if !seenMAC {
		return errors.New("parsing aka challenge: missing mac")
	}
	if message.EAPType == eapTypeAKAPrime {
		if !seenKDF {
			return fmt.Errorf("parsing aka challenge: %w: missing kdf", ErrAKAPrimeAuthenticationFailure)
		}
		if challenge.KDF != akaPrimeKDFDefault {
			return fmt.Errorf("parsing aka challenge: %w: unsupported kdf %d", ErrAKAPrimeAuthenticationFailure, challenge.KDF)
		}
		if !seenKDFInput {
			return fmt.Errorf("parsing aka challenge: %w: missing kdf input", ErrAKAPrimeAuthenticationFailure)
		}
		if len(challenge.NetworkName) == 0 {
			return fmt.Errorf("parsing aka challenge: %w: network name is empty", ErrAKAPrimeAuthenticationFailure)
		}
	}
	if seenIV != seenEncryptedData {
		return errors.New("parsing aka challenge: iv and encrypted data must appear together")
	}
	*c = challenge
	return nil
}

func BuildAKAResponse(id byte, res, autKey []byte) ([]byte, error) {
	if len(autKey) != akaKAutLen {
		return nil, fmt.Errorf("building aka response: authentication key length %d, want %d", len(autKey), akaKAutLen)
	}
	resAttr, err := buildAKARESAttribute(res)
	if err != nil {
		return nil, err
	}
	attrs := []AKAAttribute{resAttr}
	attrs = append(attrs, AKAAttribute{Type: akaAttrMAC, Value: append(make([]byte, akaAttributeReservedLen), make([]byte, akaMACLen)...)})
	macIndex := len(attrs) - 1
	message := AKAMessage{Code: eapCodeResponse, Identifier: id, Subtype: akaSubtypeChallenge, Attributes: attrs}
	packet, err := message.MarshalBinary()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha1.New, autKey)
	_, _ = mac.Write(packet)
	attrs[macIndex].Value = append(make([]byte, akaAttributeReservedLen), mac.Sum(nil)[:akaMACLen]...)
	message.Attributes = attrs
	return message.MarshalBinary()
}

func buildAKARESAttribute(res []byte) (AKAAttribute, error) {
	if len(res) < akaRESMinLen || len(res) > akaRESMaxLen {
		return AKAAttribute{}, fmt.Errorf("building aka response: res length %d, want %d..%d", len(res), akaRESMinLen, akaRESMaxLen)
	}
	value := make([]byte, akaAttributeReservedLen+len(res))
	binary.BigEndian.PutUint16(value[:2], uint16(len(res)*8))
	copy(value[akaAttributeReservedLen:], res)
	if rem := (len(value) + akaAttributeReservedLen) % akaAttributeBlockSize; rem != 0 {
		value = append(value, make([]byte, akaAttributeBlockSize-rem)...)
	}
	return AKAAttribute{Type: akaAttrRES, Value: value}, nil
}

func BuildAKAIdentityResponse(id byte, identity string) ([]byte, error) {
	return buildAKAIdentityResponse(id, eapTypeAKA, identity)
}

func BuildAKAPrimeIdentityResponse(id byte, identity string) ([]byte, error) {
	return buildAKAIdentityResponse(id, eapTypeAKAPrime, identity)
}

func buildAKAIdentityResponse(id, eapType byte, identity string) ([]byte, error) {
	if identity == "" {
		return nil, errors.New("building aka identity response: identity is empty")
	}
	if !utf8.ValidString(identity) || strings.IndexByte(identity, 0) >= 0 {
		return nil, errors.New("building aka identity response: identity is not valid UTF-8 text")
	}
	message := AKAMessage{Code: eapCodeResponse, Identifier: id, EAPType: eapType, Subtype: akaSubtypeIdentity, Attributes: []AKAAttribute{buildAKAStringAttribute(akaAttrIdentity, identity)}}
	return message.MarshalBinary()
}

func BuildAKAAuthenticationReject(id byte) ([]byte, error) {
	return buildAKAMessageWithType(eapCodeResponse, id, eapTypeAKA, akaSubtypeAuthenticationReject, nil, nil, nil)
}

func BuildAKAPrimeAuthenticationReject(id byte) ([]byte, error) {
	return buildAKAMessageWithType(eapCodeResponse, id, eapTypeAKAPrime, akaSubtypeAuthenticationReject, nil, nil, nil)
}

func BuildAKAPrimeKDFSelection(id byte, kdf uint16) ([]byte, error) {
	attr, err := (KDF{Version: kdf}).MarshalBinary()
	if err != nil {
		return nil, err
	}
	var kdfAttr AKAAttribute
	if err := kdfAttr.UnmarshalBinary(attr); err != nil {
		return nil, err
	}
	return buildAKAMessageWithType(eapCodeResponse, id, eapTypeAKAPrime, akaSubtypeChallenge, []AKAAttribute{kdfAttr}, nil, nil)
}

func BuildAKASynchronizationFailure(id byte, auts []byte) ([]byte, error) {
	if len(auts) != akaAUTSLen {
		return nil, fmt.Errorf("building aka synchronization failure: auts length %d, want %d", len(auts), akaAUTSLen)
	}
	return buildAKAMessageWithType(eapCodeResponse, id, eapTypeAKA, akaSubtypeSynchronizationFailure, []AKAAttribute{{Type: akaAttrAUTS, Value: append([]byte(nil), auts...)}}, nil, nil)
}

func BuildAKAPrimeSynchronizationFailure(id byte, auts []byte, kdfs []uint16) ([]byte, error) {
	if len(auts) != akaAUTSLen {
		return nil, fmt.Errorf("building aka synchronization failure: auts length %d, want %d", len(auts), akaAUTSLen)
	}
	if len(kdfs) == 0 {
		return nil, errors.New("building aka synchronization failure: kdf list is empty")
	}
	attrs := make([]AKAAttribute, 0, len(kdfs)+1)
	attrs = append(attrs, AKAAttribute{Type: akaAttrAUTS, Value: append([]byte(nil), auts...)})
	for _, kdf := range kdfs {
		attrs = append(attrs, buildAKAUint16Attribute(akaAttrKDF, kdf))
	}
	return buildAKAMessageWithType(eapCodeResponse, id, eapTypeAKAPrime, akaSubtypeSynchronizationFailure, attrs, nil, nil)
}
