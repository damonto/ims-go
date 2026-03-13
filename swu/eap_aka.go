package swu

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding"
	"encoding/binary"
	"fmt"
)

const (
	eapCodeRequest  byte = 1
	eapCodeResponse byte = 2
	eapCodeSuccess  byte = 3
	eapCodeFailure  byte = 4
	eapTypeAKA      byte = 23

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

var (
	_ encoding.BinaryMarshaler   = EAPPacket{}
	_ encoding.BinaryUnmarshaler = (*EAPPacket)(nil)
	_ encoding.BinaryMarshaler   = AKAAttribute{}
	_ encoding.BinaryUnmarshaler = (*AKAAttribute)(nil)
	_ encoding.BinaryMarshaler   = AKAMessage{}
	_ encoding.BinaryUnmarshaler = (*AKAMessage)(nil)
)

type EAPPacket struct {
	Code       byte
	Identifier byte
	Type       byte
	HasType    bool
	Data       []byte
}

func (p EAPPacket) MarshalBinary() ([]byte, error) {
	length := 4 + len(p.Data)
	if p.HasType {
		length++
	}
	buf := make([]byte, 4)
	buf[0] = p.Code
	buf[1] = p.Identifier
	binary.BigEndian.PutUint16(buf[2:4], uint16(length))
	if p.HasType {
		buf = append(buf, p.Type)
	}
	buf = append(buf, p.Data...)
	return buf, nil
}

func (p *EAPPacket) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("parsing eap packet: packet too short")
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length < 4 || len(data) < length {
		return fmt.Errorf("parsing eap packet: invalid length %d", length)
	}
	packet := EAPPacket{Code: data[0], Identifier: data[1]}
	if packet.Code == eapCodeSuccess || packet.Code == eapCodeFailure {
		packet.Data = append([]byte(nil), data[4:length]...)
		*p = packet
		return nil
	}
	if length < 5 {
		return fmt.Errorf("parsing eap packet: missing type field")
	}
	packet.HasType = true
	packet.Type = data[4]
	packet.Data = append([]byte(nil), data[5:length]...)
	*p = packet
	return nil
}

type AKAAttribute struct {
	Type  byte
	Value []byte
}

func (a AKAAttribute) MarshalBinary() ([]byte, error) {
	if (len(a.Value)+2)%4 != 0 {
		return nil, fmt.Errorf("marshalling aka attribute: unaligned attribute length %d", len(a.Value)+2)
	}
	buf := []byte{a.Type, byte((len(a.Value) + 2) / 4)}
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
		return AKAAttribute{}, 0, fmt.Errorf("parsing aka attribute: truncated attribute")
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
	for len(data) > 0 {
		attr, size, err := decodeAKAAttribute(data)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, attr)
		data = data[size:]
	}
	return attrs, nil
}

type AKAMessage struct {
	Code       byte
	Identifier byte
	Subtype    byte
	Attributes []AKAAttribute
}

func (m AKAMessage) marshalWithAttributes(attrs []AKAAttribute) ([]byte, error) {
	clone := m
	clone.Attributes = attrs
	return clone.MarshalBinary()
}

func (m AKAMessage) zeroedMAC() (AKAMessage, []byte, bool, error) {
	clone := AKAMessage{Code: m.Code, Identifier: m.Identifier, Subtype: m.Subtype, Attributes: append([]AKAAttribute(nil), m.Attributes...)}
	for i := range clone.Attributes {
		if clone.Attributes[i].Type != akaAttrMAC {
			continue
		}
		if len(clone.Attributes[i].Value) < 18 {
			return AKAMessage{}, nil, false, fmt.Errorf("verifying aka mac: AT_MAC is truncated")
		}
		expected := append([]byte(nil), clone.Attributes[i].Value[2:18]...)
		clone.Attributes[i].Value = append([]byte{0x00, 0x00}, make([]byte, 16)...)
		return clone, expected, true, nil
	}
	return clone, nil, false, nil
}

func (m AKAMessage) MarshalSigned(autKey, extra []byte) ([]byte, error) {
	if len(autKey) == 0 {
		return m.MarshalBinary()
	}
	attrs := append([]AKAAttribute(nil), m.Attributes...)
	attrs = append(attrs, AKAAttribute{Type: akaAttrMAC, Value: append([]byte{0x00, 0x00}, make([]byte, 16)...)})
	packet, err := m.marshalWithAttributes(attrs)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha1.New, autKey)
	_, _ = mac.Write(packet)
	if len(extra) != 0 {
		_, _ = mac.Write(extra)
	}
	attrs[len(attrs)-1].Value = append([]byte{0x00, 0x00}, mac.Sum(nil)[:16]...)
	return m.marshalWithAttributes(attrs)
}

func (m AKAMessage) VerifyMAC(autKey, extra []byte) error {
	if len(autKey) == 0 {
		return fmt.Errorf("verifying aka mac: key is empty")
	}
	zeroed, expected, ok, err := m.zeroedMAC()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("verifying aka mac: AT_MAC is missing")
	}
	packet, err := zeroed.MarshalBinary()
	if err != nil {
		return err
	}
	mac := hmac.New(sha1.New, autKey)
	_, _ = mac.Write(packet)
	if len(extra) != 0 {
		_, _ = mac.Write(extra)
	}
	if !hmac.Equal(expected, mac.Sum(nil)[:16]) {
		return fmt.Errorf("verifying aka mac: mismatch")
	}
	return nil
}

func (m AKAMessage) MarshalBinary() ([]byte, error) {
	data := []byte{m.Subtype, 0x00, 0x00}
	for _, attr := range m.Attributes {
		encoded, err := attr.MarshalBinary()
		if err != nil {
			return nil, err
		}
		data = append(data, encoded...)
	}
	packet := EAPPacket{Code: m.Code, Identifier: m.Identifier, Type: eapTypeAKA, HasType: true, Data: data}
	return packet.MarshalBinary()
}

func (m *AKAMessage) UnmarshalBinary(data []byte) error {
	var packet EAPPacket
	if err := packet.UnmarshalBinary(data); err != nil {
		return err
	}
	if !packet.HasType || packet.Type != eapTypeAKA {
		return fmt.Errorf("parsing aka message: unexpected eap type %d", packet.Type)
	}
	if len(packet.Data) < 3 {
		return fmt.Errorf("parsing aka message: payload too short")
	}
	attrs, err := decodeAKAAttributes(packet.Data[3:])
	if err != nil {
		return err
	}
	*m = AKAMessage{Code: packet.Code, Identifier: packet.Identifier, Subtype: packet.Data[0], Attributes: attrs}
	return nil
}

type AKAChallenge struct {
	Identifier    byte
	RAND          []byte
	AUTN          []byte
	IV            []byte
	EncryptedData []byte
}

func ParseAKAChallenge(data []byte) (AKAChallenge, error) {
	var message AKAMessage
	if err := message.UnmarshalBinary(data); err != nil {
		return AKAChallenge{}, err
	}
	if message.Code != eapCodeRequest || message.Subtype != akaSubtypeChallenge {
		return AKAChallenge{}, fmt.Errorf("parsing aka challenge: unsupported packet")
	}
	challenge := AKAChallenge{Identifier: message.Identifier}
	for _, attr := range message.Attributes {
		if len(attr.Value) < 2 {
			continue
		}
		switch attr.Type {
		case akaAttrRAND:
			challenge.RAND = append([]byte(nil), attr.Value[2:]...)
		case akaAttrAUTN:
			challenge.AUTN = append([]byte(nil), attr.Value[2:]...)
		case akaAttrIV:
			challenge.IV = append([]byte(nil), attr.Value[2:]...)
		case akaAttrEncryptedData:
			challenge.EncryptedData = append([]byte(nil), attr.Value[2:]...)
		}
	}
	if len(challenge.RAND) != 16 || len(challenge.AUTN) != 16 {
		return AKAChallenge{}, fmt.Errorf("parsing aka challenge: missing rand or autn")
	}
	return challenge, nil
}

func BuildAKAResponse(id byte, res, autKey []byte) ([]byte, error) {
	if len(res) == 0 {
		return nil, fmt.Errorf("building aka response: res is empty")
	}
	value := make([]byte, 2+len(res))
	binary.BigEndian.PutUint16(value[:2], uint16(len(res)*8))
	copy(value[2:], res)
	attrs := []AKAAttribute{{Type: akaAttrRES, Value: value}}
	macIndex := -1
	if len(autKey) != 0 {
		attrs = append(attrs, AKAAttribute{Type: akaAttrMAC, Value: append([]byte{0x00, 0x00}, make([]byte, 16)...)})
		macIndex = len(attrs) - 1
	}
	message := AKAMessage{Code: eapCodeResponse, Identifier: id, Subtype: akaSubtypeChallenge, Attributes: attrs}
	packet, err := message.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if macIndex < 0 {
		return packet, nil
	}
	mac := hmac.New(sha1.New, autKey)
	_, _ = mac.Write(packet)
	attrs[macIndex].Value = append([]byte{0x00, 0x00}, mac.Sum(nil)[:16]...)
	message.Attributes = attrs
	return message.MarshalBinary()
}

func BuildAKAIdentityResponse(id byte, identity string) ([]byte, error) {
	if identity == "" {
		return nil, fmt.Errorf("building aka identity response: identity is empty")
	}
	return buildAKAMessage(eapCodeResponse, id, akaSubtypeIdentity, []AKAAttribute{buildAKAStringAttribute(akaAttrIdentity, identity)}, nil, nil)
}

func BuildAKAAuthenticationReject(id byte) ([]byte, error) {
	return buildAKAMessage(eapCodeResponse, id, akaSubtypeAuthenticationReject, nil, nil, nil)
}

func BuildAKASynchronizationFailure(id byte, auts []byte) ([]byte, error) {
	if len(auts) != 14 {
		return nil, fmt.Errorf("building aka synchronization failure: auts length %d, want 14", len(auts))
	}
	return buildAKAMessage(eapCodeResponse, id, akaSubtypeSynchronizationFailure, []AKAAttribute{{Type: akaAttrAUTS, Value: append([]byte(nil), auts...)}}, nil, nil)
}
