package ike

import (
	"encoding"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	payloadTypeNone      byte = 0
	payloadTypeProposal  byte = 2
	payloadTypeTransform byte = 3

	payloadTypeSA        byte = 33
	payloadTypeKE        byte = 34
	payloadTypeIDi       byte = 35
	payloadTypeIDr       byte = 36
	payloadTypeAUTH      byte = 39
	payloadTypeNonce     byte = 40
	payloadTypeNotify    byte = 41
	payloadTypeDelete    byte = 42
	payloadTypeTSi       byte = 44
	payloadTypeTSr       byte = 45
	payloadTypeEncrypted byte = 46
	payloadTypeCP        byte = 47
	payloadTypeEAP       byte = 48
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
	notifyTypeNATDetectionSourceIP  uint16 = 16388
	notifyTypeNATDetectionDestIP    uint16 = 16389
	notifyTypeEAPOnlyAuthentication uint16 = 16417
	notifyTypeDeviceIdentity        uint16 = 41101
)

const (
	deviceIdentityIMEI   byte = 0x01
	deviceIdentityIMEISV byte = 0x02
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

const (
	trafficSelectorIPv4Range byte = 7
	trafficSelectorIPv6Range byte = 8
)

const (
	attributeFormatTLV byte = 0
	attributeFormatTV  byte = 1
)

type Payload interface {
	encoding.BinaryMarshaler
	Type() byte
}

type Attribute struct {
	Format  byte
	Type    uint16
	Value   []byte
	Value16 uint16
}

func NewTLVAttribute(typeID uint16, value []byte) Attribute {
	return Attribute{Format: attributeFormatTLV, Type: typeID, Value: append([]byte(nil), value...)}
}

func NewTVAttribute(typeID, value uint16) Attribute {
	return Attribute{Format: attributeFormatTV, Type: typeID, Value16: value}
}

func (a Attribute) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:2], uint16(a.Format)<<15|a.Type)
	if a.Format == attributeFormatTV {
		binary.BigEndian.PutUint16(buf[2:4], a.Value16)
		return buf, nil
	}
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(a.Value)))
	return append(buf, a.Value...), nil
}

func (a *Attribute) UnmarshalBinary(data []byte) error {
	attr, size, err := decodeAttribute(data)
	if err != nil {
		return err
	}
	if size != len(data) {
		return fmt.Errorf("parsing attribute: %d trailing bytes", len(data)-size)
	}
	*a = attr
	return nil
}

func (a Attribute) Uint16() (uint16, bool) {
	if a.Format != attributeFormatTV {
		return 0, false
	}
	return a.Value16, true
}

func decodeAttribute(data []byte) (Attribute, int, error) {
	if len(data) < 4 {
		return Attribute{}, 0, fmt.Errorf("parsing attribute: truncated body")
	}
	rawType := binary.BigEndian.Uint16(data[0:2])
	attr := Attribute{Format: byte(rawType >> 15), Type: rawType & 0x7fff}
	if attr.Format == attributeFormatTV {
		attr.Value16 = binary.BigEndian.Uint16(data[2:4])
		return attr, 4, nil
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if len(data) < 4+length {
		return Attribute{}, 0, fmt.Errorf("parsing attribute: invalid length %d", length)
	}
	attr.Value = append([]byte(nil), data[4:4+length]...)
	return attr, 4 + length, nil
}

func decodeAttributes(data []byte) ([]Attribute, error) {
	attrs := make([]Attribute, 0)
	for len(data) > 0 {
		attr, size, err := decodeAttribute(data)
		if err != nil {
			return nil, fmt.Errorf("parsing attributes: %w", err)
		}
		attrs = append(attrs, attr)
		data = data[size:]
	}
	return attrs, nil
}

type Transform struct {
	TransformType byte
	ID            uint16
	Attributes    []Attribute
}

func (t Transform) MarshalBinary() ([]byte, error) {
	body := make([]byte, 4)
	body[0] = t.TransformType
	binary.BigEndian.PutUint16(body[2:4], t.ID)
	for _, attr := range t.Attributes {
		encoded, err := attr.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("marshalling transform attribute: %w", err)
		}
		body = append(body, encoded...)
	}
	return body, nil
}

func (t Transform) marshalBinary(next byte) ([]byte, error) {
	body, err := t.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return marshalPayloadBlock(next, body), nil
}

func (t *Transform) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("parsing transform: truncated body")
	}
	attrs, err := decodeAttributes(data[4:])
	if err != nil {
		return err
	}
	*t = Transform{TransformType: data[0], ID: binary.BigEndian.Uint16(data[2:4]), Attributes: attrs}
	return nil
}

func decodeTransform(next byte, data []byte) (Transform, error) {
	_ = next
	var transform Transform
	if err := transform.UnmarshalBinary(data); err != nil {
		return Transform{}, err
	}
	return transform, nil
}

type Proposal struct {
	Number     byte
	ProtocolID byte
	SPI        []byte
	Transforms []Transform
}

func (p Proposal) MarshalBinary() ([]byte, error) {
	body := []byte{p.Number, p.ProtocolID, byte(len(p.SPI)), byte(len(p.Transforms))}
	body = append(body, p.SPI...)
	for i, transform := range p.Transforms {
		nextType := payloadTypeNone
		if i+1 < len(p.Transforms) {
			nextType = payloadTypeTransform
		}
		encoded, err := transform.marshalBinary(nextType)
		if err != nil {
			return nil, fmt.Errorf("marshalling transform: %w", err)
		}
		body = append(body, encoded...)
	}
	return body, nil
}

func (p Proposal) marshalBinary(next byte) ([]byte, error) {
	body, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return marshalPayloadBlock(next, body), nil
}

func (p *Proposal) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("parsing proposal: truncated body")
	}
	proposal := Proposal{
		Number:     data[0],
		ProtocolID: data[1],
	}
	if len(data) < 4+int(data[2]) {
		return fmt.Errorf("parsing proposal: truncated spi")
	}
	proposal.SPI = append([]byte(nil), data[4:4+int(data[2])]...)
	remaining := data[4+int(data[2]):]
	transformType := payloadTypeTransform
	for i := 0; i < int(data[3]); i++ {
		if len(remaining) < 4 {
			return fmt.Errorf("parsing proposal: truncated transform")
		}
		next := remaining[0]
		length := int(binary.BigEndian.Uint16(remaining[2:4]))
		if length < 4 {
			return fmt.Errorf("parsing proposal: invalid transform length %d", length)
		}
		if len(remaining) < length {
			return fmt.Errorf("parsing proposal: invalid transform length %d", length)
		}
		if transformType != payloadTypeTransform {
			return fmt.Errorf("parsing proposal: unexpected transform tag %d", transformType)
		}
		transform, err := decodeTransform(next, remaining[4:length])
		if err != nil {
			return err
		}
		proposal.Transforms = append(proposal.Transforms, transform)
		remaining = remaining[length:]
		if next == payloadTypeNone {
			break
		}
		transformType = next
	}
	if len(proposal.Transforms) != int(data[3]) {
		return fmt.Errorf("parsing proposal: transform count mismatch want=%d got=%d", int(data[3]), len(proposal.Transforms))
	}
	if len(remaining) != 0 {
		return fmt.Errorf("parsing proposal: %d trailing bytes", len(remaining))
	}
	*p = proposal
	return nil
}

type SecurityAssociationPayload struct {
	Proposals []Proposal
}

func (p *SecurityAssociationPayload) Type() byte { return payloadTypeSA }

func (p *SecurityAssociationPayload) MarshalBinary() ([]byte, error) {
	body := make([]byte, 0)
	for i, proposal := range p.Proposals {
		proposal.Number = byte(i + 1)
		nextType := payloadTypeNone
		if i+1 < len(p.Proposals) {
			nextType = payloadTypeProposal
		}
		encoded, err := proposal.marshalBinary(nextType)
		if err != nil {
			return nil, fmt.Errorf("marshalling proposal: %w", err)
		}
		body = append(body, encoded...)
	}
	return body, nil
}

func (p *SecurityAssociationPayload) UnmarshalBinary(data []byte) error {
	payload := SecurityAssociationPayload{Proposals: make([]Proposal, 0)}
	remaining := data
	proposalType := payloadTypeProposal
	for len(remaining) > 0 {
		if len(remaining) < 4 {
			return fmt.Errorf("parsing security association: truncated proposal")
		}
		next := remaining[0]
		length := int(binary.BigEndian.Uint16(remaining[2:4]))
		if length < 4 {
			return fmt.Errorf("parsing security association: invalid proposal length %d", length)
		}
		if len(remaining) < length {
			return fmt.Errorf("parsing security association: invalid proposal length %d", length)
		}
		if proposalType != payloadTypeProposal {
			return fmt.Errorf("parsing security association: unexpected proposal tag %d", proposalType)
		}
		var proposal Proposal
		if err := proposal.UnmarshalBinary(remaining[4:length]); err != nil {
			return err
		}
		payload.Proposals = append(payload.Proposals, proposal)
		remaining = remaining[length:]
		if next == payloadTypeNone {
			break
		}
		proposalType = next
	}
	if len(remaining) != 0 {
		return fmt.Errorf("parsing security association: %d trailing bytes", len(remaining))
	}
	*p = payload
	return nil
}

func decodeSecurityAssociationPayload(data []byte) (*SecurityAssociationPayload, error) {
	payload := &SecurityAssociationPayload{}
	if err := payload.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return payload, nil
}

type KeyExchangePayload struct {
	DHGroup uint16
	Data    []byte
}

func (p *KeyExchangePayload) Type() byte { return payloadTypeKE }

func (p *KeyExchangePayload) MarshalBinary() ([]byte, error) {
	body := make([]byte, 4)
	binary.BigEndian.PutUint16(body[0:2], p.DHGroup)
	body = append(body, p.Data...)
	return body, nil
}

func (p *KeyExchangePayload) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("parsing key exchange: truncated body")
	}
	p.DHGroup = binary.BigEndian.Uint16(data[0:2])
	p.Data = append([]byte(nil), data[4:]...)
	return nil
}

func decodeKeyExchangePayload(data []byte) (*KeyExchangePayload, error) {
	payload := &KeyExchangePayload{}
	if err := payload.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return payload, nil
}

type NoncePayload struct {
	Data []byte
}

func (p *NoncePayload) Type() byte { return payloadTypeNonce }

func (p *NoncePayload) MarshalBinary() ([]byte, error) {
	return append([]byte(nil), p.Data...), nil
}

func (p *NoncePayload) UnmarshalBinary(data []byte) error {
	p.Data = append([]byte(nil), data...)
	return nil
}

func decodeNoncePayload(data []byte) (*NoncePayload, error) {
	payload := &NoncePayload{}
	if err := payload.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return payload, nil
}

type NotifyPayload struct {
	ProtocolID byte
	NotifyType uint16
	SPI        []byte
	Data       []byte
}

func (p *NotifyPayload) Type() byte { return payloadTypeNotify }

func (p *NotifyPayload) MarshalBinary() ([]byte, error) {
	body := []byte{p.ProtocolID, byte(len(p.SPI)), 0x00, 0x00}
	binary.BigEndian.PutUint16(body[2:4], p.NotifyType)
	body = append(body, p.SPI...)
	body = append(body, p.Data...)
	return body, nil
}

func (p *NotifyPayload) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("parsing notify: truncated body")
	}
	spiLen := int(data[1])
	if len(data) < 4+spiLen {
		return fmt.Errorf("parsing notify: invalid spi length %d", spiLen)
	}
	p.ProtocolID = data[0]
	p.NotifyType = binary.BigEndian.Uint16(data[2:4])
	p.SPI = append([]byte(nil), data[4:4+spiLen]...)
	p.Data = append([]byte(nil), data[4+spiLen:]...)
	return nil
}

func decodeNotifyPayload(data []byte) (*NotifyPayload, error) {
	payload := &NotifyPayload{}
	if err := payload.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return payload, nil
}

type DeletePayload struct {
	ProtocolID byte
	SPIs       [][]byte
}

func (p *DeletePayload) Type() byte { return payloadTypeDelete }

func (p *DeletePayload) MarshalBinary() ([]byte, error) {
	spiSize := 0
	if len(p.SPIs) > 0 {
		spiSize = len(p.SPIs[0])
		for _, spi := range p.SPIs[1:] {
			if len(spi) != spiSize {
				return nil, fmt.Errorf("marshalling delete payload: spi length mismatch")
			}
		}
	}
	if spiSize > 0xff {
		return nil, fmt.Errorf("marshalling delete payload: spi size %d exceeds 255", spiSize)
	}
	body := []byte{p.ProtocolID, byte(spiSize), 0x00, 0x00}
	binary.BigEndian.PutUint16(body[2:4], uint16(len(p.SPIs)))
	for _, spi := range p.SPIs {
		body = append(body, spi...)
	}
	return body, nil
}

func (p *DeletePayload) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("parsing delete payload: truncated body")
	}
	spiSize := int(data[1])
	count := int(binary.BigEndian.Uint16(data[2:4]))
	if spiSize == 0 && count != 0 {
		return fmt.Errorf("parsing delete payload: invalid spi size %d for %d spis", spiSize, count)
	}
	wantLen := 4 + spiSize*count
	if len(data) != wantLen {
		return fmt.Errorf("parsing delete payload: invalid payload length %d", len(data))
	}
	payload := DeletePayload{ProtocolID: data[0], SPIs: make([][]byte, 0, count)}
	for offset := 4; offset < len(data); offset += spiSize {
		payload.SPIs = append(payload.SPIs, append([]byte(nil), data[offset:offset+spiSize]...))
	}
	*p = payload
	return nil
}

func decodeDeletePayload(data []byte) (*DeletePayload, error) {
	payload := &DeletePayload{}
	if err := payload.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return payload, nil
}

type IDPayload struct {
	Tag    byte
	IDType byte
	Data   []byte
}

func (p *IDPayload) Type() byte { return p.Tag }

func (p *IDPayload) MarshalBinary() ([]byte, error) {
	body := []byte{p.IDType, 0x00, 0x00, 0x00}
	body = append(body, p.Data...)
	return body, nil
}

func (p *IDPayload) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("parsing identification: truncated body")
	}
	p.IDType = data[0]
	p.Data = append([]byte(nil), data[4:]...)
	return nil
}

func (p *IDPayload) RawData() []byte {
	body, _ := p.MarshalBinary()
	return body
}

func decodeIDPayload(tag byte, data []byte) (*IDPayload, error) {
	payload := &IDPayload{Tag: tag}
	if err := payload.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return payload, nil
}

type AuthPayload struct {
	Method byte
	Data   []byte
}

func (p *AuthPayload) Type() byte { return payloadTypeAUTH }

func (p *AuthPayload) MarshalBinary() ([]byte, error) {
	body := []byte{p.Method, 0x00, 0x00, 0x00}
	body = append(body, p.Data...)
	return body, nil
}

func (p *AuthPayload) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("parsing authentication: truncated body")
	}
	p.Method = data[0]
	p.Data = append([]byte(nil), data[4:]...)
	return nil
}

func decodeAuthPayload(data []byte) (*AuthPayload, error) {
	payload := &AuthPayload{}
	if err := payload.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return payload, nil
}

type ConfigPayload struct {
	ConfigType byte
	Attributes []Attribute
}

func (p *ConfigPayload) Type() byte { return payloadTypeCP }

func (p *ConfigPayload) MarshalBinary() ([]byte, error) {
	body := []byte{p.ConfigType, 0x00, 0x00, 0x00}
	for _, attr := range p.Attributes {
		encoded, err := attr.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("marshalling config attribute: %w", err)
		}
		body = append(body, encoded...)
	}
	return body, nil
}

func (p *ConfigPayload) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("parsing configuration: truncated body")
	}
	attrs, err := decodeAttributes(data[4:])
	if err != nil {
		return err
	}
	p.ConfigType = data[0]
	p.Attributes = attrs
	return nil
}

func decodeConfigPayload(data []byte) (*ConfigPayload, error) {
	payload := &ConfigPayload{}
	if err := payload.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return payload, nil
}

type TrafficSelector struct {
	Type       byte
	ProtocolID byte
	Data       []byte
}

func (s TrafficSelector) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 4)
	buf[0] = s.Type
	buf[1] = s.ProtocolID
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(s.Data)+4))
	return append(buf, s.Data...), nil
}

func (s *TrafficSelector) UnmarshalBinary(data []byte) error {
	selector, size, err := decodeTrafficSelector(data)
	if err != nil {
		return err
	}
	if size != len(data) {
		return fmt.Errorf("parsing traffic selector: %d trailing bytes", len(data)-size)
	}
	*s = selector
	return nil
}

func decodeTrafficSelector(data []byte) (TrafficSelector, int, error) {
	if len(data) < 4 {
		return TrafficSelector{}, 0, fmt.Errorf("parsing traffic selector: truncated selector")
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length < 4 {
		return TrafficSelector{}, 0, fmt.Errorf("parsing traffic selector: invalid length %d", length)
	}
	if len(data) < length {
		return TrafficSelector{}, 0, fmt.Errorf("parsing traffic selector: invalid length %d", length)
	}
	selector := TrafficSelector{Type: data[0], ProtocolID: data[1], Data: append([]byte(nil), data[4:length]...)}
	return selector, length, nil
}

func decodeTrafficSelectors(data []byte) ([]TrafficSelector, error) {
	selectors := make([]TrafficSelector, 0)
	for len(data) > 0 {
		selector, size, err := decodeTrafficSelector(data)
		if err != nil {
			return nil, err
		}
		selectors = append(selectors, selector)
		data = data[size:]
	}
	return selectors, nil
}

type TrafficSelectorPayload struct {
	Tag       byte
	Selectors []TrafficSelector
}

func (p *TrafficSelectorPayload) Type() byte { return p.Tag }

func (p *TrafficSelectorPayload) MarshalBinary() ([]byte, error) {
	body := []byte{byte(len(p.Selectors)), 0x00, 0x00, 0x00}
	for _, selector := range p.Selectors {
		encoded, err := selector.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("marshalling traffic selector: %w", err)
		}
		body = append(body, encoded...)
	}
	return body, nil
}

func (p *TrafficSelectorPayload) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("parsing traffic selectors: truncated body")
	}
	count := int(data[0])
	selectors, err := decodeTrafficSelectors(data[4:])
	if err != nil {
		return err
	}
	if count != len(selectors) {
		return fmt.Errorf("parsing traffic selectors: selector count mismatch want=%d got=%d", count, len(selectors))
	}
	p.Selectors = selectors
	return nil
}

func decodeTrafficSelectorPayload(tag byte, data []byte) (*TrafficSelectorPayload, error) {
	payload := &TrafficSelectorPayload{Tag: tag}
	if err := payload.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return payload, nil
}

type EAPPayload struct {
	Data []byte
}

func (p *EAPPayload) Type() byte { return payloadTypeEAP }

func (p *EAPPayload) MarshalBinary() ([]byte, error) {
	return append([]byte(nil), p.Data...), nil
}

func (p *EAPPayload) UnmarshalBinary(data []byte) error {
	p.Data = append([]byte(nil), data...)
	return nil
}

func decodeEAPPayload(data []byte) (*EAPPayload, error) {
	payload := &EAPPayload{}
	if err := payload.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return payload, nil
}

type EncryptedPayload struct {
	NextPayload byte
	Raw         []byte
}

func (p *EncryptedPayload) Type() byte { return payloadTypeEncrypted }

func (p *EncryptedPayload) MarshalBinary() ([]byte, error) {
	return append([]byte(nil), p.Raw...), nil
}

func (p *EncryptedPayload) UnmarshalBinary(data []byte) error {
	p.Raw = append([]byte(nil), data...)
	return nil
}

func decodeEncryptedPayload(next byte, data []byte) (*EncryptedPayload, error) {
	payload := &EncryptedPayload{NextPayload: next}
	if err := payload.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return payload, nil
}

func MarshalPayloadChain(payloads []Payload) (byte, []byte, error) {
	if len(payloads) == 0 {
		return payloadTypeNone, nil, nil
	}
	first := payloads[0].Type()
	body := make([]byte, 0)
	for i, payload := range payloads {
		next := payloadTypeNone
		if encrypted, ok := payload.(*EncryptedPayload); ok {
			next = encrypted.NextPayload
		} else if i+1 < len(payloads) {
			next = payloads[i+1].Type()
		}
		encoded, err := marshalSinglePayload(payload, next)
		if err != nil {
			return 0, nil, err
		}
		body = append(body, encoded...)
	}
	return first, body, nil
}

func marshalSinglePayload(payload Payload, next byte) ([]byte, error) {
	body, err := payload.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return marshalPayloadBlock(next, body), nil
}

func marshalPayloadBlock(next byte, body []byte) []byte {
	buf := make([]byte, 4)
	buf[0] = next
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(body)+4))
	buf = append(buf, body...)
	return buf
}

func DecodePayloadChain(firstType byte, data []byte) ([]Payload, error) {
	payloads := make([]Payload, 0)
	nextType := firstType
	remaining := data
	for nextType != payloadTypeNone {
		if len(remaining) < 4 {
			return nil, fmt.Errorf("parsing payload chain: truncated payload")
		}
		next := remaining[0]
		critical := remaining[1]&0x80 != 0
		length := int(binary.BigEndian.Uint16(remaining[2:4]))
		if length < 4 {
			return nil, fmt.Errorf("parsing payload chain: invalid payload length %d", length)
		}
		if len(remaining) < length {
			return nil, fmt.Errorf("parsing payload chain: invalid payload length %d", length)
		}
		body := remaining[4:length]
		payload, err := decodePayload(nextType, next, body, critical)
		if err != nil {
			return nil, err
		}
		if payload != nil {
			payloads = append(payloads, payload)
		}
		remaining = remaining[length:]
		if nextType == payloadTypeEncrypted {
			break
		}
		nextType = next
	}
	if len(remaining) != 0 {
		return nil, fmt.Errorf("parsing payload chain: %d trailing bytes", len(remaining))
	}
	return payloads, nil
}

func decodePayload(payloadType, next byte, body []byte, critical bool) (Payload, error) {
	switch payloadType {
	case payloadTypeSA:
		return decodeSecurityAssociationPayload(body)
	case payloadTypeKE:
		return decodeKeyExchangePayload(body)
	case payloadTypeIDi, payloadTypeIDr:
		return decodeIDPayload(payloadType, body)
	case payloadTypeAUTH:
		return decodeAuthPayload(body)
	case payloadTypeNonce:
		return decodeNoncePayload(body)
	case payloadTypeNotify:
		return decodeNotifyPayload(body)
	case payloadTypeDelete:
		return decodeDeletePayload(body)
	case payloadTypeTSi, payloadTypeTSr:
		return decodeTrafficSelectorPayload(payloadType, body)
	case payloadTypeEncrypted:
		return decodeEncryptedPayload(next, body)
	case payloadTypeCP:
		return decodeConfigPayload(body)
	case payloadTypeEAP:
		return decodeEAPPayload(body)
	default:
		if !critical {
			return nil, nil
		}
		return nil, fmt.Errorf("parsing payload chain: unsupported critical payload type %d", payloadType)
	}
}

func FindNoncePayload(payloads []Payload) *NoncePayload {
	for _, payload := range payloads {
		if nonce, ok := payload.(*NoncePayload); ok {
			return nonce
		}
	}
	return nil
}

func FindSAPayload(payloads []Payload) *SecurityAssociationPayload {
	for _, payload := range payloads {
		if sa, ok := payload.(*SecurityAssociationPayload); ok {
			return sa
		}
	}
	return nil
}

func FindKEPayload(payloads []Payload, group uint16) *KeyExchangePayload {
	for _, payload := range payloads {
		ke, ok := payload.(*KeyExchangePayload)
		if !ok {
			continue
		}
		if group == 0 || ke.DHGroup == group {
			return ke
		}
	}
	return nil
}

func FindConfigPayload(payloads []Payload) *ConfigPayload {
	for _, payload := range payloads {
		if config, ok := payload.(*ConfigPayload); ok {
			return config
		}
	}
	return nil
}

func FindEAPPayload(payloads []Payload) *EAPPayload {
	for _, payload := range payloads {
		if eap, ok := payload.(*EAPPayload); ok {
			return eap
		}
	}
	return nil
}

func FindIDPayload(payloads []Payload, tag byte) *IDPayload {
	for _, payload := range payloads {
		idPayload, ok := payload.(*IDPayload)
		if ok && idPayload.Tag == tag {
			return idPayload
		}
	}
	return nil
}

func FindNotifyPayload(payloads []Payload, notifyType uint16) *NotifyPayload {
	for _, payload := range payloads {
		notifyPayload, ok := payload.(*NotifyPayload)
		if ok && notifyPayload.NotifyType == notifyType {
			return notifyPayload
		}
	}
	return nil
}

func FindDeletePayload(payloads []Payload) *DeletePayload {
	for _, payload := range payloads {
		deletePayload, ok := payload.(*DeletePayload)
		if ok {
			return deletePayload
		}
	}
	return nil
}

func DecodeDeviceIdentity(data []byte) (byte, []byte, error) {
	if len(data) < 3 {
		return 0, nil, fmt.Errorf("parsing device identity: data too short")
	}
	length := int(binary.BigEndian.Uint16(data[:2]))
	if length < 1 {
		return 0, nil, fmt.Errorf("parsing device identity: invalid length %d", length)
	}
	if len(data) != 2+length {
		return 0, nil, fmt.Errorf("parsing device identity: data length %d does not match %d", len(data), 2+length)
	}
	identityType := data[2]
	switch identityType {
	case deviceIdentityIMEI, deviceIdentityIMEISV:
	default:
		return 0, nil, fmt.Errorf("parsing device identity: unsupported type %d", identityType)
	}
	return identityType, append([]byte(nil), data[3:]...), nil
}

func EncodeDeviceIdentityForType(identity string, requestedType byte) ([]byte, error) {
	if identity == "" {
		return nil, fmt.Errorf("encoding device identity: identity is empty")
	}
	digits := []byte(identity)
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return nil, fmt.Errorf("encoding device identity: invalid digit %q", digit)
		}
	}
	identityType, err := deviceIdentityType(len(digits), requestedType)
	if err != nil {
		return nil, err
	}
	if len(digits)%2 != 0 {
		digits = append(digits, 'f')
	}
	encoded := make([]byte, len(digits)/2)
	for i := 0; i < len(digits); i += 2 {
		high := digits[i]
		low := digits[i+1]
		encoded[i/2] = bcdSwapByte(high, low)
	}
	data := make([]byte, 3+len(encoded))
	binary.BigEndian.PutUint16(data[0:2], uint16(len(encoded)+1))
	data[2] = identityType
	copy(data[3:], encoded)
	return data, nil
}

func deviceIdentityType(length int, requestedType byte) (byte, error) {
	hasIMEI := length == 15
	hasIMEISV := length == 16
	if !hasIMEI && !hasIMEISV {
		return 0, fmt.Errorf("encoding device identity: unsupported length %d", length)
	}
	switch requestedType {
	case 0:
		if hasIMEISV {
			return deviceIdentityIMEISV, nil
		}
		return deviceIdentityIMEI, nil
	case deviceIdentityIMEISV:
		if hasIMEISV {
			return deviceIdentityIMEISV, nil
		}
		if hasIMEI {
			return deviceIdentityIMEI, nil
		}
	case deviceIdentityIMEI:
		if hasIMEI {
			return deviceIdentityIMEI, nil
		}
		if hasIMEISV {
			return deviceIdentityIMEISV, nil
		}
	default:
		return 0, fmt.Errorf("encoding device identity: unsupported requested type %d", requestedType)
	}
	return 0, fmt.Errorf("encoding device identity: unsupported length %d", length)
}

func bcdSwapByte(high, low byte) byte {
	return toBCD(low)<<4 | toBCD(high)
}

func toBCD(digit byte) byte {
	if digit == 'f' || digit == 'F' {
		return 0x0f
	}
	return digit - '0'
}

func TrafficSelectorsAny() []TrafficSelector {
	return []TrafficSelector{
		{Type: trafficSelectorIPv4Range, ProtocolID: 0, Data: append([]byte{0x00, 0x00, 0xff, 0xff}, append(net.IPv4zero.To4(), []byte{0xff, 0xff, 0xff, 0xff}...)...)},
		{Type: trafficSelectorIPv6Range, ProtocolID: 0, Data: append([]byte{0x00, 0x00, 0xff, 0xff}, append(make([]byte, net.IPv6len), bytesRepeat(0xff, net.IPv6len)...)...)},
	}
}

func bytesRepeat(value byte, count int) []byte {
	buf := make([]byte, count)
	for i := range buf {
		buf[i] = value
	}
	return buf
}
