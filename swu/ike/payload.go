package ike

import (
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
)

const (
	payloadHeaderSize        = 4
	payloadHeaderCriticalBit = 0x80

	payloadTypeNone      byte = 0
	payloadTypeProposal  byte = 2
	payloadTypeTransform byte = 3

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
	deviceIdentityAuto   byte = 0x00
	deviceIdentityIMEI   byte = 0x01
	deviceIdentityIMEISV byte = 0x02

	deviceIdentityRequestLen     = 1
	deviceIdentityLengthFieldLen = 2
	deviceIdentityTypeLen        = 1
	deviceIdentityValueLen       = 8
)

const (
	trafficSelectorIPv4Range byte = 7
	trafficSelectorIPv6Range byte = 8

	trafficSelectorHeaderLen = 4
	trafficSelectorPortsLen  = 4
)

const (
	ipProtocolAny  byte = 0
	ipProtocolICMP byte = 1
	ipProtocolTCP  byte = 6
	ipProtocolUDP  byte = 17
)

const (
	protocolIDIKE byte = 1
	protocolIDAH  byte = 2
	protocolIDESP byte = 3

	deleteProtocolIDIKE = protocolIDIKE
	deleteProtocolIDAH  = protocolIDAH
	deleteProtocolIDESP = protocolIDESP
)

const (
	proposalSPISizeNone  = 0
	proposalSPISizeIPsec = 4
	proposalSPISizeIKE   = 8
)

const (
	notifySPISizeNone  = 0
	notifySPISizeIPsec = 4
)

const (
	notifyTypeInvalidSelectors uint16 = 39
	notifyTypeChildSANotFound  uint16 = 44
	notifyTypeRekeySA          uint16 = 16393
)

const (
	attributeFormatTLV byte = 0
	attributeFormatTV  byte = 1

	transformAttrKeyLength uint16 = 14
)

const (
	configTypeRequest byte = 1
	configTypeReply   byte = 2
	configTypeSet     byte = 3
	configTypeAck     byte = 4
)

const (
	configAttrInternalIPv4Address uint16 = 1
	configAttrInternalIPv4Netmask uint16 = 2
	configAttrInternalIPv4DNS     uint16 = 3
	configAttrInternalIPv4NBNS    uint16 = 4
	configAttrInternalIPv4DHCP    uint16 = 6
	configAttrApplicationVersion  uint16 = 7
	configAttrInternalIPv6Address uint16 = 8
	configAttrInternalIPv6DNS     uint16 = 10
	configAttrInternalIPv6DHCP    uint16 = 12
	configAttrInternalIPv4Subnet  uint16 = 13
	configAttrSupportedAttributes uint16 = 14
	configAttrInternalIPv6Subnet  uint16 = 15
	configAttrIPv4PCSCF           uint16 = 20
	configAttrIPv6PCSCF           uint16 = 21
	configAttrLivenessTimeout     uint16 = 24
)

const (
	dhGroup1024MODP uint16 = 2
	dhGroup2048MODP uint16 = 14
)

const (
	keyExchangeBodyHeaderLen      = 4
	keyExchange1024MODPDataLength = 128
	keyExchange2048MODPDataLength = 256
)

type Payload interface {
	encoding.BinaryMarshaler
	Type() byte
}

var (
	_ encoding.BinaryAppender    = Attribute{}
	_ encoding.BinaryAppender    = Transform{}
	_ encoding.BinaryAppender    = Proposal{}
	_ encoding.BinaryAppender    = (*SecurityAssociationPayload)(nil)
	_ encoding.BinaryAppender    = (*KeyExchangePayload)(nil)
	_ encoding.BinaryAppender    = (*NoncePayload)(nil)
	_ encoding.BinaryAppender    = (*NotifyPayload)(nil)
	_ encoding.BinaryAppender    = (*DeletePayload)(nil)
	_ encoding.BinaryAppender    = (*IDPayload)(nil)
	_ encoding.BinaryAppender    = (*AuthPayload)(nil)
	_ encoding.BinaryAppender    = (*ConfigPayload)(nil)
	_ encoding.BinaryAppender    = TrafficSelector{}
	_ encoding.BinaryAppender    = (*TrafficSelectorPayload)(nil)
	_ encoding.BinaryAppender    = (*EAPPayload)(nil)
	_ encoding.BinaryAppender    = (*EncryptedPayload)(nil)
	_ encoding.BinaryAppender    = (*EncryptedFragmentPayload)(nil)
	_ encoding.BinaryAppender    = DeviceIdentity{}
	_ encoding.BinaryMarshaler   = DeviceIdentity{}
	_ encoding.BinaryUnmarshaler = (*DeviceIdentity)(nil)
)

type UnsupportedCriticalPayloadError struct {
	PayloadType byte
}

func (e UnsupportedCriticalPayloadError) Error() string {
	return fmt.Sprintf("parsing payload chain: unsupported critical payload type %d", e.PayloadType)
}

type InvalidSyntaxError struct {
	Err error
}

func (e InvalidSyntaxError) Error() string {
	if e.Err == nil {
		return "parsing payload chain: invalid syntax"
	}
	return "parsing payload chain: invalid syntax: " + e.Err.Error()
}

func (e InvalidSyntaxError) Unwrap() error {
	return e.Err
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
	return a.AppendBinary(nil)
}

func (a Attribute) AppendBinary(dst []byte) ([]byte, error) {
	start := len(dst)
	dst = append(dst, make([]byte, 4)...)
	binary.BigEndian.PutUint16(dst[start:start+2], uint16(a.Format)<<15|a.Type)
	if a.Format == attributeFormatTV {
		binary.BigEndian.PutUint16(dst[start+2:start+4], a.Value16)
		return dst, nil
	}
	binary.BigEndian.PutUint16(dst[start+2:start+4], uint16(len(a.Value)))
	return append(dst, a.Value...), nil
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
		return Attribute{}, 0, errors.New("parsing attribute: truncated body")
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
	return t.AppendBinary(nil)
}

func (t Transform) AppendBinary(dst []byte) ([]byte, error) {
	if err := validateTransformAttributes(t.Attributes); err != nil {
		return nil, err
	}
	start := len(dst)
	dst = append(dst, make([]byte, 4)...)
	dst[start] = t.TransformType
	binary.BigEndian.PutUint16(dst[start+2:start+4], t.ID)
	for _, attr := range t.Attributes {
		var err error
		dst, err = attr.AppendBinary(dst)
		if err != nil {
			return nil, fmt.Errorf("marshalling transform attribute: %w", err)
		}
	}
	return dst, nil
}

func (t Transform) marshalBinary(next byte) ([]byte, error) {
	return t.appendBinary(nil, next)
}

func (t Transform) appendBinary(dst []byte, next byte) ([]byte, error) {
	start := len(dst)
	dst = append(dst, make([]byte, payloadHeaderSize)...)
	var err error
	dst, err = t.AppendBinary(dst)
	if err != nil {
		return nil, err
	}
	if err := setPayloadHeader(dst[start:start+payloadHeaderSize], next, len(dst)-start); err != nil {
		return nil, err
	}
	return dst, nil
}

func (t *Transform) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("parsing transform: truncated body")
	}
	attrs, err := decodeAttributes(data[4:])
	if err != nil {
		return err
	}
	if err := validateTransformAttributes(attrs); err != nil {
		return err
	}
	*t = Transform{TransformType: data[0], ID: binary.BigEndian.Uint16(data[2:4]), Attributes: attrs}
	return nil
}

func validateTransformAttributes(attrs []Attribute) error {
	seen := make(map[uint16]struct{}, len(attrs))
	for _, attr := range attrs {
		if _, ok := seen[attr.Type]; ok {
			return fmt.Errorf("parsing transform: duplicate attribute %d", attr.Type)
		}
		seen[attr.Type] = struct{}{}
		if attr.Type == transformAttrKeyLength && attr.Format != attributeFormatTV {
			return errors.New("parsing transform: key length attribute must use TV format")
		}
	}
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
	return p.AppendBinary(nil)
}

func (p Proposal) AppendBinary(dst []byte) ([]byte, error) {
	if err := validateProposalShape(len(p.SPI), len(p.Transforms)); err != nil {
		return nil, err
	}
	dst = append(dst, p.Number, p.ProtocolID, byte(len(p.SPI)), byte(len(p.Transforms)))
	dst = append(dst, p.SPI...)
	for i, transform := range p.Transforms {
		nextType := payloadTypeNone
		if i+1 < len(p.Transforms) {
			nextType = payloadTypeTransform
		}
		var err error
		dst, err = transform.appendBinary(dst, nextType)
		if err != nil {
			return nil, fmt.Errorf("marshalling transform: %w", err)
		}
	}
	return dst, nil
}

func (p Proposal) marshalBinary(next byte) ([]byte, error) {
	return p.appendBinary(nil, next)
}

func (p Proposal) appendBinary(dst []byte, next byte) ([]byte, error) {
	start := len(dst)
	dst = append(dst, make([]byte, payloadHeaderSize)...)
	var err error
	dst, err = p.AppendBinary(dst)
	if err != nil {
		return nil, err
	}
	if err := setPayloadHeader(dst[start:start+payloadHeaderSize], next, len(dst)-start); err != nil {
		return nil, err
	}
	return dst, nil
}

func (p *Proposal) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("parsing proposal: truncated body")
	}
	if err := validateProposalShape(int(data[2]), int(data[3])); err != nil {
		return err
	}
	proposal := Proposal{
		Number:     data[0],
		ProtocolID: data[1],
	}
	if len(data) < 4+int(data[2]) {
		return errors.New("parsing proposal: truncated spi")
	}
	proposal.SPI = append([]byte(nil), data[4:4+int(data[2])]...)
	remaining := data[4+int(data[2]):]
	transformType := payloadTypeTransform
	for range int(data[3]) {
		if len(remaining) < 4 {
			return errors.New("parsing proposal: truncated transform")
		}
		next := remaining[0]
		if next != payloadTypeNone && next != payloadTypeTransform {
			return fmt.Errorf("parsing proposal: invalid transform substructure tag %d", next)
		}
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
		if next == payloadTypeTransform && len(remaining) == 0 {
			return errors.New("parsing proposal: transform substructure chain is truncated")
		}
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

func validateProposalShape(spiSize, transformCount int) error {
	switch spiSize {
	case proposalSPISizeNone, proposalSPISizeIPsec, proposalSPISizeIKE:
	default:
		return fmt.Errorf("parsing proposal: invalid spi size %d", spiSize)
	}
	if transformCount == 0 {
		return errors.New("parsing proposal: transform count is zero")
	}
	if transformCount > math.MaxUint8 {
		return fmt.Errorf("parsing proposal: transform count %d exceeds 255", transformCount)
	}
	return nil
}

type SecurityAssociationPayload struct {
	Proposals []Proposal
}

func (p *SecurityAssociationPayload) Type() byte { return payloadTypeSA }

func (p *SecurityAssociationPayload) MarshalBinary() ([]byte, error) {
	return p.AppendBinary(nil)
}

func (p *SecurityAssociationPayload) AppendBinary(dst []byte) ([]byte, error) {
	if len(p.Proposals) == 0 {
		return nil, errors.New("marshalling security association: proposal count is zero")
	}
	if len(p.Proposals) > math.MaxUint8 {
		return nil, fmt.Errorf("marshalling security association: proposal count %d exceeds 255", len(p.Proposals))
	}
	for i, proposal := range p.Proposals {
		if proposal.Number == 0 {
			proposal.Number = byte(i + 1)
		}
		if len(p.Proposals) > 1 && proposal.Number != byte(i+1) {
			return nil, fmt.Errorf("marshalling security association: proposal number = %d, want %d", proposal.Number, i+1)
		}
		nextType := payloadTypeNone
		if i+1 < len(p.Proposals) {
			nextType = payloadTypeProposal
		}
		var err error
		dst, err = proposal.appendBinary(dst, nextType)
		if err != nil {
			return nil, fmt.Errorf("marshalling proposal: %w", err)
		}
	}
	return dst, nil
}

func (p *SecurityAssociationPayload) UnmarshalBinary(data []byte) error {
	if len(data) == 0 {
		return errors.New("parsing security association: proposal count is zero")
	}
	payload := SecurityAssociationPayload{Proposals: make([]Proposal, 0)}
	remaining := data
	proposalType := payloadTypeProposal
	for len(remaining) > 0 {
		if len(remaining) < 4 {
			return errors.New("parsing security association: truncated proposal")
		}
		next := remaining[0]
		if next != payloadTypeNone && next != payloadTypeProposal {
			return fmt.Errorf("parsing security association: invalid proposal substructure tag %d", next)
		}
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
		if next == payloadTypeProposal && len(remaining) == 0 {
			return errors.New("parsing security association: proposal substructure chain is truncated")
		}
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
	return p.AppendBinary(nil)
}

func (p *KeyExchangePayload) AppendBinary(dst []byte) ([]byte, error) {
	if err := validateKeyExchangeDataLength(p.DHGroup, len(p.Data)); err != nil {
		return nil, fmt.Errorf("marshalling key exchange: %w", err)
	}
	start := len(dst)
	dst = append(dst, make([]byte, keyExchangeBodyHeaderLen)...)
	binary.BigEndian.PutUint16(dst[start:start+2], p.DHGroup)
	dst = append(dst, p.Data...)
	return dst, nil
}

func (p *KeyExchangePayload) UnmarshalBinary(data []byte) error {
	if len(data) < keyExchangeBodyHeaderLen {
		return errors.New("parsing key exchange: truncated body")
	}
	p.DHGroup = binary.BigEndian.Uint16(data[0:2])
	p.Data = append([]byte(nil), data[keyExchangeBodyHeaderLen:]...)
	if err := validateKeyExchangeDataLength(p.DHGroup, len(p.Data)); err != nil {
		return fmt.Errorf("parsing key exchange: %w", err)
	}
	return nil
}

func decodeKeyExchangePayload(data []byte) (*KeyExchangePayload, error) {
	payload := &KeyExchangePayload{}
	if err := payload.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return payload, nil
}

func keyExchangeDataLength(group uint16) (int, bool) {
	switch group {
	case dhGroup1024MODP:
		return keyExchange1024MODPDataLength, true
	case dhGroup2048MODP:
		return keyExchange2048MODPDataLength, true
	default:
		return 0, false
	}
}

func validateKeyExchangeDataLength(group uint16, length int) error {
	if want, ok := keyExchangeDataLength(group); ok && length != want {
		return fmt.Errorf("invalid data length %d for dh group %d", length, group)
	}
	return nil
}

type NoncePayload struct {
	Data []byte
}

const (
	nonceDataMinLen = 16
	nonceDataMaxLen = 256
)

func (p *NoncePayload) Type() byte { return payloadTypeNonce }

func (p *NoncePayload) MarshalBinary() ([]byte, error) {
	return p.AppendBinary(nil)
}

func (p *NoncePayload) AppendBinary(dst []byte) ([]byte, error) {
	if err := validateNonceDataLen(len(p.Data)); err != nil {
		return nil, err
	}
	return append(dst, p.Data...), nil
}

func (p *NoncePayload) UnmarshalBinary(data []byte) error {
	if err := validateNonceDataLen(len(data)); err != nil {
		return err
	}
	p.Data = append([]byte(nil), data...)
	return nil
}

func validateNonceDataLen(length int) error {
	if length < nonceDataMinLen || length > nonceDataMaxLen {
		return fmt.Errorf("nonce payload: invalid data length %d", length)
	}
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
	return p.AppendBinary(nil)
}

func (p *NotifyPayload) AppendBinary(dst []byte) ([]byte, error) {
	if len(p.SPI) > math.MaxUint8 {
		return nil, fmt.Errorf("marshalling notify payload: spi size %d exceeds 255", len(p.SPI))
	}
	if err := validateNotifyPayloadSPIShape(p.ProtocolID, p.NotifyType, len(p.SPI), false); err != nil {
		return nil, fmt.Errorf("marshalling notify payload: %w", err)
	}
	start := len(dst)
	dst = append(dst, p.ProtocolID, byte(len(p.SPI)), 0x00, 0x00)
	binary.BigEndian.PutUint16(dst[start+2:start+4], p.NotifyType)
	dst = append(dst, p.SPI...)
	dst = append(dst, p.Data...)
	return dst, nil
}

func (p *NotifyPayload) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("parsing notify: truncated body")
	}
	spiLen := int(data[1])
	if len(data) < 4+spiLen {
		return fmt.Errorf("parsing notify: invalid spi length %d", spiLen)
	}
	notifyType := binary.BigEndian.Uint16(data[2:4])
	if err := validateNotifyPayloadSPIShape(data[0], notifyType, spiLen, true); err != nil {
		return fmt.Errorf("parsing notify: %w", err)
	}
	payload := NotifyPayload{
		ProtocolID: data[0],
		NotifyType: notifyType,
		SPI:        append([]byte(nil), data[4:4+spiLen]...),
		Data:       append([]byte(nil), data[4+spiLen:]...),
	}
	if spiLen == notifySPISizeNone {
		payload.ProtocolID = 0
	}
	*p = payload
	return nil
}

func validateNotifyPayloadSPIShape(protocolID byte, notifyType uint16, spiSize int, received bool) error {
	switch spiSize {
	case notifySPISizeNone:
		if !received && protocolID != 0 {
			return fmt.Errorf("notify payload without spi requires protocol id 0, got %d", protocolID)
		}
		if notifyTypeForExistingChildSA(notifyType) {
			return fmt.Errorf("notify payload type %d requires child sa spi", notifyType)
		}
	case notifySPISizeIPsec:
		if protocolID != protocolIDAH && protocolID != protocolIDESP {
			return fmt.Errorf("notify payload with spi requires protocol AH or ESP, got %d", protocolID)
		}
		if !notifyTypeForExistingChildSA(notifyType) {
			return fmt.Errorf("notify payload with spi requires existing child sa notify type, got %d", notifyType)
		}
	default:
		return fmt.Errorf("invalid spi size %d", spiSize)
	}
	return nil
}

func notifyTypeForExistingChildSA(notifyType uint16) bool {
	switch notifyType {
	case notifyTypeInvalidSelectors, notifyTypeChildSANotFound, notifyTypeRekeySA:
		return true
	default:
		return false
	}
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
	return p.AppendBinary(nil)
}

func (p *DeletePayload) AppendBinary(dst []byte) ([]byte, error) {
	spiSize := 0
	if len(p.SPIs) > 0 {
		spiSize = len(p.SPIs[0])
		for _, spi := range p.SPIs[1:] {
			if len(spi) != spiSize {
				return nil, errors.New("marshalling delete payload: spi length mismatch")
			}
		}
	}
	if spiSize > 0xff {
		return nil, fmt.Errorf("marshalling delete payload: spi size %d exceeds 255", spiSize)
	}
	if err := validateDeletePayloadSPIShape(p.ProtocolID, spiSize, len(p.SPIs)); err != nil {
		return nil, fmt.Errorf("marshalling delete payload: %w", err)
	}
	start := len(dst)
	dst = append(dst, p.ProtocolID, byte(spiSize), 0x00, 0x00)
	binary.BigEndian.PutUint16(dst[start+2:start+4], uint16(len(p.SPIs)))
	for _, spi := range p.SPIs {
		dst = append(dst, spi...)
	}
	return dst, nil
}

func (p *DeletePayload) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("parsing delete payload: truncated body")
	}
	spiSize := int(data[1])
	count := int(binary.BigEndian.Uint16(data[2:4]))
	if err := validateDeletePayloadSPIShape(data[0], spiSize, count); err != nil {
		return err
	}
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

func validateDeletePayloadSPIShape(protocolID byte, spiSize, count int) error {
	switch protocolID {
	case deleteProtocolIDIKE:
		if spiSize != 0 || count != 0 {
			return fmt.Errorf("delete payload protocol IKE requires zero spi size and count, got size %d count %d", spiSize, count)
		}
	case deleteProtocolIDAH, deleteProtocolIDESP:
		if spiSize != 4 || count == 0 {
			return fmt.Errorf("delete payload protocol %d requires 4-byte spi and at least one spi, got size %d count %d", protocolID, spiSize, count)
		}
	default:
		return fmt.Errorf("delete payload protocol id %d is unsupported", protocolID)
	}
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
	return p.AppendBinary(nil)
}

func (p *IDPayload) AppendBinary(dst []byte) ([]byte, error) {
	if len(p.Data) == 0 {
		return nil, errors.New("marshalling identification: data is empty")
	}
	dst = append(dst, p.IDType, 0x00, 0x00, 0x00)
	dst = append(dst, p.Data...)
	return dst, nil
}

func (p *IDPayload) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("parsing identification: truncated body")
	}
	if len(data) == 4 {
		return errors.New("parsing identification: data is empty")
	}
	p.IDType = data[0]
	p.Data = append([]byte(nil), data[4:]...)
	return nil
}

func (p *IDPayload) RawData() ([]byte, error) {
	return p.MarshalBinary()
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
	return p.AppendBinary(nil)
}

func (p *AuthPayload) AppendBinary(dst []byte) ([]byte, error) {
	dst = append(dst, p.Method, 0x00, 0x00, 0x00)
	dst = append(dst, p.Data...)
	return dst, nil
}

func (p *AuthPayload) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("parsing authentication: truncated body")
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
	return p.AppendBinary(nil)
}

func (p *ConfigPayload) AppendBinary(dst []byte) ([]byte, error) {
	if err := validateConfigType(p.ConfigType); err != nil {
		return nil, fmt.Errorf("marshalling configuration: %w", err)
	}
	if err := validateConfigAttributes(p.ConfigType, p.Attributes); err != nil {
		return nil, err
	}
	dst = append(dst, p.ConfigType, 0x00, 0x00, 0x00)
	for _, attr := range p.Attributes {
		var err error
		dst, err = appendConfigAttribute(dst, attr)
		if err != nil {
			return nil, fmt.Errorf("marshalling config attribute: %w", err)
		}
	}
	return dst, nil
}

func (p *ConfigPayload) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("parsing configuration: truncated body")
	}
	attrs, err := decodeConfigAttributes(data[4:])
	if err != nil {
		return err
	}
	if err := validateConfigAttributes(data[0], attrs); err != nil {
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

func validateConfigType(configType byte) error {
	switch configType {
	case configTypeRequest, configTypeReply, configTypeSet, configTypeAck:
		return nil
	default:
		return fmt.Errorf("invalid config type %d", configType)
	}
}

func appendConfigAttribute(dst []byte, attr Attribute) ([]byte, error) {
	if len(attr.Value) > math.MaxUint16 {
		return nil, fmt.Errorf("configuration attribute %d length %d exceeds uint16", attr.Type, len(attr.Value))
	}
	if err := validateConfigAttributeLength(attr.Type, len(attr.Value)); err != nil {
		return nil, err
	}
	if err := validateConfigAttributeValue(attr.Type, attr.Value); err != nil {
		return nil, err
	}
	start := len(dst)
	dst = append(dst, make([]byte, 4)...)
	binary.BigEndian.PutUint16(dst[start:start+2], attr.Type&0x7fff)
	binary.BigEndian.PutUint16(dst[start+2:start+4], uint16(len(attr.Value)))
	return append(dst, attr.Value...), nil
}

func decodeConfigAttributes(data []byte) ([]Attribute, error) {
	attrs := make([]Attribute, 0)
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, errors.New("parsing configuration attributes: truncated attribute")
		}
		rawType := binary.BigEndian.Uint16(data[0:2])
		attrType := rawType & 0x7fff
		length := int(binary.BigEndian.Uint16(data[2:4]))
		if len(data) < 4+length {
			return nil, fmt.Errorf("parsing configuration attributes: invalid attribute length %d", length)
		}
		if err := validateConfigAttributeLength(attrType, length); err != nil {
			return nil, err
		}
		if err := validateConfigAttributeValue(attrType, data[4:4+length]); err != nil {
			return nil, err
		}
		attrs = append(attrs, Attribute{
			Format: attributeFormatTLV,
			Type:   attrType,
			Value:  append([]byte(nil), data[4:4+length]...),
		})
		data = data[4+length:]
	}
	return attrs, nil
}

func validateConfigAttributes(configType byte, attrs []Attribute) error {
	if configType != configTypeReply && configType != configTypeRequest {
		return nil
	}
	hasIPv4Address := false
	netmaskCount := 0
	for _, attr := range attrs {
		switch attr.Type {
		case configAttrInternalIPv4Address:
			if len(attr.Value) != 0 {
				hasIPv4Address = true
			}
		case configAttrInternalIPv4Netmask:
			netmaskCount++
			if configType == configTypeRequest && len(attr.Value) != 0 {
				return errors.New("parsing configuration: non-empty internal ipv4 netmask in request")
			}
		}
	}
	if configType == configTypeReply && !hasIPv4Address && netmaskCount > 0 {
		return errors.New("parsing configuration: internal ipv4 netmask without internal ipv4 address")
	}
	if netmaskCount > 1 {
		return errors.New("parsing configuration: multiple internal ipv4 netmasks")
	}
	return nil
}

func validateConfigAttributeLength(attrType uint16, length int) error {
	switch attrType {
	case configAttrInternalIPv4Address,
		configAttrInternalIPv4Netmask,
		configAttrInternalIPv4DNS,
		configAttrInternalIPv4NBNS,
		configAttrInternalIPv4DHCP,
		configAttrIPv4PCSCF:
		if length == 0 || length == net.IPv4len {
			return nil
		}
	case configAttrApplicationVersion:
		return nil
	case configAttrInternalIPv6Address:
		if length == 0 || length == net.IPv6len+1 {
			return nil
		}
	case configAttrInternalIPv6DNS,
		configAttrInternalIPv6DHCP,
		configAttrIPv6PCSCF:
		if length == 0 || length == net.IPv6len {
			return nil
		}
	case configAttrInternalIPv4Subnet:
		if length == 0 || length == net.IPv4len*2 {
			return nil
		}
	case configAttrSupportedAttributes:
		if length%2 == 0 {
			return nil
		}
	case configAttrInternalIPv6Subnet:
		if length == net.IPv6len+1 {
			return nil
		}
	case configAttrLivenessTimeout:
		if length == 0 || length == 4 {
			return nil
		}
	default:
		return nil
	}
	return fmt.Errorf("parsing configuration attributes: invalid length %d for attribute %d", length, attrType)
}

func validateConfigAttributeValue(attrType uint16, value []byte) error {
	if attrType != configAttrInternalIPv4Netmask || len(value) == 0 {
		return nil
	}
	_, bits := net.IPMask(value).Size()
	if bits != net.IPv4len*8 {
		return errors.New("parsing configuration attributes: invalid internal ipv4 netmask")
	}
	return nil
}

type TrafficSelector struct {
	Type       byte
	ProtocolID byte
	Data       []byte
}

func (s TrafficSelector) MarshalBinary() ([]byte, error) {
	return s.AppendBinary(nil)
}

func (s TrafficSelector) AppendBinary(dst []byte) ([]byte, error) {
	if err := validateTrafficSelector(s); err != nil {
		return nil, err
	}
	start := len(dst)
	dst = append(dst, make([]byte, trafficSelectorHeaderLen)...)
	dst[start] = s.Type
	dst[start+1] = s.ProtocolID
	binary.BigEndian.PutUint16(dst[start+2:start+4], uint16(len(s.Data)+trafficSelectorHeaderLen))
	return append(dst, s.Data...), nil
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

func (s TrafficSelector) Contains(sub TrafficSelector) bool {
	if s.Type != sub.Type || s.ProtocolID != sub.ProtocolID {
		return false
	}
	addressLen := trafficSelectorAddressLength(s.Type)
	if addressLen == 0 || len(s.Data) != trafficSelectorPortsLen+addressLen*2 || len(sub.Data) != trafficSelectorPortsLen+addressLen*2 {
		return false
	}
	startPort := binary.BigEndian.Uint16(s.Data[0:2])
	endPort := binary.BigEndian.Uint16(s.Data[2:4])
	subStartPort := binary.BigEndian.Uint16(sub.Data[0:2])
	subEndPort := binary.BigEndian.Uint16(sub.Data[2:4])
	if startPort > subStartPort || endPort < subEndPort {
		return false
	}
	startAddress := s.Data[trafficSelectorPortsLen : trafficSelectorPortsLen+addressLen]
	endAddress := s.Data[trafficSelectorPortsLen+addressLen : trafficSelectorPortsLen+addressLen*2]
	subStartAddress := sub.Data[trafficSelectorPortsLen : trafficSelectorPortsLen+addressLen]
	subEndAddress := sub.Data[trafficSelectorPortsLen+addressLen : trafficSelectorPortsLen+addressLen*2]
	return compareBytes(startAddress, subStartAddress) <= 0 && compareBytes(endAddress, subEndAddress) >= 0
}

func decodeTrafficSelector(data []byte) (TrafficSelector, int, error) {
	if len(data) < 4 {
		return TrafficSelector{}, 0, errors.New("parsing traffic selector: truncated selector")
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length < trafficSelectorHeaderLen {
		return TrafficSelector{}, 0, fmt.Errorf("parsing traffic selector: invalid length %d", length)
	}
	if len(data) < length {
		return TrafficSelector{}, 0, fmt.Errorf("parsing traffic selector: invalid length %d", length)
	}
	selector := TrafficSelector{Type: data[0], ProtocolID: data[1], Data: append([]byte(nil), data[4:length]...)}
	if err := validateTrafficSelector(selector); err != nil {
		return TrafficSelector{}, 0, err
	}
	return selector, length, nil
}

func validateTrafficSelector(selector TrafficSelector) error {
	if !validTrafficSelectorProtocol(selector.ProtocolID) {
		return fmt.Errorf("parsing traffic selector: invalid ip protocol id %d", selector.ProtocolID)
	}

	addressLen := trafficSelectorAddressLength(selector.Type)
	if addressLen == 0 {
		return fmt.Errorf("parsing traffic selector: invalid type %d", selector.Type)
	}
	if got, want := len(selector.Data), trafficSelectorPortsLen+addressLen*2; got != want {
		if selector.Type == trafficSelectorIPv4Range {
			return fmt.Errorf("parsing traffic selector: invalid ipv4 length %d", got+trafficSelectorHeaderLen)
		}
		return fmt.Errorf("parsing traffic selector: invalid ipv6 length %d", got+trafficSelectorHeaderLen)
	}

	startPort := binary.BigEndian.Uint16(selector.Data[0:2])
	endPort := binary.BigEndian.Uint16(selector.Data[2:4])
	if startPort > endPort {
		return fmt.Errorf("parsing traffic selector: invalid port range %d-%d", startPort, endPort)
	}
	if selector.ProtocolID == ipProtocolAny && (startPort != 0 || endPort != math.MaxUint16) {
		return fmt.Errorf("parsing traffic selector: protocol 0 requires port range 0-%d", math.MaxUint16)
	}
	startAddress := selector.Data[trafficSelectorPortsLen : trafficSelectorPortsLen+addressLen]
	endAddress := selector.Data[trafficSelectorPortsLen+addressLen : trafficSelectorPortsLen+addressLen*2]
	if compareBytes(startAddress, endAddress) > 0 {
		return errors.New("parsing traffic selector: invalid address range")
	}
	return nil
}

func trafficSelectorAddressLength(selectorType byte) int {
	switch selectorType {
	case trafficSelectorIPv4Range:
		return net.IPv4len
	case trafficSelectorIPv6Range:
		return net.IPv6len
	default:
		return 0
	}
}

func validTrafficSelectorProtocol(protocol byte) bool {
	switch protocol {
	case ipProtocolAny, ipProtocolICMP, ipProtocolTCP, ipProtocolUDP:
		return true
	default:
		return false
	}
}

func compareBytes(a, b []byte) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
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
	return p.AppendBinary(nil)
}

func (p *TrafficSelectorPayload) AppendBinary(dst []byte) ([]byte, error) {
	if len(p.Selectors) == 0 {
		return nil, errors.New("marshalling traffic selectors: expected at least one selector")
	}
	if len(p.Selectors) > math.MaxUint8 {
		return nil, fmt.Errorf("marshalling traffic selectors: selector count %d exceeds 255", len(p.Selectors))
	}
	dst = append(dst, byte(len(p.Selectors)), 0x00, 0x00, 0x00)
	for _, selector := range p.Selectors {
		var err error
		dst, err = selector.AppendBinary(dst)
		if err != nil {
			return nil, fmt.Errorf("marshalling traffic selector: %w", err)
		}
	}
	return dst, nil
}

func (p *TrafficSelectorPayload) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("parsing traffic selectors: truncated body")
	}
	count := int(data[0])
	if count == 0 {
		return errors.New("parsing traffic selectors: expected at least one selector")
	}
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

func (p *TrafficSelectorPayload) Contains(sub *TrafficSelectorPayload) bool {
	for _, subSelector := range sub.Selectors {
		if !trafficSelectorsContain(p.Selectors, subSelector) {
			return false
		}
	}
	return true
}

func trafficSelectorsContain(selectors []TrafficSelector, sub TrafficSelector) bool {
	for _, selector := range selectors {
		if selector.Contains(sub) {
			return true
		}
	}
	return false
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

const eapMessageHeaderLen = 4

func (p *EAPPayload) Type() byte { return payloadTypeEAP }

func (p *EAPPayload) MarshalBinary() ([]byte, error) {
	return p.AppendBinary(nil)
}

func (p *EAPPayload) AppendBinary(dst []byte) ([]byte, error) {
	if err := validateEAPMessageLength(p.Data); err != nil {
		return nil, err
	}
	return append(dst, p.Data...), nil
}

func (p *EAPPayload) UnmarshalBinary(data []byte) error {
	if err := validateEAPMessageLength(data); err != nil {
		return err
	}
	p.Data = append([]byte(nil), data...)
	return nil
}

func validateEAPMessageLength(data []byte) error {
	if len(data) < eapMessageHeaderLen {
		return fmt.Errorf("eap payload: message length %d is shorter than header", len(data))
	}
	length := int(binary.BigEndian.Uint16(data[2:eapMessageHeaderLen]))
	if length != len(data) {
		return fmt.Errorf("eap payload: message length %d does not match payload body length %d", length, len(data))
	}
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
	return p.AppendBinary(nil)
}

func (p *EncryptedPayload) AppendBinary(dst []byte) ([]byte, error) {
	return append(dst, p.Raw...), nil
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

type EncryptedFragmentPayload struct {
	NextPayload    byte
	FragmentNumber uint16
	TotalFragments uint16
	Raw            []byte
}

func (p *EncryptedFragmentPayload) Type() byte { return payloadTypeEncryptedFragment }

func (p *EncryptedFragmentPayload) MarshalBinary() ([]byte, error) {
	return p.AppendBinary(nil)
}

func (p *EncryptedFragmentPayload) AppendBinary(dst []byte) ([]byte, error) {
	if p.FragmentNumber == 0 || p.TotalFragments == 0 {
		return nil, errors.New("marshalling encrypted fragment: fragment number and total fragments must be non-zero")
	}
	if p.FragmentNumber > p.TotalFragments {
		return nil, fmt.Errorf("marshalling encrypted fragment: fragment number %d exceeds total fragments %d", p.FragmentNumber, p.TotalFragments)
	}
	start := len(dst)
	dst = append(dst, make([]byte, 4)...)
	binary.BigEndian.PutUint16(dst[start:start+2], p.FragmentNumber)
	binary.BigEndian.PutUint16(dst[start+2:start+4], p.TotalFragments)
	dst = append(dst, p.Raw...)
	return dst, nil
}

func (p *EncryptedFragmentPayload) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("parsing encrypted fragment: truncated body")
	}
	fragmentNumber := binary.BigEndian.Uint16(data[0:2])
	totalFragments := binary.BigEndian.Uint16(data[2:4])
	if fragmentNumber == 0 || totalFragments == 0 {
		return errors.New("parsing encrypted fragment: fragment number and total fragments must be non-zero")
	}
	if fragmentNumber > totalFragments {
		return fmt.Errorf("parsing encrypted fragment: fragment number %d exceeds total fragments %d", fragmentNumber, totalFragments)
	}
	p.FragmentNumber = fragmentNumber
	p.TotalFragments = totalFragments
	p.Raw = append([]byte(nil), data[4:]...)
	return nil
}

func decodeEncryptedFragmentPayload(next byte, data []byte) (*EncryptedFragmentPayload, error) {
	payload := &EncryptedFragmentPayload{NextPayload: next}
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
		if protectedPayloadType(payload.Type()) && i+1 < len(payloads) {
			return 0, nil, errors.New("marshalling payload chain: encrypted payload must be last")
		}
		next := payloadTypeNone
		if encrypted, ok := payload.(*EncryptedPayload); ok {
			next = encrypted.NextPayload
		} else if fragment, ok := payload.(*EncryptedFragmentPayload); ok {
			next = fragment.NextPayload
		} else if i+1 < len(payloads) {
			next = payloads[i+1].Type()
		}
		var err error
		body, err = appendSinglePayload(body, payload, next)
		if err != nil {
			return 0, nil, err
		}
	}
	return first, body, nil
}

func marshalSinglePayload(payload Payload, next byte) ([]byte, error) {
	return appendSinglePayload(nil, payload, next)
}

func appendSinglePayload(dst []byte, payload Payload, next byte) ([]byte, error) {
	start := len(dst)
	dst = append(dst, make([]byte, payloadHeaderSize)...)
	var err error
	if appender, ok := payload.(encoding.BinaryAppender); ok {
		dst, err = appender.AppendBinary(dst)
	} else {
		var body []byte
		body, err = payload.MarshalBinary()
		dst = append(dst, body...)
	}
	if err != nil {
		return nil, err
	}
	if err := setPayloadHeader(dst[start:start+payloadHeaderSize], next, len(dst)-start); err != nil {
		return nil, err
	}
	return dst, nil
}

func marshalPayloadBlock(next byte, body []byte) ([]byte, error) {
	return appendPayloadBlock(nil, next, body)
}

func appendPayloadBlock(dst []byte, next byte, body []byte) ([]byte, error) {
	length := len(body) + payloadHeaderSize
	if length > math.MaxUint16 {
		return nil, fmt.Errorf("marshalling payload: payload length %d exceeds uint16", length)
	}
	start := len(dst)
	dst = append(dst, make([]byte, payloadHeaderSize)...)
	if err := setPayloadHeader(dst[start:start+payloadHeaderSize], next, length); err != nil {
		return nil, err
	}
	return append(dst, body...), nil
}

func setPayloadHeader(header []byte, next byte, length int) error {
	if length > math.MaxUint16 {
		return fmt.Errorf("marshalling payload: payload length %d exceeds uint16", length)
	}
	header[0] = next
	binary.BigEndian.PutUint16(header[2:4], uint16(length))
	return nil
}

func DecodePayloadChain(firstType byte, data []byte) ([]Payload, error) {
	payloads := make([]Payload, 0)
	nextType := firstType
	remaining := data
	seen := make(map[byte]struct{})
	for nextType != payloadTypeNone {
		if len(remaining) < payloadHeaderSize {
			return nil, errors.New("parsing payload chain: truncated payload")
		}
		next := remaining[0]
		critical := remaining[1]&payloadHeaderCriticalBit != 0
		length := int(binary.BigEndian.Uint16(remaining[2:4]))
		if length < payloadHeaderSize {
			return nil, fmt.Errorf("parsing payload chain: invalid payload length %d", length)
		}
		if len(remaining) < length {
			return nil, fmt.Errorf("parsing payload chain: invalid payload length %d", length)
		}
		body := remaining[payloadHeaderSize:length]
		payload, err := decodePayload(nextType, next, body, critical)
		if err != nil {
			return nil, err
		}
		if payload != nil {
			if !repeatablePayloadType(payload.Type()) {
				if _, ok := seen[payload.Type()]; ok {
					return nil, fmt.Errorf("parsing payload chain: duplicate payload type %d", payload.Type())
				}
				seen[payload.Type()] = struct{}{}
			}
			payloads = append(payloads, payload)
		}
		remaining = remaining[length:]
		if protectedPayloadType(nextType) {
			break
		}
		nextType = next
	}
	if len(remaining) != 0 {
		return nil, fmt.Errorf("parsing payload chain: %d trailing bytes", len(remaining))
	}
	return payloads, nil
}

func protectedPayloadType(payloadType byte) bool {
	return payloadType == payloadTypeEncrypted || payloadType == payloadTypeEncryptedFragment
}

func repeatablePayloadType(payloadType byte) bool {
	switch payloadType {
	case payloadTypeNotify, payloadTypeDelete:
		return true
	default:
		return false
	}
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
	case payloadTypeEncryptedFragment:
		return decodeEncryptedFragmentPayload(next, body)
	case payloadTypeCP:
		return decodeConfigPayload(body)
	case payloadTypeEAP:
		return decodeEAPPayload(body)
	default:
		if !critical {
			return nil, nil
		}
		return nil, UnsupportedCriticalPayloadError{PayloadType: payloadType}
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

func FindTrafficSelectorPayload(payloads []Payload, tag byte) *TrafficSelectorPayload {
	for _, payload := range payloads {
		selectorPayload, ok := payload.(*TrafficSelectorPayload)
		if ok && selectorPayload.Tag == tag {
			return selectorPayload
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

type DeviceIdentity struct {
	Type  byte
	Value []byte
}

func NewDeviceIdentity(identity string, requestedType byte) (DeviceIdentity, error) {
	if identity == "" {
		return DeviceIdentity{}, errors.New("encoding device identity: identity is empty")
	}
	digits := []byte(identity)
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return DeviceIdentity{}, fmt.Errorf("encoding device identity: invalid digit %q", digit)
		}
	}
	identityType, err := deviceIdentityType(len(digits), requestedType)
	if err != nil {
		return DeviceIdentity{}, err
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
	return DeviceIdentity{Type: identityType, Value: encoded}, nil
}

func (d DeviceIdentity) MarshalBinary() ([]byte, error) {
	return d.AppendBinary(nil)
}

func (d DeviceIdentity) AppendBinary(dst []byte) ([]byte, error) {
	if err := validateDeviceIdentityType(d.Type); err != nil {
		return nil, err
	}
	if len(d.Value) != deviceIdentityValueLen {
		if len(d.Value) != 0 {
			return nil, fmt.Errorf("encoding device identity: value length %d does not match %d", len(d.Value), deviceIdentityValueLen)
		}
	}
	start := len(dst)
	dst = append(dst, make([]byte, deviceIdentityLengthFieldLen+deviceIdentityTypeLen)...)
	binary.BigEndian.PutUint16(dst[start:start+deviceIdentityLengthFieldLen], uint16(deviceIdentityTypeLen+len(d.Value)))
	dst[start+deviceIdentityLengthFieldLen] = d.Type
	dst = append(dst, d.Value...)
	return dst, nil
}

func (d *DeviceIdentity) UnmarshalBinary(data []byte) error {
	if len(data) == deviceIdentityRequestLen {
		identity := DeviceIdentity{Type: data[0]}
		if err := validateDeviceIdentityType(identity.Type); err != nil {
			return err
		}
		*d = identity
		return nil
	}
	if len(data) < deviceIdentityLengthFieldLen+deviceIdentityTypeLen {
		return errors.New("parsing device identity: data too short")
	}
	length := int(binary.BigEndian.Uint16(data[:deviceIdentityLengthFieldLen]))
	if length < deviceIdentityTypeLen {
		return fmt.Errorf("parsing device identity: invalid length %d", length)
	}
	wireLen := deviceIdentityLengthFieldLen + length
	if len(data) != wireLen {
		return fmt.Errorf("parsing device identity: data length %d does not match %d", len(data), wireLen)
	}
	identity := DeviceIdentity{Type: data[deviceIdentityLengthFieldLen], Value: append([]byte(nil), data[deviceIdentityLengthFieldLen+deviceIdentityTypeLen:]...)}
	if err := validateDeviceIdentityType(identity.Type); err != nil {
		return err
	}
	if len(identity.Value) != 0 && len(identity.Value) != deviceIdentityValueLen {
		return fmt.Errorf("parsing device identity: value length %d does not match %d", len(identity.Value), deviceIdentityValueLen)
	}
	*d = identity
	return nil
}

func validateDeviceIdentityType(identityType byte) error {
	switch identityType {
	case deviceIdentityIMEI, deviceIdentityIMEISV:
		return nil
	default:
		return fmt.Errorf("parsing device identity: unsupported type %d", identityType)
	}
}

func deviceIdentityType(length int, requestedType byte) (byte, error) {
	hasIMEI := length == 15
	hasIMEISV := length == 16
	if !hasIMEI && !hasIMEISV {
		return 0, fmt.Errorf("encoding device identity: unsupported length %d", length)
	}
	switch requestedType {
	case deviceIdentityAuto:
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
