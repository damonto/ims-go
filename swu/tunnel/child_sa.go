package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/damonto/ims-go/swu/esp"
	"github.com/damonto/ims-go/swu/handshake"
	"github.com/damonto/ims-go/swu/ike"
)

func tunnelInfoFromChildSA(payloads []ike.Payload, cfg handshake.Config, requestProposals []ike.Proposal) (Info, error) {
	config, proposal, tsi, tsr, err := childSAConfig(payloads, requestProposals)
	if err != nil {
		return Info{}, err
	}
	tunnel, err := tunnelInfoFromProposal(proposal)
	if err != nil {
		return Info{}, err
	}
	tunnel.PDNTypeRestriction = pdnTypeRestriction(payloads)
	tunnel.InitiatorTrafficSelectors = cloneTrafficSelectors(tsi.Selectors)
	tunnel.ResponderTrafficSelectors = cloneTrafficSelectors(tsr.Selectors)
	if err := applyTunnelAddresses(&tunnel, *config, cfg); err != nil {
		return Info{}, err
	}
	if err := applyN1ModeInfo(&tunnel, payloads, cfg); err != nil {
		return Info{}, err
	}
	return tunnel, nil
}

func applyN1ModeInfo(tunnel *Info, payloads []ike.Payload, cfg handshake.Config) error {
	if cfg.PDUSessionID == 0 {
		return nil
	}
	tunnel.PDUSessionID = cfg.PDUSessionID
	if notify := ike.FindNotifyPayload(payloads, notifyTypeN1ModeInformation); notify != nil {
		var data n1ModeInformationNotifyData
		if err := data.UnmarshalBinary(notify.Data); err != nil {
			return err
		}
		tunnel.SNSSAI = data.SNSSAI
	}
	if notify := ike.FindNotifyPayload(payloads, notifyTypeN1ModeSNSSAIPlmnID); notify != nil {
		var data n1ModeSNSSAIPlmnIDNotifyData
		if err := data.UnmarshalBinary(notify.Data); err != nil {
			return err
		}
		tunnel.SNSSAIPlmnID = data.PLMNID
	}
	return nil
}

func childSAConfig(payloads []ike.Payload, requestProposals []ike.Proposal) (*ike.ConfigPayload, ike.Proposal, *ike.TrafficSelectorPayload, *ike.TrafficSelectorPayload, error) {
	config := ike.FindConfigPayload(payloads)
	sa := ike.FindSAPayload(payloads)
	if config == nil || sa == nil {
		return nil, ike.Proposal{}, nil, nil, errors.New("parsing ike_auth response: missing child sa or configuration")
	}
	if config.ConfigType != configTypeReply {
		return nil, ike.Proposal{}, nil, nil, fmt.Errorf("parsing ike_auth response: unexpected configuration type %d", config.ConfigType)
	}
	tsi := ike.FindTrafficSelectorPayload(payloads, payloadTypeTSi)
	tsr := ike.FindTrafficSelectorPayload(payloads, payloadTypeTSr)
	if tsi == nil || tsr == nil {
		return nil, ike.Proposal{}, nil, nil, errors.New("parsing ike_auth response: missing traffic selectors")
	}
	if len(sa.Proposals) != 1 {
		return nil, ike.Proposal{}, nil, nil, fmt.Errorf("parsing ike_auth response: negotiated proposal count %d", len(sa.Proposals))
	}
	if err := validateNegotiatedProposalFromRequests(sa.Proposals[0], requestProposals); err != nil {
		return nil, ike.Proposal{}, nil, nil, fmt.Errorf("parsing ike_auth response: %w", err)
	}
	proposal, err := negotiatedChildSAProposal(sa.Proposals[0], 0)
	if err != nil {
		return nil, ike.Proposal{}, nil, nil, fmt.Errorf("parsing ike_auth response: %w", err)
	}
	return config, proposal, tsi, tsr, nil
}

func negotiatedChildSAProposal(proposal ike.Proposal, dhGroup uint16) (ike.Proposal, error) {
	if proposal.ProtocolID != proposalProtocolESP {
		return ike.Proposal{}, fmt.Errorf("invalid negotiated protocol id %d", proposal.ProtocolID)
	}
	seenENCR := false
	seenINTEG := false
	seenESN := false
	seenDH := false
	for _, transform := range proposal.Transforms {
		switch transform.TransformType {
		case transformTypeENCR:
			if seenENCR {
				return ike.Proposal{}, errors.New("duplicate encryption transform")
			}
			seenENCR = true
		case transformTypeINTEG:
			if seenINTEG {
				return ike.Proposal{}, errors.New("duplicate integrity transform")
			}
			seenINTEG = true
		case transformTypeESN:
			if seenESN {
				return ike.Proposal{}, errors.New("duplicate esn transform")
			}
			if transform.ID != transformESNNoESN {
				return ike.Proposal{}, fmt.Errorf("unsupported esn transform %d", transform.ID)
			}
			seenESN = true
		case transformTypeDH:
			if seenDH {
				return ike.Proposal{}, errors.New("duplicate dh transform")
			}
			if dhGroup == 0 {
				return ike.Proposal{}, fmt.Errorf("unexpected dh group %d", transform.ID)
			}
			if transform.ID != dhGroup {
				return ike.Proposal{}, fmt.Errorf("dh group = %d, want %d", transform.ID, dhGroup)
			}
			seenDH = true
		default:
			return ike.Proposal{}, fmt.Errorf("unsupported negotiated transform type %d", transform.TransformType)
		}
	}
	if !seenENCR || !seenINTEG || !seenESN {
		return ike.Proposal{}, errors.New("negotiated esp transform is incomplete")
	}
	if dhGroup != 0 && !seenDH {
		return ike.Proposal{}, fmt.Errorf("dh group = 0, want %d", dhGroup)
	}
	return proposal, nil
}

func tunnelInfoFromProposal(proposal ike.Proposal) (Info, error) {
	tunnel := Info{}
	if len(proposal.SPI) != 4 {
		return Info{}, fmt.Errorf("parsing ike_auth response: invalid responder esp spi length %d", len(proposal.SPI))
	}
	tunnel.ESPResponderSPI = binary.BigEndian.Uint32(proposal.SPI)
	if !esp.ValidSPI(tunnel.ESPResponderSPI) {
		return Info{}, fmt.Errorf("parsing ike_auth response: invalid responder esp spi %d", tunnel.ESPResponderSPI)
	}
	for _, transform := range proposal.Transforms {
		switch transform.TransformType {
		case transformTypeENCR:
			if transform.ID != transformENCRAESCBC {
				return Info{}, fmt.Errorf("parsing ike_auth response: unsupported encryption transform %d", transform.ID)
			}
			tunnel.Encryption = transform.ID
			for _, attr := range transform.Attributes {
				if attr.Type == transformAttrKeyLength {
					if value, ok := attr.Uint16(); ok {
						tunnel.EncryptionKeyLen = value
					}
				}
			}
		case transformTypeINTEG:
			tunnel.Integrity = transform.ID
		}
	}
	if tunnel.Encryption == 0 || tunnel.EncryptionKeyLen == 0 || tunnel.Integrity == 0 {
		return Info{}, errors.New("parsing ike_auth response: negotiated esp transform is incomplete")
	}
	return tunnel, nil
}

func applyTunnelAddresses(tunnel *Info, config ike.ConfigPayload, cfg handshake.Config) error {
	addresses, err := tunnelAddresses(config.Attributes, cfg.PCSCFIPv4ConfigAttribute, cfg.PCSCFIPv6ConfigAttribute)
	if err != nil {
		return err
	}
	if addresses.internalIPv6.IsZero() && !addresses.internalIPv6Prefix.IsZero() {
		addresses.internalIPv6 = ipv6AddressFromPrefix(addresses.internalIPv6Prefix)
	}
	tunnel.InnerIPv4 = append(net.IP(nil), addresses.internalIPv4...)
	tunnel.InnerIPv6 = cloneIPAddress(addresses.internalIPv6)
	tunnel.InnerIPv6Prefix = cloneIPPrefix(addresses.internalIPv6Prefix)
	tunnel.PCSCFIPs = pcscfCandidates(addresses)
	switch {
	case len(tunnel.InnerIPv4) != 0 || !tunnel.InnerIPv6.IsZero():
		return nil
	default:
		return errors.New("parsing ike_auth response: internal ip is missing")
	}
}

func pcscfCandidates(addresses tunnelAddressSet) []net.IP {
	ips := make([]net.IP, 0, len(addresses.pcscfIPv6)+len(addresses.pcscfIPv4))
	if !addresses.internalIPv6.IsZero() {
		for _, ip := range addresses.pcscfIPv6 {
			ips = appendUniqueIP(ips, ip)
		}
	}
	if len(addresses.internalIPv4) != 0 {
		for _, ip := range addresses.pcscfIPv4 {
			ips = appendUniqueIP(ips, ip)
		}
	}
	return ips
}

type tunnelAddressSet struct {
	internalIPv4       net.IP
	internalIPv6       IPAddress
	internalIPv6Prefix IPPrefix
	pcscfIPv4          []net.IP
	pcscfIPv6          []net.IP
}

const (
	configAttrInternalIPv6AddressLen = net.IPv6len + 1
	configAttrInternalIPv6SubnetLen  = net.IPv6len + 1
)

func tunnelAddresses(attrs []ike.Attribute, pcscfIPv4Attr, pcscfIPv6Attr uint16) (tunnelAddressSet, error) {
	if pcscfIPv4Attr == 0 {
		pcscfIPv4Attr = configAttrPCSCFIPv4Address
	}
	if pcscfIPv6Attr == 0 {
		pcscfIPv6Attr = configAttrPCSCFIPv6Address
	}
	var addresses tunnelAddressSet
	for _, attr := range attrs {
		switch attr.Type {
		case configAttrInternalIPv4Address:
			if len(attr.Value) == 0 {
				continue
			}
			if len(attr.Value) != net.IPv4len {
				return tunnelAddressSet{}, configAttributeLengthError("internal ipv4 address", len(attr.Value), net.IPv4len)
			}
			addresses.internalIPv4 = append(net.IP(nil), attr.Value...)
		case configAttrInternalIPv6Address:
			if len(attr.Value) == 0 {
				continue
			}
			address, err := ipv6AddressAttribute(attr.Value, "internal ipv6 address")
			if err != nil {
				return tunnelAddressSet{}, err
			}
			addresses.internalIPv6 = address
			addresses.internalIPv6Prefix = ipv6Prefix(address.IP, address.PrefixLen)
		case configAttrInternalIPv6Subnet:
			if len(attr.Value) == 0 {
				continue
			}
			prefix, err := ipv6PrefixAttribute(attr.Value, "internal ipv6 subnet")
			if err != nil {
				return tunnelAddressSet{}, err
			}
			if addresses.internalIPv6Prefix.IsZero() {
				addresses.internalIPv6Prefix = prefix
			}
		}

		matchesPCSCFIPv4 := attr.Type == pcscfIPv4Attr || attr.Type == configAttrPCSCFIPv4Address
		matchesPCSCFIPv6 := attr.Type == pcscfIPv6Attr || attr.Type == configAttrPCSCFIPv6Address
		if err := appendPCSCFAddressAttribute(&addresses, attr.Value, matchesPCSCFIPv4, matchesPCSCFIPv6); err != nil {
			return tunnelAddressSet{}, err
		}
	}
	return addresses, nil
}

func appendPCSCFAddressAttribute(addresses *tunnelAddressSet, value []byte, matchesIPv4, matchesIPv6 bool) error {
	if !matchesIPv4 && !matchesIPv6 {
		return nil
	}
	if len(value) == 0 {
		return nil
	}
	switch {
	case matchesIPv4 && matchesIPv6:
		switch len(value) {
		case net.IPv4len:
			addresses.pcscfIPv4 = appendUniqueIP(addresses.pcscfIPv4, value)
		case net.IPv6len:
			addresses.pcscfIPv6 = appendUniqueIP(addresses.pcscfIPv6, value)
		default:
			return fmt.Errorf("parsing configuration attributes: p-cscf address length %d, want %d or %d", len(value), net.IPv4len, net.IPv6len)
		}
	case matchesIPv4:
		if len(value) != net.IPv4len {
			return configAttributeLengthError("p-cscf ipv4 address", len(value), net.IPv4len)
		}
		addresses.pcscfIPv4 = appendUniqueIP(addresses.pcscfIPv4, value)
	case matchesIPv6:
		if len(value) != net.IPv6len {
			return configAttributeLengthError("p-cscf ipv6 address", len(value), net.IPv6len)
		}
		addresses.pcscfIPv6 = appendUniqueIP(addresses.pcscfIPv6, value)
	}
	return nil
}

func configAttributeLengthError(name string, got, want int) error {
	return fmt.Errorf("parsing configuration attributes: %s length %d, want %d", name, got, want)
}

func ipv6AddressAttribute(value []byte, name string) (IPAddress, error) {
	if len(value) != configAttrInternalIPv6AddressLen {
		return IPAddress{}, configAttributeLengthError(name, len(value), configAttrInternalIPv6AddressLen)
	}
	prefixLen := int(value[net.IPv6len])
	if prefixLen > net.IPv6len*8 {
		return IPAddress{}, fmt.Errorf("parsing configuration attributes: %s prefix length %d exceeds 128", name, prefixLen)
	}
	return IPAddress{
		IP:        append(net.IP(nil), value[:net.IPv6len]...),
		PrefixLen: prefixLen,
	}, nil
}

func ipv6PrefixAttribute(value []byte, name string) (IPPrefix, error) {
	if len(value) != configAttrInternalIPv6SubnetLen {
		return IPPrefix{}, configAttributeLengthError(name, len(value), configAttrInternalIPv6SubnetLen)
	}
	prefixLen := int(value[net.IPv6len])
	if prefixLen > net.IPv6len*8 {
		return IPPrefix{}, fmt.Errorf("parsing configuration attributes: %s prefix length %d exceeds 128", name, prefixLen)
	}
	return ipv6Prefix(value[:net.IPv6len], prefixLen), nil
}

func ipv6Prefix(ip net.IP, prefixLen int) IPPrefix {
	prefix := append(net.IP(nil), ip.To16()...)
	if len(prefix) == net.IPv6len {
		prefix = prefix.Mask(net.CIDRMask(prefixLen, net.IPv6len*8))
	}
	return IPPrefix{
		IP:        prefix,
		PrefixLen: prefixLen,
	}
}

func ipv6AddressFromPrefix(prefix IPPrefix) IPAddress {
	ip := append(net.IP(nil), prefix.IP.To16()...)
	if len(ip) != net.IPv6len {
		return IPAddress{}
	}
	if prefix.PrefixLen < net.IPv6len*8 {
		incrementIPv6(ip)
	}
	return IPAddress{IP: ip, PrefixLen: prefix.PrefixLen}
}

func incrementIPv6(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

func appendUniqueIP(ips []net.IP, ip net.IP) []net.IP {
	for _, existing := range ips {
		if existing.Equal(ip) {
			return ips
		}
	}
	return append(ips, append(net.IP(nil), ip...))
}

func childSAProposals(cfg handshake.Config, espSPI uint32) []ike.Proposal {
	return childSAProposalsWithDH(cfg, espSPI, 0)
}

func childSAProposalsWithDH(cfg handshake.Config, espSPI uint32, dhGroup uint16) []ike.Proposal {
	keyLens := uint16ValuesOrDefault(cfg.ChildEncryptionKeyLens, defaultEncryptionKeyLens)
	integrity := uint16ValuesOrDefault(cfg.ChildIntegrity, defaultChildIntegrity)
	transforms := make([]ike.Transform, 0, len(keyLens)+len(integrity)+2)
	for _, keyLen := range keyLens {
		transforms = append(transforms, aesCBCTransform(keyLen))
	}
	for _, integ := range integrity {
		transforms = append(transforms, ike.Transform{TransformType: transformTypeINTEG, ID: integ})
	}
	if dhGroup != 0 {
		transforms = append(transforms, ike.Transform{TransformType: transformTypeDH, ID: dhGroup})
	}
	transforms = append(transforms, ike.Transform{TransformType: transformTypeESN, ID: transformESNNoESN})
	return []ike.Proposal{
		{
			Number:     1,
			ProtocolID: proposalProtocolESP,
			SPI:        uint32Bytes(espSPI),
			Transforms: transforms,
		},
	}
}

func aesCBCTransform(keyLen uint16) ike.Transform {
	return ike.Transform{
		TransformType: transformTypeENCR,
		ID:            transformENCRAESCBC,
		Attributes:    []ike.Attribute{ike.NewTVAttribute(transformAttrKeyLength, keyLen)},
	}
}

func uint16ValuesOrDefault(values, defaults []uint16) []uint16 {
	if len(values) == 0 {
		return defaults
	}
	return values
}

func defaultIKEAuthInitPayloads(cfg handshake.Config, identity string, espSPI uint32) ([]ike.Payload, error) {
	if identity == "" {
		return nil, errors.New("identity is empty")
	}
	apn := strings.TrimSpace(cfg.APN)
	if apn == "" {
		apn = DefaultAPN
	}
	childSA := &ike.SecurityAssociationPayload{Proposals: childSAProposals(cfg, espSPI)}
	config := &ike.ConfigPayload{ConfigType: configTypeRequest, Attributes: pdnConfigRequestAttributes(cfg.PDNType)}
	for _, attr := range pcscfRequestAttributes(cfg) {
		config.Attributes = append(config.Attributes, ike.NewTLVAttribute(attr, nil))
	}
	selectors := ike.TrafficSelectorsAny()
	payloads := []ike.Payload{
		&ike.IDPayload{Tag: payloadTypeIDi, IDType: idTypeRFC822Addr, Data: []byte(identity)},
		&ike.IDPayload{Tag: payloadTypeIDr, IDType: idTypeFQDN, Data: []byte(apn)},
		config,
		childSA,
		&ike.TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: selectors},
		&ike.TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: selectors},
		&ike.NotifyPayload{ProtocolID: protocolIDUnset, NotifyType: notifyTypeEAPOnlyAuthentication},
	}
	if cfg.PCSCFRestoration {
		payloads = append(payloads, &ike.NotifyPayload{ProtocolID: protocolIDUnset, NotifyType: notifyTypePCSCFReselectionSupport})
	}
	if cfg.PDUSessionID != 0 {
		data, err := (n1ModeCapabilityNotifyData{PDUSessionID: cfg.PDUSessionID}).MarshalBinary()
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, &ike.NotifyPayload{ProtocolID: protocolIDUnset, NotifyType: notifyTypeN1ModeCapability, Data: data})
	}
	return payloads, nil
}

func pdnConfigRequestAttributes(pdnType PDNType) []ike.Attribute {
	attrs := make([]ike.Attribute, 0, 5)
	if pdnType != PDNTypeIPv6 {
		attrs = append(attrs,
			ike.NewTLVAttribute(configAttrInternalIPv4Address, nil),
			ike.NewTLVAttribute(configAttrInternalIPv4DNS, nil),
		)
	}
	if pdnType != PDNTypeIPv4 {
		attrs = append(attrs,
			ike.NewTLVAttribute(configAttrInternalIPv6Address, nil),
			ike.NewTLVAttribute(configAttrInternalIPv6DNS, nil),
		)
	}
	attrs = append(attrs, ike.NewTLVAttribute(configAttrTimeoutPeriodForLivenessCheck, nil))
	return attrs
}

func pdnTypeRestriction(payloads []ike.Payload) PDNType {
	for _, payload := range payloads {
		notify, ok := payload.(*ike.NotifyPayload)
		if !ok {
			continue
		}
		switch notify.NotifyType {
		case notifyTypePDNTypeIPv4OnlyAllowed:
			return PDNTypeIPv4
		case notifyTypePDNTypeIPv6OnlyAllowed:
			return PDNTypeIPv6
		}
	}
	return PDNTypeUnspecified
}

func pcscfConfigAttributes(cfg handshake.Config) (uint16, uint16) {
	pcscfIPv4Attr := cfg.PCSCFIPv4ConfigAttribute
	if pcscfIPv4Attr == 0 {
		pcscfIPv4Attr = configAttrPCSCFIPv4Address
	}
	pcscfIPv6Attr := cfg.PCSCFIPv6ConfigAttribute
	if pcscfIPv6Attr == 0 {
		pcscfIPv6Attr = configAttrPCSCFIPv6Address
	}
	return pcscfIPv4Attr, pcscfIPv6Attr
}

func pcscfRequestAttributes(cfg handshake.Config) []uint16 {
	pcscfIPv4Attr, pcscfIPv6Attr := pcscfConfigAttributes(cfg)
	candidates := []uint16{
		pcscfIPv4Attr,
		pcscfIPv6Attr,
		configAttrPCSCFIPv4Address,
		configAttrPCSCFIPv6Address,
	}

	attrs := make([]uint16, 0, len(candidates))
	for _, candidate := range candidates {
		if slices.Contains(attrs, candidate) {
			continue
		}
		attrs = append(attrs, candidate)
	}
	return attrs
}
