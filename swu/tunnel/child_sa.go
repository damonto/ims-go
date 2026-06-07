package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/damonto/vowifi-go/swu/esp"
	"github.com/damonto/vowifi-go/swu/handshake"
	"github.com/damonto/vowifi-go/swu/ike"
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
	addresses := tunnelAddresses(config.Attributes, cfg.PCSCFIPv4ConfigAttribute, cfg.PCSCFIPv6ConfigAttribute)
	switch {
	case addresses.internalIPv6 != nil:
		tunnel.InnerIP = addresses.internalIPv6
		tunnel.PCSCFIPs = cloneIPList(addresses.pcscfIPv6)
	case addresses.internalIPv4 != nil:
		tunnel.InnerIP = addresses.internalIPv4
		tunnel.PCSCFIPs = cloneIPList(addresses.pcscfIPv4)
	default:
		return errors.New("parsing ike_auth response: internal ip is missing")
	}
	tunnel.PCSCFIP = nil
	if len(tunnel.PCSCFIPs) != 0 {
		tunnel.PCSCFIP = append(net.IP(nil), tunnel.PCSCFIPs[0]...)
	}
	return nil
}

type tunnelAddressSet struct {
	internalIPv4 net.IP
	internalIPv6 net.IP
	pcscfIPv4    []net.IP
	pcscfIPv6    []net.IP
}

const (
	configAttrInternalIPv6AddressLen = net.IPv6len + 1
	configAttrInternalIPv6SubnetLen  = net.IPv6len + 1
)

func tunnelAddresses(attrs []ike.Attribute, pcscfIPv4Attr, pcscfIPv6Attr uint16) tunnelAddressSet {
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
			if len(attr.Value) == net.IPv4len {
				addresses.internalIPv4 = append(net.IP(nil), attr.Value...)
			}
		case configAttrInternalIPv6Address:
			if len(attr.Value) == configAttrInternalIPv6AddressLen {
				addresses.internalIPv6 = append(net.IP(nil), attr.Value[:net.IPv6len]...)
			}
		case configAttrInternalIPv6Subnet:
			if addresses.internalIPv6 == nil && len(attr.Value) == configAttrInternalIPv6SubnetLen {
				addresses.internalIPv6 = append(net.IP(nil), attr.Value[:net.IPv6len]...)
			}
		}

		matchesPCSCFIPv4 := attr.Type == pcscfIPv4Attr || attr.Type == configAttrPCSCFIPv4Address
		matchesPCSCFIPv6 := attr.Type == pcscfIPv6Attr || attr.Type == configAttrPCSCFIPv6Address
		switch {
		case matchesPCSCFIPv4 && matchesPCSCFIPv6 && len(attr.Value) == net.IPv6len:
			addresses.pcscfIPv6 = appendUniqueIP(addresses.pcscfIPv6, attr.Value)
		case matchesPCSCFIPv4:
			if len(attr.Value) == net.IPv4len {
				addresses.pcscfIPv4 = appendUniqueIP(addresses.pcscfIPv4, attr.Value)
			}
		case matchesPCSCFIPv6:
			if len(attr.Value) == net.IPv6len {
				addresses.pcscfIPv6 = appendUniqueIP(addresses.pcscfIPv6, attr.Value)
			}
		}
	}
	return addresses
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
	proposals := make([]ike.Proposal, 0, len(keyLens)*len(integrity))
	for _, keyLen := range keyLens {
		for _, integ := range integrity {
			transforms := []ike.Transform{
				aesCBCTransform(keyLen),
				{TransformType: transformTypeINTEG, ID: integ},
			}
			if dhGroup != 0 {
				transforms = append(transforms, ike.Transform{TransformType: transformTypeDH, ID: dhGroup})
			}
			transforms = append(transforms, ike.Transform{TransformType: transformTypeESN, ID: transformESNNoESN})
			proposals = append(proposals, ike.Proposal{
				Number:     byte(len(proposals) + 1),
				ProtocolID: proposalProtocolESP,
				SPI:        uint32Bytes(espSPI),
				Transforms: transforms,
			})
		}
	}
	return proposals
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
	config := &ike.ConfigPayload{ConfigType: configTypeRequest, Attributes: []ike.Attribute{
		ike.NewTLVAttribute(configAttrInternalIPv4Address, nil),
		ike.NewTLVAttribute(configAttrInternalIPv4DNS, nil),
		ike.NewTLVAttribute(configAttrInternalIPv6Address, nil),
		ike.NewTLVAttribute(configAttrInternalIPv6DNS, nil),
		ike.NewTLVAttribute(configAttrTimeoutPeriodForLivenessCheck, nil),
	}}
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
