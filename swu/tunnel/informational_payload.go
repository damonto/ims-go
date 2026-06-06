package tunnel

import (
	"fmt"
	"net"
	"slices"

	"github.com/damonto/vowifi-go/swu/ike"
)

const minCookie2NotifyDataLength = 8

func buildDeviceIdentityResponsePayload(payloads []ike.Payload, identity string) (*ike.NotifyPayload, bool, error) {
	notify := ike.FindNotifyPayload(payloads, notifyTypeDeviceIdentity)
	if notify == nil {
		return nil, false, nil
	}
	var request ike.DeviceIdentity
	if err := request.UnmarshalBinary(notify.Data); err != nil {
		return nil, false, err
	}
	if len(request.Value) != 0 {
		return nil, false, nil
	}
	response, err := ike.NewDeviceIdentity(identity, request.Type)
	if err != nil {
		return nil, false, err
	}
	data, err := response.MarshalBinary()
	if err != nil {
		return nil, false, err
	}
	return &ike.NotifyPayload{ProtocolID: protocolIDUnset, NotifyType: notifyTypeDeviceIdentity, Data: data}, true, nil
}

func appendCookie2ResponsePayloads(responsePayloads []ike.Payload, payloads []ike.Payload) ([]ike.Payload, error) {
	for _, payload := range payloads {
		notify, ok := payload.(*ike.NotifyPayload)
		if !ok || notify.NotifyType != notifyTypeCookie2 {
			continue
		}
		if len(notify.Data) < minCookie2NotifyDataLength || len(notify.Data) > maxCookieNotifyDataLength {
			return nil, fmt.Errorf("parsing informational cookie2: invalid COOKIE2 length %d", len(notify.Data))
		}
		responsePayloads = append(responsePayloads, &ike.NotifyPayload{
			ProtocolID: protocolIDUnset,
			NotifyType: notifyTypeCookie2,
			Data:       append([]byte(nil), notify.Data...),
		})
	}
	return responsePayloads, nil
}

func buildInformationalConfigReply(state informationalState, payloads []ike.Payload) (*ike.ConfigPayload, informationalAction) {
	request := ike.FindConfigPayload(payloads)
	if request == nil || request.ConfigType != configTypeRequest {
		return nil, informationalAction{}
	}
	attrs := make([]ike.Attribute, 0, len(request.Attributes))
	action := informationalAction{}
	if state.cfg.DisablePCSCFRestoration {
		state.cfg.PCSCFIPv4ConfigAttribute = 0
		state.cfg.PCSCFIPv6ConfigAttribute = 0
	}
	pcscfReplyTypes := pcscfReselectionReplyTypes(request.Attributes, state.cfg)
	for _, attrType := range pcscfReplyTypes {
		attrs = append(attrs, ike.NewTLVAttribute(attrType, nil))
	}
	if len(pcscfReplyTypes) != 0 {
		if info, ok := pcscfReselectionInfo(state.info, request.Attributes, state.cfg); ok {
			action.pcscfReselection = true
			action.pcscfInfo = info
		}
	}
	if len(attrs) == 0 {
		return nil, informationalAction{}
	}
	return &ike.ConfigPayload{ConfigType: configTypeReply, Attributes: attrs}, action
}

func pcscfReselectionReplyTypes(attrs []ike.Attribute, cfg Config) []uint16 {
	if cfg.DisablePCSCFRestoration {
		return nil
	}
	pcscfIPv4Attr, pcscfIPv6Attr := pcscfConfigAttributes(handshakeConfig(cfg))
	replyTypes := make([]uint16, 0, 2)
	for _, attr := range attrs {
		if attr.Type != pcscfIPv4Attr && attr.Type != pcscfIPv6Attr && attr.Type != configAttrPCSCFIPv4Address && attr.Type != configAttrPCSCFIPv6Address {
			continue
		}
		if !containsUint16(replyTypes, attr.Type) {
			replyTypes = append(replyTypes, attr.Type)
		}
	}
	return replyTypes
}

func pcscfReselectionInfo(previous Info, attrs []ike.Attribute, cfg Config) (Info, bool) {
	pcscfIPv4Attr, pcscfIPv6Attr := pcscfConfigAttributes(handshakeConfig(cfg))
	addresses := tunnelAddresses(attrs, pcscfIPv4Attr, pcscfIPv6Attr)
	ips := make([]net.IP, 0, len(addresses.pcscfIPv6)+len(addresses.pcscfIPv4))
	ips = append(ips, addresses.pcscfIPv6...)
	ips = append(ips, addresses.pcscfIPv4...)
	if len(ips) == 0 {
		return Info{}, false
	}
	return pcscfInfoFromAddresses(previous, ips), true
}

func containsUint16(values []uint16, target uint16) bool {
	return slices.Contains(values, target)
}

func buildInformationalResponsePayloads(state informationalState, payloads []ike.Payload, identity string) ([]ike.Payload, informationalAction, error) {
	if responsePayloads, action, ok, err := buildDeleteResponsePayloads(state, payloads); ok || err != nil {
		return responsePayloads, action, err
	}
	responsePayloads := make([]ike.Payload, 0, 2)
	var err error
	responsePayloads, err = appendCookie2ResponsePayloads(responsePayloads, payloads)
	if err != nil {
		return nil, informationalAction{}, err
	}
	deviceIdentityPayload, ok, err := buildDeviceIdentityResponsePayload(payloads, identity)
	if err != nil {
		return nil, informationalAction{}, fmt.Errorf("building informational device identity: %w", err)
	}
	if ok {
		responsePayloads = append(responsePayloads, deviceIdentityPayload)
	}
	if configReply, configAction := buildInformationalConfigReply(state, payloads); configReply != nil {
		responsePayloads = append(responsePayloads, configReply)
		if configAction.pcscfReselection {
			return responsePayloads, configAction, nil
		}
	}
	return responsePayloads, informationalAction{}, nil
}
