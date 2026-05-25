package protocol

import "fmt"

type InternalOpenRequest struct {
	TransactionID uint16
	DevicePath    []byte
}

func (r InternalOpenRequest) Request() Request {
	return Request{
		TransactionID: r.TransactionID,
		MessageID:     QMICtlInternalProxyOpen,
		Service:       QMIServiceControl,
		TLVs: TLVs{
			{Type: 0x01, Len: uint16(len(r.DevicePath)), Value: r.DevicePath},
		},
	}
}

type AllocateClientIDRequest struct {
	TransactionID uint16
	ServiceType   ServiceType
}

func (r AllocateClientIDRequest) Request() Request {
	return Request{
		TransactionID: r.TransactionID,
		MessageID:     QMICtlCmdAllocateClientID,
		Service:       QMIServiceControl,
		TLVs: TLVs{
			{Type: 0x01, Len: 1, Value: []byte{byte(r.ServiceType)}},
		},
	}
}

type AllocateClientIDResponse struct {
	ClientID uint8
}

func (r *AllocateClientIDResponse) UnmarshalResponse(tlvs TLVs) error {
	if value, ok := tlvs.Find(0x01); ok && len(value.Value) >= 2 {
		r.ClientID = value.Value[1]
		return nil
	}
	return fmt.Errorf("could not find allocated client ID in response")
}

type ReleaseClientIDRequest struct {
	ClientID      uint8
	TransactionID uint16
	ServiceType   ServiceType
}

func (r ReleaseClientIDRequest) Request() Request {
	return Request{
		TransactionID: r.TransactionID,
		MessageID:     QMICtlCmdReleaseClientID,
		Service:       QMIServiceControl,
		TLVs: TLVs{
			{Type: 0x01, Len: 2, Value: []byte{byte(r.ServiceType), r.ClientID}},
		},
	}
}

type ReleaseClientIDResponse struct {
	ClientID uint8
}

func (r *ReleaseClientIDResponse) UnmarshalResponse(tlvs TLVs) error {
	if value, ok := tlvs.Find(0x01); ok && len(value.Value) >= 2 {
		r.ClientID = value.Value[1]
		return nil
	}
	return fmt.Errorf("could not find released client ID in response")
}
