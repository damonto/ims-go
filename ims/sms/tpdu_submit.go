package sms

import (
	"encoding"
	"fmt"
)

var _ encoding.BinaryMarshaler = submitTPDU{}

type submitTPDU struct {
	Reference           byte
	Destination         string
	Part                userDataPart
	RejectDuplicates    bool
	RequestStatusReport bool
}

type submitTPDUConfig struct {
	Reference           byte
	Destination         string
	Part                userDataPart
	RejectDuplicates    bool
	RequestStatusReport bool
}

func newSubmitTPDU(cfg submitTPDUConfig) submitTPDU {
	return submitTPDU{
		Reference:           cfg.Reference,
		Destination:         cfg.Destination,
		Part:                cfg.Part,
		RejectDuplicates:    cfg.RejectDuplicates,
		RequestStatusReport: cfg.RequestStatusReport,
	}
}

func (tp submitTPDU) MarshalBinary() ([]byte, error) {
	destination, err := encodeTPAddress(tp.Destination)
	if err != nil {
		return nil, fmt.Errorf("marshalling SMS-SUBMIT destination address: %w", err)
	}
	firstOctet := byte(tpduMTISubmit)
	if tp.RejectDuplicates {
		firstOctet |= tpduRejectDuplicatesFlag
	}
	if tp.RequestStatusReport {
		firstOctet |= tpduStatusReportRequestFlag
	}
	if tp.Part.udhi {
		firstOctet |= tpduUserDataHeaderFlag
	}
	payload := make([]byte, 0, 32+len(tp.Part.userData))
	payload = append(payload, firstOctet)
	payload = append(payload, tp.Reference)
	payload = append(payload, destination...)
	payload = append(payload, tp.Part.pid)
	payload = append(payload, tp.Part.dcs)
	payload = append(payload, byte(tp.Part.udl))
	payload = append(payload, tp.Part.userData...)
	return payload, nil
}
