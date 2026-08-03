package sms

import (
	"encoding"
	"fmt"
)

var (
	_ encoding.BinaryAppender  = submitTPDU{}
	_ encoding.BinaryMarshaler = submitTPDU{}
)

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
	return tp.AppendBinary(nil)
}

func (tp submitTPDU) AppendBinary(dst []byte) ([]byte, error) {
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
	dst = append(dst, firstOctet, tp.Reference)
	dst = append(dst, destination...)
	dst = append(dst, tp.Part.pid, tp.Part.dcs, byte(tp.Part.udl))
	dst = append(dst, tp.Part.userData...)
	return dst, nil
}
