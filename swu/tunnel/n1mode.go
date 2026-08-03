package tunnel

import (
	"encoding"
	"fmt"
)

var (
	_ encoding.BinaryAppender    = n1ModeCapabilityNotifyData{}
	_ encoding.BinaryMarshaler   = n1ModeCapabilityNotifyData{}
	_ encoding.BinaryUnmarshaler = (*n1ModeCapabilityNotifyData)(nil)
	_ encoding.BinaryAppender    = n1ModeInformationNotifyData{}
	_ encoding.BinaryMarshaler   = n1ModeInformationNotifyData{}
	_ encoding.BinaryUnmarshaler = (*n1ModeInformationNotifyData)(nil)
	_ encoding.BinaryAppender    = n1ModeSNSSAIPlmnIDNotifyData{}
	_ encoding.BinaryMarshaler   = n1ModeSNSSAIPlmnIDNotifyData{}
	_ encoding.BinaryUnmarshaler = (*n1ModeSNSSAIPlmnIDNotifyData)(nil)
)

const (
	n1ModeValueLenFieldLen = 1
	n1ModePDUSessionIDLen  = 1
	n1ModePlmnIDLen        = 3
)

type n1ModeCapabilityNotifyData struct {
	PDUSessionID byte
}

func (d n1ModeCapabilityNotifyData) MarshalBinary() ([]byte, error) {
	return d.AppendBinary(nil)
}

func (d n1ModeCapabilityNotifyData) AppendBinary(dst []byte) ([]byte, error) {
	if d.PDUSessionID == 0 {
		return nil, fmt.Errorf("encoding N1_MODE_CAPABILITY notify: pdu session id is unset")
	}
	return append(dst, n1ModePDUSessionIDLen, d.PDUSessionID), nil
}

func (d *n1ModeCapabilityNotifyData) UnmarshalBinary(data []byte) error {
	if len(data) != n1ModeValueLenFieldLen+n1ModePDUSessionIDLen {
		return fmt.Errorf("parsing N1_MODE_CAPABILITY notify: data length %d does not match %d", len(data), n1ModeValueLenFieldLen+n1ModePDUSessionIDLen)
	}
	if data[0] != n1ModePDUSessionIDLen {
		return fmt.Errorf("parsing N1_MODE_CAPABILITY notify: value length %d does not match %d", data[0], n1ModePDUSessionIDLen)
	}
	if data[1] == 0 {
		return fmt.Errorf("parsing N1_MODE_CAPABILITY notify: pdu session id is unset")
	}
	d.PDUSessionID = data[1]
	return nil
}

type n1ModeInformationNotifyData struct {
	SNSSAI []byte
}

func (d n1ModeInformationNotifyData) MarshalBinary() ([]byte, error) {
	return d.AppendBinary(nil)
}

func (d n1ModeInformationNotifyData) AppendBinary(dst []byte) ([]byte, error) {
	if len(d.SNSSAI) > 0xff {
		return nil, fmt.Errorf("encoding N1_MODE_INFORMATION notify: s-nssai length %d exceeds 255", len(d.SNSSAI))
	}
	dst = append(dst, byte(len(d.SNSSAI)))
	dst = append(dst, d.SNSSAI...)
	return dst, nil
}

func (d *n1ModeInformationNotifyData) UnmarshalBinary(data []byte) error {
	if len(data) < n1ModeValueLenFieldLen {
		return fmt.Errorf("parsing N1_MODE_INFORMATION notify: data length %d does not include length field", len(data))
	}
	valueLen := int(data[0])
	if len(data) != n1ModeValueLenFieldLen+valueLen {
		return fmt.Errorf("parsing N1_MODE_INFORMATION notify: s-nssai length %d does not match %d", valueLen, len(data)-n1ModeValueLenFieldLen)
	}
	d.SNSSAI = append([]byte(nil), data[n1ModeValueLenFieldLen:]...)
	return nil
}

type n1ModeSNSSAIPlmnIDNotifyData struct {
	PLMNID []byte
}

func (d n1ModeSNSSAIPlmnIDNotifyData) MarshalBinary() ([]byte, error) {
	return d.AppendBinary(nil)
}

func (d n1ModeSNSSAIPlmnIDNotifyData) AppendBinary(dst []byte) ([]byte, error) {
	if len(d.PLMNID) != n1ModePlmnIDLen {
		return nil, fmt.Errorf("encoding N1_MODE_S_NSSAI_PLMN_ID notify: plmn id length %d does not match %d", len(d.PLMNID), n1ModePlmnIDLen)
	}
	dst = append(dst, n1ModePlmnIDLen)
	dst = append(dst, d.PLMNID...)
	return dst, nil
}

func (d *n1ModeSNSSAIPlmnIDNotifyData) UnmarshalBinary(data []byte) error {
	if len(data) != n1ModeValueLenFieldLen+n1ModePlmnIDLen {
		return fmt.Errorf("parsing N1_MODE_S_NSSAI_PLMN_ID notify: data length %d does not match %d", len(data), n1ModeValueLenFieldLen+n1ModePlmnIDLen)
	}
	if data[0] != n1ModePlmnIDLen {
		return fmt.Errorf("parsing N1_MODE_S_NSSAI_PLMN_ID notify: value length %d does not match %d", data[0], n1ModePlmnIDLen)
	}
	d.PLMNID = append([]byte(nil), data[n1ModeValueLenFieldLen:]...)
	return nil
}
