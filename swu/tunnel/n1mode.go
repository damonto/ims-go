package tunnel

import (
	"encoding"
	"fmt"
)

var (
	_ encoding.BinaryMarshaler   = n1ModeCapabilityNotifyData{}
	_ encoding.BinaryUnmarshaler = (*n1ModeCapabilityNotifyData)(nil)
	_ encoding.BinaryMarshaler   = n1ModeInformationNotifyData{}
	_ encoding.BinaryUnmarshaler = (*n1ModeInformationNotifyData)(nil)
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
	if d.PDUSessionID == 0 {
		return nil, fmt.Errorf("encoding N1_MODE_CAPABILITY notify: pdu session id is unset")
	}
	return []byte{n1ModePDUSessionIDLen, d.PDUSessionID}, nil
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
	if len(d.SNSSAI) > 0xff {
		return nil, fmt.Errorf("encoding N1_MODE_INFORMATION notify: s-nssai length %d exceeds 255", len(d.SNSSAI))
	}
	out := make([]byte, n1ModeValueLenFieldLen+len(d.SNSSAI))
	out[0] = byte(len(d.SNSSAI))
	copy(out[n1ModeValueLenFieldLen:], d.SNSSAI)
	return out, nil
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
	if len(d.PLMNID) != n1ModePlmnIDLen {
		return nil, fmt.Errorf("encoding N1_MODE_S_NSSAI_PLMN_ID notify: plmn id length %d does not match %d", len(d.PLMNID), n1ModePlmnIDLen)
	}
	out := make([]byte, n1ModeValueLenFieldLen+n1ModePlmnIDLen)
	out[0] = n1ModePlmnIDLen
	copy(out[n1ModeValueLenFieldLen:], d.PLMNID)
	return out, nil
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
