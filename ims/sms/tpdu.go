package sms

import (
	"errors"
	"fmt"
)

const (
	tpduMTIDeliverReport = 0x00
	tpduMTIDeliver       = 0x00
	tpduMTISubmit        = 0x01
	tpduMTIStatusReport  = 0x02
	tpduMTIReserved      = 0x03
	tpduMTIMask          = 0x03
)

const (
	tpduRejectDuplicatesFlag      = 0x04
	tpduNoMoreMessagesFlag        = 0x04
	tpduLoopPreventionFlag        = 0x08
	tpduStatusReportRequestFlag   = 0x20
	tpduStatusReportFromCommand   = 0x20
	tpduUserDataHeaderFlag        = 0x40
	tpduParameterIndicatorNone    = 0x00
	tpduParameterIndicatorPID     = 0x01
	tpduParameterIndicatorDCS     = 0x02
	tpduParameterIndicatorUDL     = 0x04
	tpduParameterIndicatorExtFlag = 0x80
	tpduTimestampOctets           = 7
	tpduStatusReportTimeStatusLen = tpduTimestampOctets*2 + 1
)

const (
	tpPIDUSIMDataDownload = 0x7F
	tpDCSGSM7             = 0x00
	tpDCSUCS2             = 0x08
)

const (
	dcsGeneralCodingGroupMask = 0xC0
	dcsGeneralCodingGroup     = 0x00
	dcsMessageClassGroupMask  = 0xF0
	dcsMessageClassGroup      = 0xF0
	dcsCompressedFlag         = 0x20
	dcsClassFlag              = 0x10
	dcsAlphabetShift          = 2
	dcsAlphabetMask           = 0x03
	dcsClassMask              = 0x03
	dcsMessageClassSIM        = 2
	dcsAlphabetGSM7           = 0x00
	dcsAlphabet8Bit           = 0x01
	dcsAlphabetUCS2           = 0x02
)

var tpduZeroTimestamp [tpduTimestampOctets]byte

type userDataEncoding byte

const (
	userDataEncodingGSM7 userDataEncoding = iota
	userDataEncoding8Bit
	userDataEncodingUCS2
)

func userDataEncodingFromAlphabetBits(bits, dcs byte) (userDataEncoding, error) {
	switch bits {
	case dcsAlphabetGSM7:
		return userDataEncodingGSM7, nil
	case dcsAlphabet8Bit:
		return userDataEncoding8Bit, nil
	case dcsAlphabetUCS2:
		return userDataEncodingUCS2, nil
	default:
		return 0, fmt.Errorf("decoding SMS DCS: reserved alphabet bits in dcs 0x%02X", dcs)
	}
}

func userDataEncodingFromDCS(dcs byte) (userDataEncoding, error) {
	switch {
	case dcs&dcsGeneralCodingGroupMask == dcsGeneralCodingGroup:
		if dcs&dcsCompressedFlag != 0 {
			return 0, fmt.Errorf("decoding SMS DCS: compressed dcs 0x%02X is unsupported", dcs)
		}
		return userDataEncodingFromAlphabetBits((dcs>>dcsAlphabetShift)&dcsAlphabetMask, dcs)
	case dcs&dcsMessageClassGroupMask == dcsMessageClassGroup:
		return userDataEncodingFromAlphabetBits((dcs>>dcsAlphabetShift)&dcsAlphabetMask, dcs)
	default:
		return 0, fmt.Errorf("decoding SMS DCS: unsupported dcs 0x%02X", dcs)
	}
}

func dcsMessageClass(dcs byte) int {
	switch {
	case dcs&dcsGeneralCodingGroupMask == dcsGeneralCodingGroup:
		if dcs&dcsClassFlag == 0 {
			return -1
		}
		return int(dcs & dcsClassMask)
	case dcs&dcsMessageClassGroupMask == dcsMessageClassGroup:
		return int(dcs & dcsClassMask)
	default:
		return -1
	}
}

func encodeSubmit(reference byte, to, text string) ([]byte, error) {
	parts, err := buildUserDataParts(text)
	if err != nil {
		return nil, err
	}
	if len(parts) != 1 {
		return nil, fmt.Errorf("encoding SMS-SUBMIT: message requires %d segments", len(parts))
	}
	return newSubmitTPDU(submitTPDUConfig{
		Reference:   reference,
		Destination: to,
		Part:        parts[0],
	}).MarshalBinary()
}

func decodeDeliver(data []byte) (Incoming, error) {
	var deliver deliverTPDU
	if err := deliver.UnmarshalBinary(data); err != nil {
		return Incoming{}, err
	}
	return deliver.Message, nil
}

func decodeStatusReport(data []byte) (StatusReport, error) {
	var report statusReportTPDU
	if err := report.UnmarshalBinary(data); err != nil {
		return StatusReport{}, err
	}
	return report.Message, nil
}

func buildDeliver(from, text string) ([]byte, error) {
	parts, err := buildUserDataParts(text)
	if err != nil {
		return nil, err
	}
	if len(parts) != 1 {
		return nil, fmt.Errorf("building SMS-DELIVER: message requires %d segments", len(parts))
	}
	return newDeliverTPDU(from, parts[0]).MarshalBinary()
}

func tpduMessageType(data []byte) (byte, error) {
	if len(data) == 0 {
		return 0, errors.New("decoding SMS-TPDU: packet too short")
	}
	return data[0] & tpduMTIMask, nil
}
