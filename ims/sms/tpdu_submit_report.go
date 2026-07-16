package sms

import (
	"errors"
	"fmt"
)

func decodeSubmitReport(data []byte, failed bool) (SubmitReport, error) {
	if len(data) == 0 {
		return SubmitReport{}, errors.New("packet too short")
	}
	if data[0]&tpduMTIMask != tpduMTISubmit {
		return SubmitReport{}, fmt.Errorf("unexpected tp-mti 0x%02X", data[0]&tpduMTIMask)
	}
	report := SubmitReport{RawTPDU: append([]byte(nil), data...)}
	idx := 1 // TP-MTI and TP-UDHI
	if failed {
		if len(data[idx:]) < 1 {
			return SubmitReport{}, errors.New("missing failure cause")
		}
		report.FailureCause = data[idx]
		report.HasFailureCause = true
		if data[0]&tpduReportUnusedMask != 0 {
			report.FailureCause = tpFailureCauseUnspecified
			return report, nil
		}
		idx++
	}
	if len(data[idx:]) < 1 {
		return SubmitReport{}, errors.New("missing parameter indicator")
	}
	pi := data[idx]
	idx++
	for pi&tpduParameterIndicatorExtFlag != 0 {
		if len(data[idx:]) < 1 {
			return SubmitReport{}, errors.New("truncated parameter indicator")
		}
		pi = data[idx]
		idx++
	}
	// Only the first PI carries parameters defined by this release.
	firstPI := data[1]
	if failed {
		firstPI = data[2]
	}
	if len(data[idx:]) < tpduTimestampOctets {
		return SubmitReport{}, errors.New("missing service-centre timestamp")
	}
	var err error
	report.ServiceCenterTime, err = decodeTimestamp(data[idx : idx+tpduTimestampOctets])
	if err != nil {
		return SubmitReport{}, err
	}
	idx += tpduTimestampOctets
	if firstPI&tpduParameterIndicatorPID != 0 {
		if len(data[idx:]) < 1 {
			return SubmitReport{}, errors.New("missing protocol identifier")
		}
		report.ProtocolIdentifier = data[idx]
		report.HasProtocolIdentifier = true
		idx++
	}
	dcs := byte(tpDCSGSM7)
	if firstPI&tpduParameterIndicatorDCS != 0 {
		if len(data[idx:]) < 1 {
			return SubmitReport{}, errors.New("missing data coding scheme")
		}
		dcs = data[idx]
		report.DataCodingScheme = dcs
		report.HasDataCodingScheme = true
		idx++
	}
	if firstPI&tpduParameterIndicatorUDL != 0 {
		if len(data[idx:]) < 1 {
			return SubmitReport{}, errors.New("missing user data length")
		}
		udl := int(data[idx])
		report.UserDataLength = udl
		idx++
		octets, err := userDataOctets(udl, dcs)
		if err != nil {
			return SubmitReport{}, err
		}
		if len(data[idx:]) < octets {
			return SubmitReport{}, errors.New("truncated user data")
		}
		report.UserData = append([]byte(nil), data[idx:idx+octets]...)
		idx += octets
	}
	if idx != len(data) && firstPI&tpduParameterIndicatorReservedMask == 0 {
		return SubmitReport{}, fmt.Errorf("trailing data: %d octets", len(data)-idx)
	}
	return report, nil
}
