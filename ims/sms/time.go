package sms

import (
	"errors"
	"fmt"
	"time"
)

const (
	decimalDigitMax     = 9
	timestampPivotYear  = 70
	timestampCentury20  = 1900
	timestampCentury21  = 2000
	timeZoneSignFlag    = 0x08
	timeZoneValueMask   = 0xF7
	timeZoneQuarterSecs = 15 * 60
)

func decodeDecimalByte(b byte) int {
	tens := int(b & semiOctetMask)
	ones := int((b >> 4) & semiOctetMask)
	if tens > decimalDigitMax {
		tens = 0
	}
	if ones > decimalDigitMax {
		ones = 0
	}
	return tens*10 + ones
}

func decodeTimestamp(data []byte) (time.Time, error) {
	if len(data) < tpduTimestampOctets {
		return time.Time{}, errors.New("decoding SMS timestamp: packet too short")
	}
	year := decodeDecimalByte(data[0])
	if year >= timestampPivotYear {
		year += timestampCentury20
	} else {
		year += timestampCentury21
	}
	month := decodeDecimalByte(data[1])
	if month < 1 || month > 12 {
		return time.Time{}, fmt.Errorf("decoding SMS timestamp: invalid month %d", month)
	}
	day := decodeDecimalByte(data[2])
	if day < 1 || day > 31 {
		return time.Time{}, fmt.Errorf("decoding SMS timestamp: invalid day %d", day)
	}
	hour := decodeDecimalByte(data[3])
	if hour > 23 {
		return time.Time{}, fmt.Errorf("decoding SMS timestamp: invalid hour %d", hour)
	}
	minute := decodeDecimalByte(data[4])
	if minute > 59 {
		return time.Time{}, fmt.Errorf("decoding SMS timestamp: invalid minute %d", minute)
	}
	second := decodeDecimalByte(data[5])
	if second > 59 {
		return time.Time{}, fmt.Errorf("decoding SMS timestamp: invalid second %d", second)
	}

	zone := data[6]
	negative := zone&timeZoneSignFlag != 0
	quarters := decodeDecimalByte(zone & timeZoneValueMask)
	offset := quarters * timeZoneQuarterSecs
	if negative {
		offset = -offset
	}
	location := time.FixedZone("", offset)
	ts := time.Date(year, time.Month(month), day, hour, minute, second, 0, location)
	if ts.Year() != year || ts.Month() != time.Month(month) || ts.Day() != day || ts.Hour() != hour || ts.Minute() != minute || ts.Second() != second {
		return time.Time{}, fmt.Errorf("decoding SMS timestamp: invalid calendar date %04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, minute, second)
	}
	return ts, nil
}

func encodeTimestamp(ts time.Time) []byte {
	_, offset := ts.Zone()
	negative := offset < 0
	if negative {
		offset = -offset
	}
	quarters := offset / timeZoneQuarterSecs
	timeZone := byte(0)
	if digits := swapDigits(fmt.Sprintf("%02d", quarters)); len(digits) > 0 {
		timeZone = digits[0]
	}
	if negative {
		timeZone |= timeZoneSignFlag
	}

	return []byte{
		swapDigits(fmt.Sprintf("%02d", ts.Year()%100))[0],
		swapDigits(fmt.Sprintf("%02d", ts.Month()))[0],
		swapDigits(fmt.Sprintf("%02d", ts.Day()))[0],
		swapDigits(fmt.Sprintf("%02d", ts.Hour()))[0],
		swapDigits(fmt.Sprintf("%02d", ts.Minute()))[0],
		swapDigits(fmt.Sprintf("%02d", ts.Second()))[0],
		timeZone,
	}
}
