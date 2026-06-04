package sms

import (
	"errors"
	"fmt"
	"unicode/utf16"

	"github.com/damonto/vowifi-go/ims/sip"
)

const (
	singleGSM7Limit = 160
	concatGSM7Limit = 153
	singleUCS2Units = 70
	concatUCS2Units = 67
)

const (
	ucs2HighSurrogateMin = 0xD800
	ucs2HighSurrogateMax = 0xDBFF
)

type userDataPart struct {
	udhi     bool
	pid      byte
	dcs      byte
	udl      int
	userData []byte
}

func buildUserDataParts(text string) ([]userDataPart, error) {
	gsm7, err := NewGSM7(text)
	if err == nil {
		return buildGSM7UserDataParts(gsm7)
	}
	parts := buildUCS2UserDataParts(UCS2(text))
	if parts == nil {
		return nil, errors.New("encoding SMS-SUBMIT: UCS2 message exceeds 255-part limit")
	}
	return parts, nil
}

func buildGSM7UserDataParts(gsm7 GSM7) ([]userDataPart, error) {
	if gsm7.SeptetCount() <= singleGSM7Limit {
		return []userDataPart{{dcs: tpDCSGSM7, udl: gsm7.SeptetCount(), userData: gsm7.Packed()}}, nil
	}
	chunks := splitGSM7Septets(gsm7.septets, concatGSM7Limit)
	if len(chunks) > 255 {
		return nil, fmt.Errorf("encoding SMS-SUBMIT: %d GSM7 segments exceed 255-part limit", len(chunks))
	}
	ref := byte(sip.RandomUint32())
	parts := make([]userDataPart, 0, len(chunks))
	for i, chunk := range chunks {
		header := buildConcatUDH8(ref, byte(len(chunks)), byte(i+1))
		packed, headerSeptets := packSeptetsWithHeader(header, chunk)
		parts = append(parts, userDataPart{udhi: true, dcs: tpDCSGSM7, udl: headerSeptets + len(chunk), userData: packed})
	}
	return parts, nil
}

func buildUCS2UserDataParts(text UCS2) []userDataPart {
	words := utf16.Encode([]rune(string(text)))
	if len(words) <= singleUCS2Units {
		userData := encodeUCS2Words(words)
		return []userDataPart{{dcs: tpDCSUCS2, udl: len(userData), userData: userData}}
	}
	chunks := splitUCS2Words(words, concatUCS2Units)
	if len(chunks) > 255 {
		return nil
	}
	ref := byte(sip.RandomUint32())
	parts := make([]userDataPart, 0, len(chunks))
	for i, chunk := range chunks {
		header := buildConcatUDH8(ref, byte(len(chunks)), byte(i+1))
		userData := append(header, encodeUCS2Words(chunk)...)
		parts = append(parts, userDataPart{udhi: true, dcs: tpDCSUCS2, udl: len(userData), userData: userData})
	}
	return parts
}

func encodeUserData(text string) ([]byte, byte, byte, error) {
	gsm7, err := NewGSM7(text)
	if err == nil {
		return gsm7.Packed(), tpDCSGSM7, byte(gsm7.SeptetCount()), nil
	}
	ucs2 := encodeUCS2(text)
	return ucs2, tpDCSUCS2, byte(len(ucs2)), nil
}

func splitGSM7Septets(septets []byte, limit int) [][]byte {
	parts := make([][]byte, 0, (len(septets)+limit-1)/limit)
	for len(septets) > 0 {
		end := min(len(septets), limit)
		if end < len(septets) && septets[end-1] == gsm7EscapeSeptet {
			end--
		}
		if end <= 0 {
			end = min(len(septets), limit)
		}
		parts = append(parts, append([]byte(nil), septets[:end]...))
		septets = septets[end:]
	}
	return parts
}

func splitUCS2Words(words []uint16, limit int) [][]uint16 {
	parts := make([][]uint16, 0, (len(words)+limit-1)/limit)
	for len(words) > 0 {
		end := min(len(words), limit)
		if end < len(words) && end > 0 && words[end-1] >= ucs2HighSurrogateMin && words[end-1] <= ucs2HighSurrogateMax {
			end--
		}
		if end <= 0 {
			end = min(len(words), limit)
		}
		parts = append(parts, append([]uint16(nil), words[:end]...))
		words = words[end:]
	}
	return parts
}
