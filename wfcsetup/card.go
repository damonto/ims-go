package wfcsetup

import "strings"

func samePLMNDigits(profileMCC, profileMNC, cardMCC, cardMNC string, cardMNCLength int) bool {
	profileMCC = strings.TrimSpace(profileMCC)
	profileMNC = strings.TrimSpace(profileMNC)
	cardMCC = strings.TrimSpace(cardMCC)
	cardMNC = strings.TrimSpace(cardMNC)
	if profileMCC != cardMCC {
		return false
	}
	if profileMNC == cardMNC {
		return true
	}
	if sameZeroPaddedMNC(profileMNC, cardMNC) {
		return true
	}
	if cardMNCLength == 2 && len(profileMNC) == 3 && profileMNC[0] == '0' {
		return strings.TrimLeft(profileMNC, "0") == cardMNC
	}
	if cardMNCLength == 3 && len(profileMNC) == 2 {
		return cardMNC == "0"+profileMNC
	}
	return false
}

func sameZeroPaddedMNC(a, b string) bool {
	if len(a)+1 == len(b) && b[0] == '0' {
		return a == b[1:]
	}
	if len(b)+1 == len(a) && a[0] == '0' {
		return a[1:] == b
	}
	return false
}

type simMatch struct {
	MCC  string
	MNC  string
	GID1 string
}

func matchSIM(card Card, match simMatch) bool {
	if !samePLMNDigits(match.MCC, match.MNC, card.MCC(), card.MNC(), card.MNCLength()) {
		return false
	}
	if strings.TrimSpace(match.GID1) == "" {
		return true
	}
	return sameGIDPrefix(match.GID1, card.GID1())
}

func sameGIDPrefix(profileGID, cardGID string) bool {
	profileGID = normalizeGID(profileGID)
	cardGID = normalizeGID(cardGID)
	if profileGID == "" || cardGID == "" {
		return false
	}
	return strings.HasPrefix(cardGID, profileGID)
}

func normalizeGID(gid string) string {
	gid = strings.TrimSpace(gid)
	gid = strings.TrimPrefix(gid, "0x")
	gid = strings.TrimPrefix(gid, "0X")
	return strings.ToUpper(gid)
}

func matchAnySIM(card Card, matches []simMatch) bool {
	for _, match := range matches {
		if matchSIM(card, match) {
			return true
		}
	}
	return false
}
