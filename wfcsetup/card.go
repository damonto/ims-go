package wfcsetup

import "strings"

type mncLengthCard interface {
	MNCLength() int
}

type gid1Card interface {
	GID1() string
}

func cardMNCLength(card Card) int {
	if card, ok := card.(mncLengthCard); ok {
		return card.MNCLength()
	}
	return 0
}

func cardGID1(card Card) string {
	if card, ok := card.(gid1Card); ok {
		return strings.TrimSpace(card.GID1())
	}
	return ""
}

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
	if !samePLMNDigits(match.MCC, match.MNC, card.MCC(), card.MNC(), cardMNCLength(card)) {
		return false
	}
	if strings.TrimSpace(match.GID1) == "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(match.GID1), cardGID1(card))
}

func matchAnySIM(card Card, matches []simMatch) bool {
	for _, match := range matches {
		if matchSIM(card, match) {
			return true
		}
	}
	return false
}
