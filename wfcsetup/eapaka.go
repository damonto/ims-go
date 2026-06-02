package wfcsetup

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/damonto/vowifi-go/eapaka"
)

func eapAKAChallengeResponse(ctx context.Context, card Card, challengeText string) (string, error) {
	return eapAKAChallengeResponseForIdentity(ctx, card, imsiEAP(card), challengeText, "eap-aka")
}

func eapAKAChallengeResponseForIdentity(ctx context.Context, card Card, identity, challengeText, label string) (string, error) {
	challenge, err := decodeEAPAKAChallenge(challengeText)
	if err != nil {
		return "", fmt.Errorf("decoding %s challenge: %w", label, err)
	}
	authenticate := card.AKA
	if eapCard, ok := card.(eapAKACard); ok {
		authenticate = eapCard.EAPAKA
	}
	aka, err := authenticate(ctx, challenge.RAND, challenge.AUTN)
	if err != nil {
		return "", fmt.Errorf("authenticating %s challenge: %w", label, err)
	}
	if aka.Reject {
		return "", fmt.Errorf("USIM rejected %s challenge", label)
	}
	text, err := buildEAPAKAChallengeResponseText(challenge, aka.RES, aka.CK, aka.IK, aka.AUTS, identity)
	if err != nil {
		return "", fmt.Errorf("building %s challenge response: %w", label, err)
	}
	return text, nil
}

func decodeEAPAKAChallenge(text string) (eapaka.AKAChallenge, error) {
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return eapaka.AKAChallenge{}, fmt.Errorf("decoding base64: %w", err)
	}
	var challenge eapaka.AKAChallenge
	if err := challenge.UnmarshalBinaryWithOptions(data, eapaka.AKAChallengeParseOptions{AllowMissingMAC: true}); err != nil {
		return eapaka.AKAChallenge{}, err
	}
	return challenge, nil
}

func buildEAPAKAChallengeResponseText(challenge eapaka.AKAChallenge, res, ck, ik, auts []byte, identity string) (string, error) {
	data, err := buildEAPAKAChallengeResponse(challenge, res, ck, ik, auts, identity)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func buildEAPAKAChallengeResponse(challenge eapaka.AKAChallenge, res, ck, ik, auts []byte, identity string) ([]byte, error) {
	if len(auts) != 0 {
		return eapaka.BuildAKASynchronizationFailure(challenge.Identifier, auts)
	}
	if len(res) == 0 {
		return nil, errors.New("RES is required")
	}
	if len(ck) == 0 {
		return nil, errors.New("CK is required")
	}
	if len(ik) == 0 {
		return nil, errors.New("IK is required")
	}
	keys, err := eapaka.DeriveAKAKeys([]byte(identity), ik, ck)
	if err != nil {
		return nil, err
	}
	return eapaka.BuildAKAResponse(challenge.Identifier, res, keys.AUT)
}

func imsiEAP(card Card) string {
	imsi := strings.TrimSpace(card.IMSI())
	mcc := strings.TrimSpace(card.MCC())
	mnc := strings.TrimSpace(card.MNC())
	if len(mnc) == 2 {
		mnc = "0" + mnc
	}
	if imsi == "" || mcc == "" || mnc == "" {
		return ""
	}
	return "0" + imsi + "@nai.epc.mnc" + mnc + ".mcc" + mcc + ".3gppnetwork.org"
}
