package wfcsetup

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	eapAKACodeRequest  = 0x01
	eapAKACodeResponse = 0x02
	eapAKAType         = 0x17

	eapAKASubtypeChallenge   = 0x01
	eapAKASubtypeSyncFailure = 0x04

	eapAKAAttributeRand = 0x01
	eapAKAAttributeAutn = 0x02
	eapAKAAttributeRes  = 0x03
	eapAKAAttributeAuts = 0x04
	eapAKAAttributeMAC  = 0x0b

	eapAKAHeaderLen          = 8
	eapAKAAttributeHeaderLen = 4
	eapAKABitsPerByte        = 8
	eapAKAChallengeValueLen  = 16
	eapAKAAutsLen            = 14
	eapAKAMACValueLen        = 16
	eapAKAMACAttributeWords  = 0x05
	eapAKAAutsAttributeWords = 0x04
	eapAKASyncFailureLen     = 10
)

type eapAKAChallenge struct {
	Identifier byte
	Rand       []byte
	Autn       []byte
}

func eapAKAChallengeResponse(ctx context.Context, card Card, challengeText string) (string, error) {
	var challenge eapAKAChallenge
	if err := challenge.UnmarshalText([]byte(challengeText)); err != nil {
		return "", fmt.Errorf("decoding eap-aka challenge: %w", err)
	}
	authenticate := card.AKA
	if eapCard, ok := card.(eapAKACard); ok {
		authenticate = eapCard.EAPAKA
	}
	aka, err := authenticate(ctx, challenge.Rand, challenge.Autn)
	if err != nil {
		return "", fmt.Errorf("authenticating eap-aka challenge: %w", err)
	}
	if aka.Reject {
		return "", errors.New("USIM rejected eap-aka challenge")
	}
	text, err := respondToEAPAKAChallengeBase64(challenge, aka.RES, aka.CK, aka.IK, aka.AUTS, imsiEAP(card))
	if err != nil {
		return "", fmt.Errorf("building eap-aka challenge response: %w", err)
	}
	return text, nil
}

func (challenge *eapAKAChallenge) UnmarshalText(text []byte) error {
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return fmt.Errorf("decode EAP-AKA challenge: %w", err)
	}
	return challenge.UnmarshalBinary(data)
}

func (challenge *eapAKAChallenge) UnmarshalBinary(data []byte) error {
	if len(data) < eapAKAHeaderLen {
		return errors.New("EAP-AKA challenge too short")
	}
	if data[0] != eapAKACodeRequest {
		return fmt.Errorf("unexpected EAP code %#x", data[0])
	}
	packetLen := int(binary.BigEndian.Uint16(data[2:4]))
	if packetLen != len(data) {
		return fmt.Errorf("EAP length %d does not match packet length %d", packetLen, len(data))
	}
	if data[4] != eapAKAType {
		return fmt.Errorf("unexpected EAP type %#x", data[4])
	}
	if data[5] != eapAKASubtypeChallenge {
		return fmt.Errorf("unexpected EAP-AKA subtype %#x", data[5])
	}
	next := eapAKAChallenge{Identifier: data[1]}
	for off := eapAKAHeaderLen; off < len(data); {
		if len(data)-off < 2 {
			return errors.New("truncated EAP-AKA attribute")
		}
		typ := data[off]
		attrLen := int(data[off+1]) * eapAKAAttributeHeaderLen
		if attrLen < eapAKAAttributeHeaderLen {
			return fmt.Errorf("invalid EAP-AKA attribute length %d", attrLen)
		}
		if attrLen > len(data)-off {
			return errors.New("EAP-AKA attribute exceeds packet length")
		}
		value := data[off+eapAKAAttributeHeaderLen : off+attrLen]
		switch typ {
		case eapAKAAttributeRand:
			if len(value) != eapAKAChallengeValueLen {
				return fmt.Errorf("AT_RAND length %d, want %d", len(value), eapAKAChallengeValueLen)
			}
			next.Rand = append([]byte(nil), value...)
		case eapAKAAttributeAutn:
			if len(value) != eapAKAChallengeValueLen {
				return fmt.Errorf("AT_AUTN length %d, want %d", len(value), eapAKAChallengeValueLen)
			}
			next.Autn = append([]byte(nil), value...)
		}
		off += attrLen
	}
	if len(next.Rand) != eapAKAChallengeValueLen {
		return errors.New("AT_RAND is missing")
	}
	if len(next.Autn) != eapAKAChallengeValueLen {
		return errors.New("AT_AUTN is missing")
	}
	*challenge = next
	return nil
}

func respondToEAPAKAChallengeBase64(challenge eapAKAChallenge, res, ck, ik, auts []byte, identity string) (string, error) {
	data, err := respondToEAPAKAChallenge(challenge, res, ck, ik, auts, identity)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func respondToEAPAKAChallenge(challenge eapAKAChallenge, res, ck, ik, auts []byte, identity string) ([]byte, error) {
	if len(auts) > 0 {
		if len(auts) != eapAKAAutsLen {
			return nil, fmt.Errorf("AUTS length %d, want %d", len(auts), eapAKAAutsLen)
		}
		return eapAKASyncFailureResponse(challenge.Identifier, auts), nil
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
	kAut, err := deriveEAPAKAKAut(identity, ik, ck)
	if err != nil {
		return nil, err
	}
	return eapAKAChallengeResponsePacket(challenge.Identifier, res, kAut), nil
}

func eapAKAChallengeResponsePacket(identifier byte, res, kAut []byte) []byte {
	resLen := paddedEAPAKALen(len(res))
	atResLen := eapAKAAttributeHeaderLen + resLen
	msg := make([]byte, eapAKAHeaderLen+atResLen+eapAKAAttributeHeaderLen+eapAKAMACValueLen)
	msg[0] = eapAKACodeResponse
	msg[1] = identifier
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(msg)))
	msg[4] = eapAKAType
	msg[5] = eapAKASubtypeChallenge

	off := eapAKAHeaderLen
	msg[off] = eapAKAAttributeRes
	msg[off+1] = byte(atResLen / eapAKAAttributeHeaderLen)
	binary.BigEndian.PutUint16(msg[off+2:off+4], uint16(len(res)*eapAKABitsPerByte))
	copy(msg[off+eapAKAAttributeHeaderLen:off+eapAKAAttributeHeaderLen+len(res)], res)
	off += atResLen

	msg[off] = eapAKAAttributeMAC
	msg[off+1] = eapAKAMACAttributeWords
	mac := hmac.New(sha1.New, kAut)
	mac.Write(msg)
	copy(msg[off+eapAKAAttributeHeaderLen:off+eapAKAAttributeHeaderLen+eapAKAMACValueLen], mac.Sum(nil)[:eapAKAMACValueLen])
	return msg
}

func eapAKASyncFailureResponse(identifier byte, auts []byte) []byte {
	msg := make([]byte, eapAKASyncFailureLen+len(auts))
	msg[0] = eapAKACodeResponse
	msg[1] = identifier
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(msg)))
	msg[4] = eapAKAType
	msg[5] = eapAKASubtypeSyncFailure
	msg[eapAKAHeaderLen] = eapAKAAttributeAuts
	msg[eapAKAHeaderLen+1] = eapAKAAutsAttributeWords
	copy(msg[eapAKASyncFailureLen:], auts)
	return msg
}

func deriveEAPAKAKAut(identity string, ik, ck []byte) ([]byte, error) {
	if identity == "" {
		return nil, errors.New("identity is required")
	}
	h := sha1.New()
	h.Write([]byte(identity))
	h.Write(ik)
	h.Write(ck)
	key := fips1862PRF(h.Sum(nil), 160)
	return key[16:32], nil
}

func paddedEAPAKALen(n int) int {
	if n%4 == 0 {
		return n
	}
	return n + 4 - n%4
}

func fips1862PRF(seed []byte, length int) []byte {
	xkey := append([]byte(nil), seed...)
	out := make([]byte, 0, length)
	state := [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}
	for len(out) < length {
		for range 2 {
			w := sha1G(state, xkey)
			out = append(out, w...)
			addMod160(xkey, w)
		}
	}
	return out[:length]
}

func addMod160(xkey, w []byte) {
	carry := 1
	for i := 19; i >= 0; i-- {
		carry += int(xkey[i]) + int(w[i])
		xkey[i] = byte(carry)
		carry >>= 8
	}
}

func sha1G(state [5]uint32, xkey []byte) []byte {
	var block [64]byte
	copy(block[:20], xkey)
	w := sha1Block(state, block)
	out := make([]byte, 20)
	for i, v := range w {
		binary.BigEndian.PutUint32(out[i*4:], v)
	}
	return out
}

func sha1Block(h [5]uint32, block [64]byte) [5]uint32 {
	var w [80]uint32
	for i := range 16 {
		w[i] = binary.BigEndian.Uint32(block[i*4:])
	}
	for i := 16; i < 80; i++ {
		v := w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
		w[i] = v<<1 | v>>31
	}
	a, b, c, d, e := h[0], h[1], h[2], h[3], h[4]
	for i := range 80 {
		var f, k uint32
		switch {
		case i < 20:
			f = (b & c) | (^b & d)
			k = 0x5a827999
		case i < 40:
			f = b ^ c ^ d
			k = 0x6ed9eba1
		case i < 60:
			f = (b & c) | (b & d) | (c & d)
			k = 0x8f1bbcdc
		default:
			f = b ^ c ^ d
			k = 0xca62c1d6
		}
		temp := (a<<5 | a>>27) + f + e + k + w[i]
		e, d, c, b, a = d, c, b<<30|b>>2, a, temp
	}
	return [5]uint32{h[0] + a, h[1] + b, h[2] + c, h[3] + d, h[4] + e}
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
