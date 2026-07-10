package tunnel

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/damonto/ims-go/eapaka"
)

func checkcodeValue(attrs []eapaka.AKAAttribute, eapType byte) ([]byte, bool, error) {
	attr := eapaka.FindAttribute(attrs, akaAttrCheckcode)
	if attr == nil {
		return nil, false, nil
	}
	wantLen := 2 + sha1.Size
	if eapType == eapTypeAKAPrime {
		wantLen = 2 + sha256.Size
	}
	if len(attr.Value) != 2 && len(attr.Value) != wantLen {
		return nil, true, fmt.Errorf("invalid checkcode length %d", len(attr.Value))
	}
	if len(attr.Value) == 2 {
		return nil, true, nil
	}
	return attr.Value[2:], true, nil
}

func (f *akaAuthFlow) verifyCheckcode(attrs []eapaka.AKAAttribute, eapType byte) error {
	got, ok, err := checkcodeValue(attrs, eapType)
	if err != nil {
		return err
	}
	if !ok {
		if f.identityExtended {
			return errors.New("checkcode is missing after extended aka identity request")
		}
		return nil
	}
	if len(got) == 0 {
		if len(f.identityPackets) == 0 {
			return nil
		}
		return errors.New("empty checkcode after aka identity exchange")
	}
	sum := sha1.New()
	if eapType == eapTypeAKAPrime {
		sum = sha256.New()
	}
	for _, packet := range f.identityPackets {
		_, _ = sum.Write(packet)
	}
	if !hmac.Equal(got, sum.Sum(nil)) {
		return errors.New("checkcode mismatch")
	}
	return nil
}

func (f *akaAuthFlow) challengeResponseCheckcode(attrs []eapaka.AKAAttribute, eapType byte) []byte {
	if !eapaka.HasAttribute(attrs, akaAttrCheckcode) || len(f.identityPackets) == 0 {
		return nil
	}
	sum := sha1.New()
	if eapType == eapTypeAKAPrime {
		sum = sha256.New()
	}
	for _, packet := range f.identityPackets {
		_, _ = sum.Write(packet)
	}
	return append([]byte{0x00, 0x00}, sum.Sum(nil)...)
}

func (f *akaAuthFlow) verifyMessageMAC(eapType byte, data, autKey, extra []byte) error {
	if eapType == eapTypeAKAPrime {
		return eapaka.VerifyMessageMACSHA256(data, autKey, extra)
	}
	return eapaka.VerifyMessageMAC(data, autKey, extra)
}
