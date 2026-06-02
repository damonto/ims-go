package eapaka

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	akaPrimeKDFCKIKFC   byte   = 0x20
	akaPrimeKDFDefault  uint16 = 1
	akaPrimeSQNXorAKLen        = 6
	akaPrimeCKLen              = 16
	akaPrimeIKLen              = 16
	akaPrimeKEncrLen           = 16
	akaPrimeKAutLen            = 32
	akaPrimeKReLen             = 32
	akaPrimeMSKLen             = 64
	akaPrimeEMSKLen            = 64
)

type AKAPrimeKeys struct {
	CKPrime []byte
	IKPrime []byte
	MK      []byte
	ENCR    []byte
	AUT     []byte
	RE      []byte
	MSK     []byte
	EMSK    []byte
}

func DeriveAKAPrimeCKIK(ck, ik, networkName, sqnXorAK []byte) ([]byte, []byte, error) {
	if len(ck) != akaPrimeCKLen {
		return nil, nil, fmt.Errorf("deriving aka prime ck/ik: ck length %d, want %d", len(ck), akaPrimeCKLen)
	}
	if len(ik) != akaPrimeIKLen {
		return nil, nil, fmt.Errorf("deriving aka prime ck/ik: ik length %d, want %d", len(ik), akaPrimeIKLen)
	}
	if len(networkName) == 0 {
		return nil, nil, errors.New("deriving aka prime ck/ik: network name is empty")
	}
	if len(networkName) > 0xffff {
		return nil, nil, fmt.Errorf("deriving aka prime ck/ik: network name length %d exceeds uint16", len(networkName))
	}
	if len(sqnXorAK) != akaPrimeSQNXorAKLen {
		return nil, nil, fmt.Errorf("deriving aka prime ck/ik: sqn xor ak length %d, want %d", len(sqnXorAK), akaPrimeSQNXorAKLen)
	}

	key := make([]byte, 0, len(ck)+len(ik))
	key = append(key, ck...)
	key = append(key, ik...)

	seed := make([]byte, 0, 1+len(networkName)+2+len(sqnXorAK)+2)
	seed = append(seed, akaPrimeKDFCKIKFC)
	seed = append(seed, networkName...)
	seed = binary.BigEndian.AppendUint16(seed, uint16(len(networkName)))
	seed = append(seed, sqnXorAK...)
	seed = binary.BigEndian.AppendUint16(seed, uint16(len(sqnXorAK)))

	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(seed)
	ckik := mac.Sum(nil)
	return append([]byte(nil), ckik[:akaPrimeCKLen]...), append([]byte(nil), ckik[akaPrimeCKLen:akaPrimeCKLen+akaPrimeIKLen]...), nil
}

func DeriveAKAPrimeKeys(identity, ck, ik, networkName, sqnXorAK []byte) (AKAPrimeKeys, error) {
	if len(identity) == 0 {
		return AKAPrimeKeys{}, errors.New("deriving aka prime keys: identity is empty")
	}
	ckPrime, ikPrime, err := DeriveAKAPrimeCKIK(ck, ik, networkName, sqnXorAK)
	if err != nil {
		return AKAPrimeKeys{}, err
	}

	key := make([]byte, 0, len(ikPrime)+len(ckPrime))
	key = append(key, ikPrime...)
	key = append(key, ckPrime...)
	seed := make([]byte, 0, len("EAP-AKA'")+len(identity))
	seed = append(seed, "EAP-AKA'"...)
	seed = append(seed, identity...)

	total := akaPrimeKEncrLen + akaPrimeKAutLen + akaPrimeKReLen + akaPrimeMSKLen + akaPrimeEMSKLen
	mk, err := sha256PRFPlus(key, seed, total)
	if err != nil {
		return AKAPrimeKeys{}, err
	}

	keys := AKAPrimeKeys{
		CKPrime: ckPrime,
		IKPrime: ikPrime,
		MK:      append([]byte(nil), mk...),
		ENCR:    append([]byte(nil), mk[:akaPrimeKEncrLen]...),
	}
	offset := akaPrimeKEncrLen
	keys.AUT = append([]byte(nil), mk[offset:offset+akaPrimeKAutLen]...)
	offset += akaPrimeKAutLen
	keys.RE = append([]byte(nil), mk[offset:offset+akaPrimeKReLen]...)
	offset += akaPrimeKReLen
	keys.MSK = append([]byte(nil), mk[offset:offset+akaPrimeMSKLen]...)
	offset += akaPrimeMSKLen
	keys.EMSK = append([]byte(nil), mk[offset:offset+akaPrimeEMSKLen]...)
	return keys, nil
}

func DeriveAKAPrimeFastReauthKeys(identity []byte, counter uint16, nonceS, kRe []byte) ([]byte, []byte, error) {
	if len(identity) == 0 {
		return nil, nil, errors.New("deriving aka prime fast reauth keys: identity is empty")
	}
	if len(nonceS) != akaVectorLen {
		return nil, nil, fmt.Errorf("deriving aka prime fast reauth keys: nonce_s length %d, want %d", len(nonceS), akaVectorLen)
	}
	if len(kRe) != akaPrimeKReLen {
		return nil, nil, fmt.Errorf("deriving aka prime fast reauth keys: k_re length %d, want %d", len(kRe), akaPrimeKReLen)
	}
	seed := make([]byte, 0, len("EAP-AKA' re-auth")+len(identity)+2+len(nonceS))
	seed = append(seed, "EAP-AKA' re-auth"...)
	seed = append(seed, identity...)
	seed = binary.BigEndian.AppendUint16(seed, counter)
	seed = append(seed, nonceS...)

	mk, err := sha256PRFPlus(kRe, seed, akaPrimeMSKLen+akaPrimeEMSKLen)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), mk[:akaPrimeMSKLen]...), append([]byte(nil), mk[akaPrimeMSKLen:]...), nil
}

func DeriveAKAPrimeFastReauthKeysFromMK(identity []byte, counter uint16, nonceS, mk []byte) ([]byte, []byte, error) {
	total := akaPrimeKEncrLen + akaPrimeKAutLen + akaPrimeKReLen + akaPrimeMSKLen + akaPrimeEMSKLen
	if len(mk) != total {
		return nil, nil, fmt.Errorf("deriving aka prime fast reauth keys: mk length %d, want %d", len(mk), total)
	}
	offset := akaPrimeKEncrLen + akaPrimeKAutLen
	return DeriveAKAPrimeFastReauthKeys(identity, counter, nonceS, mk[offset:offset+akaPrimeKReLen])
}

func sha256PRFPlus(key, seed []byte, size int) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("sha256 prf+: key is empty")
	}
	if size <= 0 {
		return nil, fmt.Errorf("sha256 prf+: size %d", size)
	}
	out := make([]byte, 0, size)
	var prev []byte
	for counter := byte(1); len(out) < size; counter++ {
		if counter == 0 {
			return nil, errors.New("sha256 prf+: counter overflow")
		}
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(prev)
		_, _ = mac.Write(seed)
		_, _ = mac.Write([]byte{counter})
		prev = mac.Sum(nil)
		out = append(out, prev...)
	}
	return append([]byte(nil), out[:size]...), nil
}
