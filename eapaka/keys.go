package eapaka

import (
	"crypto/sha1"
	"errors"
	"fmt"
)

const (
	akaKEncrLen = 16
	akaKAutLen  = 16
)

type AKAKeys struct {
	MK   []byte
	ENCR []byte
	AUT  []byte
	MSK  []byte
	EMSK []byte
}

func DeriveAKAKeys(identity, ik, ck []byte) (AKAKeys, error) {
	if len(identity) == 0 {
		return AKAKeys{}, errors.New("deriving aka keys: identity is empty")
	}
	if len(ik) != akaVectorLen {
		return AKAKeys{}, fmt.Errorf("deriving aka keys: ik length %d, want %d", len(ik), akaVectorLen)
	}
	if len(ck) != akaVectorLen {
		return AKAKeys{}, fmt.Errorf("deriving aka keys: ck length %d, want %d", len(ck), akaVectorLen)
	}

	mkHasher := sha1.New()
	_, _ = mkHasher.Write(identity)
	_, _ = mkHasher.Write(ik)
	_, _ = mkHasher.Write(ck)
	mk := mkHasher.Sum(nil)

	total := akaKEncrLen + akaKAutLen + akaPrimeMSKLen + akaPrimeEMSKLen
	stream, err := sha1DSSExpand(mk, total)
	if err != nil {
		return AKAKeys{}, err
	}
	keys := AKAKeys{
		MK:   append([]byte(nil), mk...),
		ENCR: append([]byte(nil), stream[:akaKEncrLen]...),
	}
	offset := akaKEncrLen
	keys.AUT = append([]byte(nil), stream[offset:offset+akaKAutLen]...)
	offset += akaKAutLen
	keys.MSK = append([]byte(nil), stream[offset:offset+akaPrimeMSKLen]...)
	offset += akaPrimeMSKLen
	keys.EMSK = append([]byte(nil), stream[offset:offset+akaPrimeEMSKLen]...)
	return keys, nil
}
