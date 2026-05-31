package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	crand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"

	"github.com/damonto/vowifi-go/swu/eapaka"
	"github.com/damonto/vowifi-go/swu/ike"
)

var (
	sha1DSSIncrement = big.NewInt(1)
	sha1DSSModulus   = new(big.Int).Lsh(big.NewInt(1), 160)
	dhPublicMin      = big.NewInt(1)

	errMissingEncryptedPayload = errors.New("opening ike packet: missing encrypted payload")
)

type ikeKeys struct {
	SKD  []byte
	SKAI []byte
	SKAR []byte
	SKEI []byte
	SKER []byte
	SKPI []byte
	SKPR []byte
}

type eapKeys struct {
	RES  []byte
	IK   []byte
	CK   []byte
	MK   []byte
	ENCR []byte
	AUT  []byte
	MSK  []byte
	EMSK []byte
}

type ESPKeys struct {
	EncryptionInitiator []byte
	IntegrityInitiator  []byte
	EncryptionResponder []byte
	IntegrityResponder  []byte
}

type ikeCrypto struct {
	encr          uint16
	encrKeyBits   uint16
	integ         uint16
	prf           uint16
	dhGroup       uint16
	initiatorSPI  uint64
	responderSPI  uint64
	nonceI        []byte
	nonceR        []byte
	private       *big.Int
	public        []byte
	groupPrime    *big.Int
	groupByteSize int
	random        io.Reader
	keys          ikeKeys
	eap           eapKeys
}

func newIKECrypto(dhGroup uint16) (*ikeCrypto, error) {
	prime, groupSize, err := modpGroup(dhGroup)
	if err != nil {
		return nil, err
	}
	private, err := randomDHPrivate(prime)
	if err != nil {
		return nil, fmt.Errorf("creating dh private key: %w", err)
	}
	generator := big.NewInt(2)
	publicInt := new(big.Int).Exp(generator, private, prime)
	public := publicInt.FillBytes(make([]byte, groupSize))
	return &ikeCrypto{
		dhGroup:       dhGroup,
		private:       private,
		public:        public,
		groupPrime:    prime,
		groupByteSize: groupSize,
		random:        crand.Reader,
	}, nil
}

func (c *ikeCrypto) PublicKey() []byte {
	return append([]byte(nil), c.public...)
}

func (c *ikeCrypto) SetProposal(encr, encrKeyBits, integ, prf uint16) {
	c.encr = encr
	c.encrKeyBits = encrKeyBits
	c.integ = integ
	c.prf = prf
}

func (c *ikeCrypto) SetSPIs(initiator, responder uint64) {
	c.initiatorSPI = initiator
	c.responderSPI = responder
}

func (c *ikeCrypto) SetNonces(initiator, responder []byte) {
	c.nonceI = append([]byte(nil), initiator...)
	c.nonceR = append([]byte(nil), responder...)
}

func (c *ikeCrypto) DeriveIKEKeys(peerPublic []byte) error {
	shared, err := c.sharedSecret(peerPublic)
	if err != nil {
		return err
	}
	nonce := append(append([]byte(nil), c.nonceI...), c.nonceR...)
	skeyseed := c.prfHMAC(nonce, shared)
	seed := make([]byte, 0, len(nonce)+16)
	seed = append(seed, nonce...)
	spi := make([]byte, 16)
	binary.BigEndian.PutUint64(spi[0:8], c.initiatorSPI)
	binary.BigEndian.PutUint64(spi[8:16], c.responderSPI)
	seed = append(seed, spi...)
	total := (3 * c.prfLength()) + (2 * c.integKeyLength()) + (2 * c.encrKeyLength())
	stream, err := c.prfPlus(skeyseed, seed, total)
	if err != nil {
		return err
	}
	c.keys.SKD = append([]byte(nil), stream[:c.prfLength()]...)
	stream = stream[c.prfLength():]
	c.keys.SKAI = append([]byte(nil), stream[:c.integKeyLength()]...)
	stream = stream[c.integKeyLength():]
	c.keys.SKAR = append([]byte(nil), stream[:c.integKeyLength()]...)
	stream = stream[c.integKeyLength():]
	c.keys.SKEI = append([]byte(nil), stream[:c.encrKeyLength()]...)
	stream = stream[c.encrKeyLength():]
	c.keys.SKER = append([]byte(nil), stream[:c.encrKeyLength()]...)
	stream = stream[c.encrKeyLength():]
	c.keys.SKPI = append([]byte(nil), stream[:c.prfLength()]...)
	stream = stream[c.prfLength():]
	c.keys.SKPR = append([]byte(nil), stream[:c.prfLength()]...)
	return nil
}

func (c *ikeCrypto) DeriveRekeyedIKEKeys(old *ikeCrypto, peerPublic []byte) error {
	shared, err := c.sharedSecret(peerPublic)
	if err != nil {
		return err
	}
	nonce := append(append([]byte(nil), c.nonceI...), c.nonceR...)
	skeyseedInput := make([]byte, 0, len(shared)+len(nonce))
	skeyseedInput = append(skeyseedInput, shared...)
	skeyseedInput = append(skeyseedInput, nonce...)
	skeyseed := old.prfHMAC(old.keys.SKD, skeyseedInput)
	seed := make([]byte, 0, len(nonce)+16)
	seed = append(seed, nonce...)
	spi := make([]byte, 16)
	binary.BigEndian.PutUint64(spi[0:8], c.initiatorSPI)
	binary.BigEndian.PutUint64(spi[8:16], c.responderSPI)
	seed = append(seed, spi...)
	total := (3 * c.prfLength()) + (2 * c.integKeyLength()) + (2 * c.encrKeyLength())
	stream, err := c.prfPlus(skeyseed, seed, total)
	if err != nil {
		return err
	}
	c.keys.SKD = append([]byte(nil), stream[:c.prfLength()]...)
	stream = stream[c.prfLength():]
	c.keys.SKAI = append([]byte(nil), stream[:c.integKeyLength()]...)
	stream = stream[c.integKeyLength():]
	c.keys.SKAR = append([]byte(nil), stream[:c.integKeyLength()]...)
	stream = stream[c.integKeyLength():]
	c.keys.SKEI = append([]byte(nil), stream[:c.encrKeyLength()]...)
	stream = stream[c.encrKeyLength():]
	c.keys.SKER = append([]byte(nil), stream[:c.encrKeyLength()]...)
	stream = stream[c.encrKeyLength():]
	c.keys.SKPI = append([]byte(nil), stream[:c.prfLength()]...)
	stream = stream[c.prfLength():]
	c.keys.SKPR = append([]byte(nil), stream[:c.prfLength()]...)
	return nil
}

func (c *ikeCrypto) DeriveESPKeys(encrKeyBits, integ uint16) (ESPKeys, error) {
	return c.DeriveESPKeysWithNonces(encrKeyBits, integ, c.nonceI, c.nonceR)
}

func (c *ikeCrypto) DeriveESPKeysWithNonces(encrKeyBits, integ uint16, nonceI, nonceR []byte) (ESPKeys, error) {
	seed := append(append([]byte(nil), nonceI...), nonceR...)
	return c.deriveESPKeysWithSeed(encrKeyBits, integ, seed)
}

func (c *ikeCrypto) DeriveESPKeysWithDH(encrKeyBits, integ uint16, nonceI, nonceR []byte, dh *ikeCrypto, peerPublic []byte) (ESPKeys, error) {
	shared, err := dh.sharedSecret(peerPublic)
	if err != nil {
		return ESPKeys{}, err
	}
	seed := make([]byte, 0, len(shared)+len(nonceI)+len(nonceR))
	seed = append(seed, shared...)
	seed = append(seed, nonceI...)
	seed = append(seed, nonceR...)
	return c.deriveESPKeysWithSeed(encrKeyBits, integ, seed)
}

func (c *ikeCrypto) deriveESPKeysWithSeed(encrKeyBits, integ uint16, seed []byte) (ESPKeys, error) {
	if len(c.keys.SKD) == 0 {
		return ESPKeys{}, errors.New("deriving esp keys: ike keys are empty")
	}
	encrKeyLen := encrKeyLengthFromBits(encrKeyBits)
	integKeyLen, err := integKeyLength(integ)
	if err != nil {
		return ESPKeys{}, err
	}
	total := (2 * encrKeyLen) + (2 * integKeyLen)
	stream, err := c.prfPlus(c.keys.SKD, seed, total)
	if err != nil {
		return ESPKeys{}, err
	}
	keys := ESPKeys{
		EncryptionInitiator: append([]byte(nil), stream[:encrKeyLen]...),
	}
	stream = stream[encrKeyLen:]
	keys.IntegrityInitiator = append([]byte(nil), stream[:integKeyLen]...)
	stream = stream[integKeyLen:]
	keys.EncryptionResponder = append([]byte(nil), stream[:encrKeyLen]...)
	stream = stream[encrKeyLen:]
	keys.IntegrityResponder = append([]byte(nil), stream[:integKeyLen]...)
	return keys, nil
}

func (c *ikeCrypto) DeriveEAPKeys(identity, res, ik, ck []byte) error {
	keys, err := deriveEAPKeys(identity, ik, ck)
	if err != nil {
		return err
	}
	c.eap = eapKeys{
		RES:  append([]byte(nil), res...),
		IK:   append([]byte(nil), ik...),
		CK:   append([]byte(nil), ck...),
		MK:   keys.MK,
		ENCR: keys.ENCR,
		AUT:  keys.AUT,
		MSK:  keys.MSK,
		EMSK: keys.EMSK,
	}
	return nil
}

func (c *ikeCrypto) DeriveAKAPrimeEAPKeys(identity, res, ck, ik, networkName, sqnXorAK []byte) error {
	keys, err := eapaka.DeriveAKAPrimeKeys(identity, ck, ik, networkName, sqnXorAK)
	if err != nil {
		return err
	}
	c.eap = eapKeys{
		RES:  append([]byte(nil), res...),
		IK:   append([]byte(nil), ik...),
		CK:   append([]byte(nil), ck...),
		MK:   keys.MK,
		ENCR: keys.ENCR,
		AUT:  keys.AUT,
		MSK:  keys.MSK,
		EMSK: keys.EMSK,
	}
	return nil
}

func (c *ikeCrypto) ComputeInitiatorAuth(saInitRequest, responderNonce, idiRaw []byte) ([]byte, error) {
	if len(c.eap.MSK) == 0 {
		return nil, errors.New("computing initiator auth: eap msk is empty")
	}
	inner := c.prfHMAC(c.keys.SKPI, idiRaw)
	data := make([]byte, 0, len(saInitRequest)+len(responderNonce)+len(inner))
	data = append(data, saInitRequest...)
	data = append(data, responderNonce...)
	data = append(data, inner...)
	tmpKey := c.prfHMAC(c.eap.MSK, []byte("Key Pad for IKEv2"))
	return c.prfHMAC(tmpKey, data), nil
}

func (c *ikeCrypto) ComputeResponderAuth(saInitResponse, initiatorNonce, idrRaw []byte) ([]byte, error) {
	if len(c.eap.MSK) == 0 {
		return nil, errors.New("computing responder auth: eap msk is empty")
	}
	inner := c.prfHMAC(c.keys.SKPR, idrRaw)
	data := make([]byte, 0, len(saInitResponse)+len(initiatorNonce)+len(inner))
	data = append(data, saInitResponse...)
	data = append(data, initiatorNonce...)
	data = append(data, inner...)
	tmpKey := c.prfHMAC(c.eap.MSK, []byte("Key Pad for IKEv2"))
	return c.prfHMAC(tmpKey, data), nil
}

func (c *ikeCrypto) SealIKE(header ike.IKEHeader, payloads []ike.Payload, initiator bool) ([]byte, error) {
	first, body, err := ike.MarshalPayloadChain(payloads)
	if err != nil {
		return nil, fmt.Errorf("sealing ike packet: %w", err)
	}
	padLen := aes.BlockSize - ((len(body) + 1) % aes.BlockSize)
	if padLen == aes.BlockSize {
		padLen = 0
	}
	plain := append([]byte(nil), body...)
	plain = append(plain, make([]byte, padLen)...)
	plain = append(plain, byte(padLen))
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(c.randomReader(), iv); err != nil {
		return nil, fmt.Errorf("sealing ike packet: reading iv: %w", err)
	}
	ciphertext, err := c.encryptCBC(c.encryptionKey(initiator), iv, plain)
	if err != nil {
		return nil, err
	}
	icvLen, err := integLength(c.integ)
	if err != nil {
		return nil, err
	}
	container := &ike.EncryptedPayload{NextPayload: first, Raw: append(append(iv, ciphertext...), make([]byte, icvLen)...)}
	packet := ike.IKEPacket{Header: header, Payloads: []ike.Payload{container}}
	raw, err := packet.MarshalBinary()
	if err != nil {
		return nil, err
	}
	icv := c.integHMAC(c.integrityKey(initiator), raw[:len(raw)-icvLen])
	copy(raw[len(raw)-icvLen:], icv)
	return raw, nil
}

func (c *ikeCrypto) OpenIKE(packet ike.IKEPacket, senderInitiator bool) ([]ike.Payload, error) {
	if len(packet.Payloads) != 1 {
		return nil, errors.New("opening ike packet: expected encrypted payload container")
	}
	container, ok := packet.Payloads[0].(*ike.EncryptedPayload)
	if !ok {
		return nil, errMissingEncryptedPayload
	}
	ivLen := aes.BlockSize
	icvLen, err := integLength(c.integ)
	if err != nil {
		return nil, err
	}
	if len(container.Raw) < ivLen+icvLen {
		return nil, errors.New("opening ike packet: encrypted body too short")
	}
	body := container.Raw
	wantICV := body[len(body)-icvLen:]
	gotICV := c.integHMAC(c.integrityKey(senderInitiator), packet.Raw[:len(packet.Raw)-icvLen])
	if !hmac.Equal(gotICV, wantICV) {
		return nil, errors.New("opening ike packet: integrity check failed")
	}
	iv := body[:ivLen]
	ciphertext := body[ivLen : len(body)-icvLen]
	plain, err := c.decryptCBC(c.encryptionKey(senderInitiator), iv, ciphertext)
	if err != nil {
		return nil, err
	}
	if len(plain) == 0 {
		return nil, errors.New("opening ike packet: plaintext is empty")
	}
	padLen := int(plain[len(plain)-1])
	if len(plain) < padLen+1 {
		return nil, errors.New("opening ike packet: invalid padding")
	}
	plain = plain[:len(plain)-1-padLen]
	payloads, err := ike.DecodePayloadChain(container.NextPayload, plain)
	if err != nil {
		var critical ike.UnsupportedCriticalPayloadError
		if errors.As(err, &critical) {
			return nil, err
		}
		return nil, ike.InvalidSyntaxError{Err: err}
	}
	if hasEncryptedPayload(payloads) {
		return nil, ike.InvalidSyntaxError{Err: errors.New("nested encrypted payload")}
	}
	return payloads, nil
}

func (c *ikeCrypto) ProtectedBytes(wire []byte) (uint64, error) {
	packet := normalizeIKEPacket(wire, true)
	var ikePacket ike.IKEPacket
	if err := ikePacket.UnmarshalBinary(packet); err != nil {
		return 0, fmt.Errorf("counting ike protected bytes: %w", err)
	}
	if len(ikePacket.Payloads) != 1 {
		return 0, errors.New("counting ike protected bytes: expected encrypted payload container")
	}
	container, ok := ikePacket.Payloads[0].(*ike.EncryptedPayload)
	if !ok {
		return 0, errMissingEncryptedPayload
	}
	icvLen, err := integLength(c.integ)
	if err != nil {
		return 0, err
	}
	if len(container.Raw) < aes.BlockSize+icvLen {
		return 0, errors.New("counting ike protected bytes: encrypted body too short")
	}
	return uint64(len(container.Raw) - aes.BlockSize - icvLen), nil
}

func (c *ikeCrypto) EAPAuthKey() []byte {
	return append([]byte(nil), c.eap.AUT...)
}

func (c *ikeCrypto) EAPMSK() []byte {
	return append([]byte(nil), c.eap.MSK...)
}

func (c *ikeCrypto) randomReader() io.Reader {
	if c.random != nil {
		return c.random
	}
	return crand.Reader
}

func (c *ikeCrypto) encryptionKey(senderInitiator bool) []byte {
	if senderInitiator {
		return c.keys.SKEI
	}
	return c.keys.SKER
}

func (c *ikeCrypto) integrityKey(senderInitiator bool) []byte {
	if senderInitiator {
		return c.keys.SKAI
	}
	return c.keys.SKAR
}

func (c *ikeCrypto) sharedSecret(peerPublic []byte) ([]byte, error) {
	if len(peerPublic) == 0 {
		return nil, errors.New("deriving shared secret: peer public key is empty")
	}
	peer := new(big.Int).SetBytes(peerPublic)
	if !validMODPPublicKey(peer, c.groupPrime) {
		return nil, errors.New("deriving shared secret: peer public key is outside modp group range")
	}
	shared := new(big.Int).Exp(peer, c.private, c.groupPrime)
	return shared.FillBytes(make([]byte, c.groupByteSize)), nil
}

func validMODPPublicKey(peer, prime *big.Int) bool {
	upper := new(big.Int).Sub(prime, dhPublicMin)
	return peer.Cmp(dhPublicMin) > 0 && peer.Cmp(upper) < 0
}

func (c *ikeCrypto) prfPlus(key, seed []byte, size int) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("deriving prf+: invalid size %d", size)
	}
	if size == 0 {
		return nil, nil
	}
	maxSize := 255 * c.prfLength()
	if size > maxSize {
		return nil, fmt.Errorf("deriving prf+: size %d exceeds RFC 7296 limit %d", size, maxSize)
	}
	result := make([]byte, 0, size)
	var last []byte
	for i := 1; len(result) < size; i++ {
		blockInput := make([]byte, 0, len(last)+len(seed)+1)
		blockInput = append(blockInput, last...)
		blockInput = append(blockInput, seed...)
		blockInput = append(blockInput, byte(i))
		last = c.prfHMAC(key, blockInput)
		result = append(result, last...)
	}
	return result[:size], nil
}

func (c *ikeCrypto) prfHMAC(key, data []byte) []byte {
	h := hmac.New(c.prfHash(), key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func (c *ikeCrypto) integHMAC(key, data []byte) []byte {
	h := hmac.New(c.integHash(), key)
	_, _ = h.Write(data)
	full := h.Sum(nil)
	length, _ := integLength(c.integ)
	return full[:length]
}

func (c *ikeCrypto) prfHash() func() hash.Hash {
	switch c.prf {
	case transformPRFHMACMD5:
		return md5.New
	case transformPRFHMACSHA1:
		return sha1.New
	case transformPRFHMACSHA256:
		return sha256.New
	default:
		return sha1.New
	}
}

func (c *ikeCrypto) integHash() func() hash.Hash {
	switch c.integ {
	case transformINTEGHMACMD596:
		return md5.New
	case transformINTEGHMACSHA196:
		return sha1.New
	case transformINTEGHMACSHA256:
		return sha256.New
	default:
		return sha1.New
	}
}

func (c *ikeCrypto) prfLength() int {
	switch c.prf {
	case transformPRFHMACMD5:
		return md5.Size
	case transformPRFHMACSHA1:
		return sha1.Size
	case transformPRFHMACSHA256:
		return sha256.Size
	default:
		return sha1.Size
	}
}

func (c *ikeCrypto) integKeyLength() int {
	length, _ := integKeyLength(c.integ)
	return length
}

func (c *ikeCrypto) encrKeyLength() int {
	return encrKeyLengthFromBits(c.encrKeyBits)
}

func (c *ikeCrypto) encryptCBC(key, iv, plain []byte) ([]byte, error) {
	if c.encr != transformENCRAESCBC {
		return nil, fmt.Errorf("encrypting ike packet: unsupported encryption transform %d", c.encr)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("encrypting ike packet: %w", err)
	}
	if len(plain)%aes.BlockSize != 0 {
		return nil, errors.New("encrypting ike packet: plaintext is not block aligned")
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return out, nil
}

func (c *ikeCrypto) decryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	if c.encr != transformENCRAESCBC {
		return nil, fmt.Errorf("decrypting ike packet: unsupported encryption transform %d", c.encr)
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("decrypting ike packet: ciphertext is not block aligned")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("decrypting ike packet: %w", err)
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return out, nil
}

func deriveEAPKeys(identity, ik, ck []byte) (eapKeys, error) {
	mkHasher := sha1.New()
	_, _ = mkHasher.Write(identity)
	_, _ = mkHasher.Write(ik)
	_, _ = mkHasher.Write(ck)
	mk := mkHasher.Sum(nil)
	result, err := sha1DSSExpand(mk, 160)
	if err != nil {
		return eapKeys{}, err
	}
	return eapKeys{
		MK:   append([]byte(nil), mk...),
		ENCR: append([]byte(nil), result[:16]...),
		AUT:  append([]byte(nil), result[16:32]...),
		MSK:  append([]byte(nil), result[32:96]...),
		EMSK: append([]byte(nil), result[96:160]...),
	}, nil
}

func sha1DSSExpand(seed []byte, size int) ([]byte, error) {
	if len(seed) != 20 {
		return nil, fmt.Errorf("sha1-dss expand: seed length %d", len(seed))
	}
	if size <= 0 {
		return nil, fmt.Errorf("sha1-dss expand: size %d", size)
	}
	x := new(big.Int).SetBytes(seed)
	result := make([]byte, 0, size)
	for len(result) < size {
		block, err := nextSHA1DSSBlock(x)
		if err != nil {
			return nil, err
		}
		result = append(result, block...)
	}
	return append([]byte(nil), result[:size]...), nil
}

func nextSHA1DSSBlock(x *big.Int) ([]byte, error) {
	block, err := sha1DSS(x.FillBytes(make([]byte, 20)))
	if err != nil {
		return nil, err
	}
	x.Add(x, new(big.Int).SetBytes(block))
	x.Add(x, sha1DSSIncrement)
	x.Mod(x, sha1DSSModulus)
	return block, nil
}

func sha1DSS(data []byte) ([]byte, error) {
	if len(data) != 20 {
		return nil, fmt.Errorf("sha1-dss: input length %d", len(data))
	}
	words := make([]uint32, 80)
	block := make([]byte, 64)
	copy(block, data)
	for i := 0; i < 16; i++ {
		words[i] = binary.BigEndian.Uint32(block[i*4 : i*4+4])
	}
	for i := 16; i < 80; i++ {
		words[i] = rol(words[i-3]^words[i-8]^words[i-14]^words[i-16], 1)
	}
	h0 := uint32(0x67452301)
	h1 := uint32(0xEFCDAB89)
	h2 := uint32(0x98BADCFE)
	h3 := uint32(0x10325476)
	h4 := uint32(0xC3D2E1F0)
	a, b, c, d, e := h0, h1, h2, h3, h4
	for i := 0; i < 80; i++ {
		var f, k uint32
		switch {
		case i < 20:
			f = (b & c) | (^b & d)
			k = 0x5A827999
		case i < 40:
			f = b ^ c ^ d
			k = 0x6ED9EBA1
		case i < 60:
			f = (b & c) | (b & d) | (c & d)
			k = 0x8F1BBCDC
		default:
			f = b ^ c ^ d
			k = 0xCA62C1D6
		}
		temp := rol(a, 5) + f + e + k + words[i]
		e = d
		d = c
		c = rol(b, 30)
		b = a
		a = temp
	}
	h0 += a
	h1 += b
	h2 += c
	h3 += d
	h4 += e
	out := make([]byte, 20)
	binary.BigEndian.PutUint32(out[0:4], h0)
	binary.BigEndian.PutUint32(out[4:8], h1)
	binary.BigEndian.PutUint32(out[8:12], h2)
	binary.BigEndian.PutUint32(out[12:16], h3)
	binary.BigEndian.PutUint32(out[16:20], h4)
	return out, nil
}

func rol(value uint32, bits uint) uint32 {
	return value<<bits | value>>(32-bits)
}

func modpGroup(group uint16) (*big.Int, int, error) {
	hexPrime := ""
	switch group {
	case transformDH1024MODP:
		hexPrime = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"
	case transformDH2048MODP:
		hexPrime = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
	default:
		return nil, 0, fmt.Errorf("loading dh group: unsupported group %d", group)
	}
	prime, ok := new(big.Int).SetString(hexPrime, 16)
	if !ok {
		return nil, 0, errors.New("loading dh group: invalid prime")
	}
	return prime, len(hexPrime) / 2, nil
}

func randomDHPrivate(prime *big.Int) (*big.Int, error) {
	limit := new(big.Int).Sub(prime, big.NewInt(2))
	value, err := crand.Int(crand.Reader, limit)
	if err != nil {
		return nil, err
	}
	return value.Add(value, big.NewInt(2)), nil
}

func encrKeyLengthFromBits(bits uint16) int {
	return int(bits / 8)
}

func integKeyLength(integ uint16) (int, error) {
	switch integ {
	case transformINTEGHMACMD596:
		return md5.Size, nil
	case transformINTEGHMACSHA196:
		return sha1.Size, nil
	case transformINTEGHMACSHA256:
		return sha256.Size, nil
	default:
		return 0, fmt.Errorf("integrity key length: unsupported transform %d", integ)
	}
}

func integLength(integ uint16) (int, error) {
	switch integ {
	case transformINTEGHMACMD596:
		return 12, nil
	case transformINTEGHMACSHA196:
		return 12, nil
	case transformINTEGHMACSHA256:
		return 16, nil
	default:
		return 0, fmt.Errorf("integrity length: unsupported transform %d", integ)
	}
}
