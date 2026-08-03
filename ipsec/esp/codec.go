package esp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"sync"

	"github.com/damonto/ims-go/ipsec/aesctr"
	"github.com/damonto/ims-go/ipsec/aesxcbc"
)

const (
	EncryptionNull     = "null"
	EncryptionAESCBC   = "aes-cbc"
	EncryptionAESCTR   = "aes-ctr"
	EncryptionAESGCM   = "aes-gcm"
	EncryptionAESGCMUS = "aes-gcm-us"
)

const (
	IntegrityNone          = "none"
	IntegrityNull          = "null"
	IntegrityHMACMD596     = "hmac-md5-96"
	IntegrityHMACSHA196    = "hmac-sha1-96"
	IntegrityHMACSHA196RFC = "hmac-sha-1-96"
	IntegrityAESXCBC96     = "aes-xcbc-96"
	IntegrityHMACSHA256128 = "hmac-sha256-128"
	IntegrityHMACSHA256RFC = "hmac-sha2-256-128"
	IntegrityHMACSHA384192 = "hmac-sha384-192"
	IntegrityHMACSHA512256 = "hmac-sha512-256"
	IntegrityAESGMAC       = "aes-gmac"
	IntegrityAESGMACUS     = "aes-gmac-us"
)

const (
	espSPILen        = 4
	espSequenceLen   = 4
	espHeaderLen     = espSPILen + espSequenceLen
	espTrailerLen    = 2
	espMinPacketLen  = espHeaderLen + espTrailerLen
	espDefaultAlign  = 4
	espExplicitIVLen = 8
	espGCMICVLen     = 16
	ReservedSPIMax   = 255

	// NextHeaderNoNext marks RFC 4303 dummy ESP packets.
	NextHeaderNoNext = 59
)

var (
	_ encoding.BinaryAppender    = ESPPacket{}
	_ encoding.BinaryMarshaler   = ESPPacket{}
	_ encoding.BinaryUnmarshaler = (*ESPPacket)(nil)
)

type ESPPacket struct {
	SPI        uint32
	Sequence   uint32
	NextHeader byte
	Payload    []byte
}

func ValidSPI(spi uint32) bool {
	return spi > ReservedSPIMax
}

func validateESPHeader(spi, sequence uint32) error {
	if !ValidSPI(spi) {
		return fmt.Errorf("invalid spi 0x%08X", spi)
	}
	if sequence == 0 {
		return errors.New("invalid sequence number 0")
	}
	return nil
}

func (p ESPPacket) MarshalBinary() ([]byte, error) {
	return p.AppendBinary(nil)
}

func (p ESPPacket) AppendBinary(dst []byte) ([]byte, error) {
	if err := validateESPHeader(p.SPI, p.Sequence); err != nil {
		return nil, fmt.Errorf("marshalling esp packet: %w", err)
	}
	start := len(dst)
	dst = append(dst, make([]byte, espHeaderLen)...)
	binary.BigEndian.PutUint32(dst[start:start+espSPILen], p.SPI)
	binary.BigEndian.PutUint32(dst[start+espSPILen:start+espHeaderLen], p.Sequence)
	dst = append(dst, p.Payload...)
	padLen := paddingLength(len(p.Payload)+espTrailerLen, espDefaultAlign)
	for i := 1; i <= padLen; i++ {
		dst = append(dst, byte(i))
	}
	dst = append(dst, byte(padLen), p.NextHeader)
	return dst, nil
}

func (p *ESPPacket) UnmarshalBinary(data []byte) error {
	if len(data) < espMinPacketLen {
		return errors.New("parsing esp packet: packet too short")
	}
	spi := binary.BigEndian.Uint32(data[:espSPILen])
	sequence := binary.BigEndian.Uint32(data[espSPILen:espHeaderLen])
	if err := validateESPHeader(spi, sequence); err != nil {
		return fmt.Errorf("parsing esp packet: %w", err)
	}
	padLen := int(data[len(data)-espTrailerLen])
	if len(data) < espMinPacketLen+padLen {
		return errors.New("parsing esp packet: invalid padding")
	}
	payloadEnd := len(data) - espTrailerLen - padLen
	for i := range padLen {
		if data[payloadEnd+i] != byte(i+1) {
			return errors.New("parsing esp packet: invalid padding")
		}
	}
	*p = ESPPacket{
		SPI:        spi,
		Sequence:   sequence,
		NextHeader: data[len(data)-1],
		Payload:    append([]byte(nil), data[espHeaderLen:payloadEnd]...),
	}
	return nil
}

type Codec struct {
	SPI           uint32
	Encryption    string
	Integrity     string
	EncryptionKey []byte
	IntegrityKey  []byte
	Salt          [4]byte
	Random        io.Reader
}

type Config struct {
	SPI           uint32
	EncryptionKey []byte
	IntegrityKey  []byte
}

type ESP struct {
	mu     sync.Mutex
	codec  Codec
	seq    uint32
	replay ReplayWindow
}

var errNextHeaderRequired = errors.New("encoding ESP: next header is required")

func NewESP(cfg Config) (*ESP, error) {
	if !ValidSPI(cfg.SPI) {
		return nil, errors.New("creating ESP: invalid SPI")
	}
	if len(cfg.EncryptionKey) != 16 {
		return nil, errors.New("creating ESP: expected 16-byte AES encryption key")
	}
	if len(cfg.IntegrityKey) != 20 {
		return nil, errors.New("creating ESP: expected 20-byte HMAC-SHA1 key")
	}
	return &ESP{
		codec: Codec{
			SPI:           cfg.SPI,
			Encryption:    EncryptionAESCBC,
			Integrity:     IntegrityHMACSHA196,
			EncryptionKey: append([]byte(nil), cfg.EncryptionKey...),
			IntegrityKey:  append([]byte(nil), cfg.IntegrityKey...),
		},
	}, nil
}

// Seal cannot infer the protected protocol and therefore never emits a packet.
// Deprecated: use SealWithNextHeader.
func (e *ESP) Seal(payload []byte) ([]byte, error) {
	return nil, errNextHeaderRequired
}

// SealWithNextHeader encodes one ESP packet with the supplied Next Header.
// A normal ESP data packet must identify the protected protocol; Next Header
// 59 is reserved for dummy packets and is intentionally not accepted here.
func (e *ESP) SealWithNextHeader(payload []byte, nextHeader byte) ([]byte, error) {
	if nextHeader == NextHeaderNoNext {
		return nil, errors.New("encoding ESP: dummy packets are not supported")
	}
	e.mu.Lock()
	seq, ok := NextSequence(&e.seq)
	codec := e.codec
	e.mu.Unlock()
	if !ok {
		return nil, errors.New("encoding ESP: sequence number overflow")
	}
	return codec.Encode(ESPPacket{SPI: codec.SPI, Sequence: seq, NextHeader: nextHeader, Payload: payload})
}

func (e *ESP) Open(packet []byte) ([]byte, error) {
	e.mu.Lock()
	codec := e.codec
	e.mu.Unlock()
	pkt, err := codec.Decode(packet)
	if err != nil {
		return nil, err
	}
	if pkt.SPI != codec.SPI {
		return nil, fmt.Errorf("decoding ESP: unexpected spi 0x%08X", pkt.SPI)
	}
	if pkt.NextHeader == NextHeaderNoNext {
		return nil, errors.New("decoding ESP: dummy packets are not supported")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.replay.Accept(pkt.Sequence) {
		return nil, fmt.Errorf("decoding ESP: replayed packet sequence %d", pkt.Sequence)
	}
	return pkt.Payload, nil
}

func (c Codec) Encode(pkt ESPPacket) ([]byte, error) {
	if !ValidSPI(c.SPI) {
		return nil, errors.New("encoding ESP: invalid codec SPI")
	}
	if pkt.SPI != c.SPI {
		return nil, fmt.Errorf("encoding ESP: packet SPI 0x%08X does not match codec SPI 0x%08X", pkt.SPI, c.SPI)
	}
	if err := validateESPHeader(pkt.SPI, pkt.Sequence); err != nil {
		return nil, fmt.Errorf("encoding ESP: %w", err)
	}
	if err := c.validateAlgorithms(); err != nil {
		return nil, fmt.Errorf("encoding ESP: %w", err)
	}
	plaintext := append([]byte(nil), pkt.Payload...)
	padLen := paddingLength(len(plaintext)+espTrailerLen, c.blockSize())
	for i := 1; i <= padLen; i++ {
		plaintext = append(plaintext, byte(i))
	}
	plaintext = append(plaintext, byte(padLen), pkt.NextHeader)

	header := make([]byte, espHeaderLen)
	binary.BigEndian.PutUint32(header[:espSPILen], pkt.SPI)
	binary.BigEndian.PutUint32(header[espSPILen:espHeaderLen], pkt.Sequence)

	if c.Encryption == EncryptionAESGCM {
		iv, err := c.explicitIV(pkt.SPI, pkt.Sequence)
		if err != nil {
			return nil, err
		}
		aead, err := newAESGCM(c.EncryptionKey)
		if err != nil {
			return nil, err
		}
		sealed := aead.Seal(nil, nonce(c.Salt, iv), plaintext, header)
		tagStart := len(sealed) - espGCMICVLen
		buf := append([]byte(nil), header...)
		buf = append(buf, iv...)
		buf = append(buf, sealed[:tagStart]...)
		buf = append(buf, sealed[tagStart:]...)
		return buf, nil
	}

	if normalizeIntegrity(c.Integrity) == IntegrityAESGMAC {
		iv, err := c.explicitIV(pkt.SPI, pkt.Sequence)
		if err != nil {
			return nil, err
		}
		aead, err := newAESGCM(c.IntegrityKey)
		if err != nil {
			return nil, err
		}
		wire := append([]byte(nil), header...)
		wire = append(wire, iv...)
		wire = append(wire, plaintext...)
		aad := append([]byte(nil), header...)
		aad = append(aad, plaintext...)
		tag := aead.Seal(nil, nonce(c.Salt, iv), nil, aad)
		return append(wire, tag...), nil
	}

	body := plaintext
	if c.Encryption == EncryptionAESCBC {
		block, err := aes.NewCipher(c.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("creating cipher: %w", err)
		}
		iv := make([]byte, aes.BlockSize)
		r := c.Random
		if r == nil {
			r = rand.Reader
		}
		if _, err := io.ReadFull(r, iv); err != nil {
			return nil, fmt.Errorf("reading IV: %w", err)
		}
		ciphertext := make([]byte, len(plaintext))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
		body = append(iv, ciphertext...)
	} else if c.Encryption == EncryptionAESCTR {
		// RFC 3686 forbids IV reuse with the same key. The ESP sequence number
		// is unique within an SA, so binding the IV to SPI and sequence makes
		// that invariant explicit instead of relying on randomness.
		iv := sequenceIV(pkt.SPI, pkt.Sequence)
		ciphertext, err := aesctr.Crypt(c.EncryptionKey, c.Salt[:], iv, plaintext)
		if err != nil {
			return nil, fmt.Errorf("encrypting AES-CTR payload: %w", err)
		}
		body = append(iv, ciphertext...)
	} else if c.Encryption != EncryptionNull {
		return nil, fmt.Errorf("encoding ESP: unsupported encryption %q", c.Encryption)
	}

	buf := append([]byte(nil), header...)
	buf = append(buf, body...)
	icv, err := c.integritySum(buf)
	if err != nil {
		return nil, err
	}
	buf = append(buf, icv...)
	return buf, nil
}

func (c Codec) Decode(data []byte) (ESPPacket, error) {
	if err := c.validateAlgorithms(); err != nil {
		return ESPPacket{}, fmt.Errorf("decoding ESP: %w", err)
	}
	if len(data) < espHeaderLen {
		return ESPPacket{}, errors.New("decoding ESP: packet too short")
	}
	pkt := ESPPacket{SPI: binary.BigEndian.Uint32(data[:espSPILen]), Sequence: binary.BigEndian.Uint32(data[espSPILen:espHeaderLen])}
	if err := validateESPHeader(pkt.SPI, pkt.Sequence); err != nil {
		return ESPPacket{}, fmt.Errorf("decoding ESP: %w", err)
	}
	if pkt.SPI != c.SPI {
		return ESPPacket{}, fmt.Errorf("decoding ESP: packet SPI 0x%08X does not match codec SPI 0x%08X", pkt.SPI, c.SPI)
	}

	if c.Encryption == EncryptionAESGCM {
		if len(data) < espHeaderLen+espExplicitIVLen+espGCMICVLen {
			return ESPPacket{}, errors.New("decoding ESP: packet too short for AES-GCM")
		}
		header := data[:espHeaderLen]
		iv := data[espHeaderLen : espHeaderLen+espExplicitIVLen]
		ciphertext := data[espHeaderLen+espExplicitIVLen : len(data)-espGCMICVLen]
		tag := data[len(data)-espGCMICVLen:]
		aead, err := newAESGCM(c.EncryptionKey)
		if err != nil {
			return ESPPacket{}, err
		}
		sealed := make([]byte, 0, len(ciphertext)+len(tag))
		sealed = append(sealed, ciphertext...)
		sealed = append(sealed, tag...)
		body, err := aead.Open(nil, nonce(c.Salt, iv), sealed, header)
		if err != nil {
			return ESPPacket{}, errors.New("decoding ESP: integrity check failed")
		}
		return decodePlaintext(pkt, body)
	}

	if normalizeIntegrity(c.Integrity) == IntegrityAESGMAC {
		if len(data) < espHeaderLen+espExplicitIVLen+espTrailerLen+espGCMICVLen {
			return ESPPacket{}, errors.New("decoding ESP: packet too short for AES-GMAC")
		}
		iv := data[espHeaderLen : espHeaderLen+espExplicitIVLen]
		body := data[espHeaderLen+espExplicitIVLen : len(data)-espGCMICVLen]
		tag := data[len(data)-espGCMICVLen:]
		aead, err := newAESGCM(c.IntegrityKey)
		if err != nil {
			return ESPPacket{}, err
		}
		aad := append([]byte(nil), data[:espHeaderLen]...)
		aad = append(aad, body...)
		if _, err := aead.Open(nil, nonce(c.Salt, iv), tag, aad); err != nil {
			return ESPPacket{}, errors.New("decoding ESP: integrity check failed")
		}
		return decodePlaintext(pkt, body)
	}

	icvLen, err := c.integrityLength()
	if err != nil {
		return ESPPacket{}, err
	}
	if icvLen > 0 {
		if len(data) < espHeaderLen+icvLen {
			return ESPPacket{}, errors.New("decoding ESP: packet too short for ICV")
		}
		mac, err := c.integritySum(data[:len(data)-icvLen])
		if err != nil {
			return ESPPacket{}, err
		}
		if !hmac.Equal(mac, data[len(data)-icvLen:]) {
			return ESPPacket{}, errors.New("decoding ESP: integrity check failed")
		}
		data = data[:len(data)-icvLen]
	}

	body := data[espHeaderLen:]
	if c.Encryption == EncryptionAESCBC {
		if len(body) < aes.BlockSize || (len(body)-aes.BlockSize)%aes.BlockSize != 0 {
			return ESPPacket{}, errors.New("decoding ESP: invalid AES-CBC body length")
		}
		block, err := aes.NewCipher(c.EncryptionKey)
		if err != nil {
			return ESPPacket{}, fmt.Errorf("creating cipher: %w", err)
		}
		iv := body[:aes.BlockSize]
		ciphertext := body[aes.BlockSize:]
		plaintext := make([]byte, len(ciphertext))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
		body = plaintext
	} else if c.Encryption == EncryptionAESCTR {
		if len(body) < aesctr.IVSize {
			return ESPPacket{}, errors.New("decoding ESP: invalid AES-CTR body length")
		}
		iv := body[:aesctr.IVSize]
		ciphertext := body[aesctr.IVSize:]
		plaintext, err := aesctr.Crypt(c.EncryptionKey, c.Salt[:], iv, ciphertext)
		if err != nil {
			return ESPPacket{}, fmt.Errorf("decrypting AES-CTR payload: %w", err)
		}
		body = plaintext
	} else if c.Encryption != EncryptionNull {
		return ESPPacket{}, fmt.Errorf("decoding ESP: unsupported encryption %q", c.Encryption)
	}

	return decodePlaintext(pkt, body)
}

func decodePlaintext(pkt ESPPacket, body []byte) (ESPPacket, error) {
	if len(body) < espTrailerLen {
		return ESPPacket{}, errors.New("decoding ESP: missing trailer")
	}
	padLen := int(body[len(body)-espTrailerLen])
	pkt.NextHeader = body[len(body)-1]
	if len(body) < espTrailerLen+padLen {
		return ESPPacket{}, errors.New("decoding ESP: invalid padding")
	}
	padStart := len(body) - espTrailerLen - padLen
	for i := range padLen {
		if body[padStart+i] != byte(i+1) {
			return ESPPacket{}, errors.New("decoding ESP: invalid padding")
		}
	}
	pkt.Payload = append([]byte(nil), body[:len(body)-espTrailerLen-padLen]...)
	return pkt, nil
}

// CryptoPayloadBytes reports how many bytes will be processed by ESP encryption.
func (c Codec) CryptoPayloadBytes(payloadLen int) (uint64, error) {
	if payloadLen < 0 {
		return 0, errors.New("ESP crypto bytes: payload length must be >= 0")
	}
	switch c.Encryption {
	case EncryptionAESCBC, EncryptionAESCTR, EncryptionAESGCM, EncryptionNull:
	default:
		return 0, fmt.Errorf("ESP crypto bytes: unsupported encryption %q", c.Encryption)
	}
	plaintextLen := payloadLen + espTrailerLen
	plaintextLen += paddingLength(plaintextLen, c.blockSize())
	return uint64(plaintextLen), nil
}

// CryptoPacketBytes reports how many received packet bytes were processed by ESP encryption.
func (c Codec) CryptoPacketBytes(packetLen int) (uint64, error) {
	if packetLen < espHeaderLen {
		return 0, errors.New("ESP crypto bytes: packet too short")
	}
	icvLen, err := c.integrityLength()
	if err != nil {
		return 0, err
	}
	if c.Encryption == EncryptionAESGCM {
		icvLen = espGCMICVLen
	}
	if packetLen < espHeaderLen+icvLen {
		return 0, errors.New("ESP crypto bytes: packet too short for ICV")
	}
	bodyLen := packetLen - espHeaderLen - icvLen
	switch c.Encryption {
	case EncryptionAESCBC:
		if bodyLen < aes.BlockSize || (bodyLen-aes.BlockSize)%aes.BlockSize != 0 {
			return 0, errors.New("ESP crypto bytes: invalid AES-CBC body length")
		}
		return uint64(bodyLen - aes.BlockSize), nil
	case EncryptionAESCTR:
		if bodyLen < aesctr.IVSize {
			return 0, errors.New("ESP crypto bytes: invalid AES-CTR body length")
		}
		return uint64(bodyLen - aesctr.IVSize), nil
	case EncryptionAESGCM:
		if bodyLen < espExplicitIVLen {
			return 0, errors.New("ESP crypto bytes: invalid AES-GCM body length")
		}
		return uint64(bodyLen - espExplicitIVLen), nil
	case EncryptionNull:
		if normalizeIntegrity(c.Integrity) == IntegrityAESGMAC {
			if bodyLen < espExplicitIVLen {
				return 0, errors.New("ESP crypto bytes: invalid AES-GMAC body length")
			}
			return uint64(bodyLen - espExplicitIVLen), nil
		}
		return uint64(bodyLen), nil
	default:
		return 0, fmt.Errorf("ESP crypto bytes: unsupported encryption %q", c.Encryption)
	}
}

func (c Codec) integritySum(data []byte) ([]byte, error) {
	length, err := c.integrityLength()
	if err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	if normalizeIntegrity(c.Integrity) == IntegrityAESXCBC96 {
		mac, err := aesxcbc.MAC(c.IntegrityKey, data)
		if err != nil {
			return nil, fmt.Errorf("ESP integrity: %w", err)
		}
		return append([]byte(nil), mac[:length]...), nil
	}
	h, err := c.integrityHash()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(h, c.IntegrityKey)
	_, _ = mac.Write(data)
	return mac.Sum(nil)[:length], nil
}

func (c Codec) validateAlgorithms() error {
	if !ValidSPI(c.SPI) {
		return errors.New("invalid codec SPI")
	}
	switch c.Encryption {
	case EncryptionAESCBC, EncryptionAESCTR, EncryptionAESGCM, EncryptionNull:
	default:
		return fmt.Errorf("unsupported encryption %q", c.Encryption)
	}
	integrity := normalizeIntegrity(c.Integrity)
	switch integrity {
	case IntegrityNone, IntegrityHMACMD596, IntegrityHMACSHA196, IntegrityAESXCBC96, IntegrityHMACSHA256128, IntegrityHMACSHA384192, IntegrityHMACSHA512256, IntegrityAESGMAC:
	default:
		return fmt.Errorf("unsupported integrity %q", c.Integrity)
	}
	if c.Encryption == EncryptionAESGCM && integrity != IntegrityNone {
		return errors.New("AES-GCM requires null integrity")
	}
	if c.Encryption == EncryptionAESCTR && integrity == IntegrityNone {
		return errors.New("AES-CTR requires integrity")
	}
	if integrity == IntegrityAESGMAC && c.Encryption != EncryptionNull {
		return errors.New("AES-GMAC requires null encryption")
	}
	if c.Encryption == EncryptionNull && integrity == IntegrityNone {
		return errors.New("encryption and integrity must not both be null")
	}
	if c.Encryption == EncryptionAESCBC || c.Encryption == EncryptionAESCTR || c.Encryption == EncryptionAESGCM {
		if !validAESKeyLength(len(c.EncryptionKey)) {
			return fmt.Errorf("invalid AES encryption key length %d", len(c.EncryptionKey))
		}
	}
	if integrity == IntegrityAESGMAC {
		if !validAESKeyLength(len(c.IntegrityKey)) {
			return fmt.Errorf("invalid AES-GMAC key length %d", len(c.IntegrityKey))
		}
	} else if integrity == IntegrityAESXCBC96 && len(c.IntegrityKey) != aesxcbc.KeySize {
		return fmt.Errorf("invalid AES-XCBC key length %d", len(c.IntegrityKey))
	} else if integrity == IntegrityHMACSHA256128 && len(c.IntegrityKey) != sha256.Size {
		return fmt.Errorf("invalid HMAC-SHA256 key length %d", len(c.IntegrityKey))
	} else if integrity == IntegrityHMACSHA384192 && len(c.IntegrityKey) != sha512.Size384 {
		return fmt.Errorf("invalid HMAC-SHA384 key length %d", len(c.IntegrityKey))
	} else if integrity == IntegrityHMACSHA512256 && len(c.IntegrityKey) != sha512.Size {
		return fmt.Errorf("invalid HMAC-SHA512 key length %d", len(c.IntegrityKey))
	} else if integrity != IntegrityNone && len(c.IntegrityKey) == 0 {
		return errors.New("integrity key is empty")
	}
	return nil
}

func validAESKeyLength(length int) bool {
	return length == 16 || length == 24 || length == 32
}

func (c Codec) integrityHash() (func() hash.Hash, error) {
	switch normalizeIntegrity(c.Integrity) {
	case IntegrityNone:
		return nil, nil
	case IntegrityHMACMD596:
		return md5.New, nil
	case IntegrityHMACSHA196:
		return sha1.New, nil
	case IntegrityHMACSHA256128:
		return sha256.New, nil
	case IntegrityHMACSHA384192:
		return sha512.New384, nil
	case IntegrityHMACSHA512256:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("ESP integrity: unsupported integrity %q", c.Integrity)
	}
}

func (c Codec) integrityLength() (int, error) {
	switch normalizeIntegrity(c.Integrity) {
	case IntegrityNone:
		return 0, nil
	case IntegrityHMACMD596, IntegrityHMACSHA196, IntegrityAESXCBC96:
		return 12, nil
	case IntegrityHMACSHA256128, IntegrityAESGMAC:
		return 16, nil
	case IntegrityHMACSHA384192:
		return 24, nil
	case IntegrityHMACSHA512256:
		return 32, nil
	default:
		return 0, fmt.Errorf("ESP integrity: unsupported integrity %q", c.Integrity)
	}
}

func paddingLength(length, blockSize int) int {
	if blockSize == 1 {
		return 0
	}
	if rem := length % blockSize; rem != 0 {
		return blockSize - rem
	}
	return 0
}

func (c Codec) blockSize() int {
	if c.Encryption == EncryptionAESCBC {
		return aes.BlockSize
	}
	return espDefaultAlign
}

func normalizeIntegrity(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case IntegrityNull:
		return IntegrityNone
	case IntegrityHMACSHA196RFC:
		return IntegrityHMACSHA196
	case IntegrityHMACSHA256RFC:
		return IntegrityHMACSHA256128
	case IntegrityAESGMACUS:
		return IntegrityAESGMAC
	default:
		return value
	}
}

func (c Codec) explicitIV(spi, sequence uint32) ([]byte, error) {
	if c.Random == nil {
		return sequenceIV(spi, sequence), nil
	}
	iv := make([]byte, espExplicitIVLen)
	if _, err := io.ReadFull(c.Random, iv); err != nil {
		return nil, fmt.Errorf("reading IV: %w", err)
	}
	return iv, nil
}

func sequenceIV(spi, sequence uint32) []byte {
	iv := make([]byte, espExplicitIVLen)
	binary.BigEndian.PutUint32(iv[:4], spi)
	binary.BigEndian.PutUint32(iv[4:], sequence)
	return iv
}

func nonce(salt [4]byte, iv []byte) []byte {
	value := make([]byte, 0, len(salt)+len(iv))
	value = append(value, salt[:]...)
	return append(value, iv...)
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	aead, err := cipher.NewGCMWithTagSize(block, espGCMICVLen)
	if err != nil {
		return nil, fmt.Errorf("creating AEAD: %w", err)
	}
	return aead, nil
}
