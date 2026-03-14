package esp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync"
)

const (
	EncryptionNull   = "null"
	EncryptionAESCBC = "aes-cbc"
)

const (
	IntegrityNone          = "none"
	IntegrityHMACMD596     = "hmac-md5-96"
	IntegrityHMACSHA196    = "hmac-sha1-96"
	IntegrityHMACSHA256128 = "hmac-sha256-128"
)

var (
	_ encoding.BinaryMarshaler   = ESPPacket{}
	_ encoding.BinaryUnmarshaler = (*ESPPacket)(nil)
)

type ESPPacket struct {
	SPI        uint32
	Sequence   uint32
	NextHeader byte
	Payload    []byte
}

func (p ESPPacket) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[:4], p.SPI)
	binary.BigEndian.PutUint32(buf[4:8], p.Sequence)
	buf = append(buf, p.Payload...)
	buf = append(buf, 0x00, p.NextHeader)
	return buf, nil
}

func (p *ESPPacket) UnmarshalBinary(data []byte) error {
	if len(data) < 10 {
		return errors.New("parsing esp packet: packet too short")
	}
	padLen := int(data[len(data)-2])
	if len(data) < 10+padLen {
		return errors.New("parsing esp packet: invalid padding")
	}
	payloadEnd := len(data) - 2 - padLen
	for i := range padLen {
		if data[payloadEnd+i] != byte(i+1) {
			return errors.New("parsing esp packet: invalid padding")
		}
	}
	*p = ESPPacket{
		SPI:        binary.BigEndian.Uint32(data[:4]),
		Sequence:   binary.BigEndian.Uint32(data[4:8]),
		NextHeader: data[len(data)-1],
		Payload:    append([]byte(nil), data[8:payloadEnd]...),
	}
	return nil
}

type Codec struct {
	SPI           uint32
	Encryption    string
	Integrity     string
	EncryptionKey []byte
	IntegrityKey  []byte
	Random        io.Reader
}

type Config struct {
	SPI  uint32
	Key  []byte
	Salt [4]byte
}

type ESP struct {
	mu     sync.Mutex
	codec  Codec
	salt   [4]byte
	seq    uint32
	replay ReplayWindow
}

func NewESP(cfg Config) (*ESP, error) {
	if len(cfg.Key) != 16 {
		return nil, errors.New("creating ESP: expected 16-byte AES key")
	}
	return &ESP{
		codec: Codec{
			SPI:           cfg.SPI,
			Encryption:    EncryptionAESCBC,
			Integrity:     IntegrityHMACSHA196,
			EncryptionKey: append([]byte(nil), cfg.Key...),
			IntegrityKey:  append([]byte(nil), cfg.Key...),
		},
		salt: cfg.Salt,
	}, nil
}

func (e *ESP) Seal(payload []byte) ([]byte, error) {
	e.mu.Lock()
	seq, ok := NextSequence(&e.seq)
	codec := e.codec
	salt := e.salt
	e.mu.Unlock()
	if !ok {
		return nil, errors.New("encoding ESP: sequence number overflow")
	}
	iv := make([]byte, aes.BlockSize)
	copy(iv[:4], salt[:])
	binary.BigEndian.PutUint32(iv[12:], seq)
	codec.Random = bytes.NewReader(iv)
	return codec.Encode(ESPPacket{SPI: codec.SPI, Sequence: seq, NextHeader: 0x3B, Payload: payload})
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
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.replay.Accept(pkt.Sequence) {
		return nil, fmt.Errorf("decoding ESP: replayed packet sequence %d", pkt.Sequence)
	}
	return pkt.Payload, nil
}

func (c Codec) Encode(pkt ESPPacket) ([]byte, error) {
	plaintext := append([]byte(nil), pkt.Payload...)
	padLen := paddingLength(len(plaintext)+2, c.blockSize())
	for i := 1; i <= padLen; i++ {
		plaintext = append(plaintext, byte(i))
	}
	plaintext = append(plaintext, byte(padLen), pkt.NextHeader)

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
	} else if c.Encryption != EncryptionNull {
		return nil, fmt.Errorf("encoding ESP: unsupported encryption %q", c.Encryption)
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[:4], pkt.SPI)
	binary.BigEndian.PutUint32(buf[4:8], pkt.Sequence)
	buf = append(buf, body...)
	icv, err := c.integritySum(buf)
	if err != nil {
		return nil, err
	}
	buf = append(buf, icv...)
	return buf, nil
}

func (c Codec) Decode(data []byte) (ESPPacket, error) {
	if len(data) < 8 {
		return ESPPacket{}, errors.New("decoding ESP: packet too short")
	}
	icvLen, err := c.integrityLength()
	if err != nil {
		return ESPPacket{}, err
	}
	if icvLen > 0 {
		if len(data) < 8+icvLen {
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

	pkt := ESPPacket{SPI: binary.BigEndian.Uint32(data[:4]), Sequence: binary.BigEndian.Uint32(data[4:8])}
	body := data[8:]
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
	} else if c.Encryption != EncryptionNull {
		return ESPPacket{}, fmt.Errorf("decoding ESP: unsupported encryption %q", c.Encryption)
	}

	if len(body) < 2 {
		return ESPPacket{}, errors.New("decoding ESP: missing trailer")
	}
	padLen := int(body[len(body)-2])
	pkt.NextHeader = body[len(body)-1]
	if len(body) < 2+padLen {
		return ESPPacket{}, errors.New("decoding ESP: invalid padding")
	}
	padStart := len(body) - 2 - padLen
	for i := range padLen {
		if body[padStart+i] != byte(i+1) {
			return ESPPacket{}, errors.New("decoding ESP: invalid padding")
		}
	}
	pkt.Payload = append([]byte(nil), body[:len(body)-2-padLen]...)
	return pkt, nil
}

func (c Codec) integritySum(data []byte) ([]byte, error) {
	length, err := c.integrityLength()
	if err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	h, err := c.integrityHash()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(h, c.IntegrityKey)
	_, _ = mac.Write(data)
	return mac.Sum(nil)[:length], nil
}

func (c Codec) integrityHash() (func() hash.Hash, error) {
	switch c.Integrity {
	case IntegrityNone:
		return nil, nil
	case IntegrityHMACMD596:
		return md5.New, nil
	case IntegrityHMACSHA196:
		return sha1.New, nil
	case IntegrityHMACSHA256128:
		return sha256.New, nil
	default:
		return nil, fmt.Errorf("ESP integrity: unsupported integrity %q", c.Integrity)
	}
}

func (c Codec) integrityLength() (int, error) {
	switch c.Integrity {
	case IntegrityNone:
		return 0, nil
	case IntegrityHMACMD596, IntegrityHMACSHA196:
		return 12, nil
	case IntegrityHMACSHA256128:
		return 16, nil
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
	return 1
}
