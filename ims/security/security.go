package security

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/damonto/ims-client/usim"
)

type Param struct {
	Mechanism string
	Alg       string
	EAlg      string
	Mod       string
	PortC     int
	PortS     int
	Prot      string
	SPIC      uint32
	SPIS      uint32
	Q         string
}

type Params []Param

type Challenge struct {
	Realm     string
	Nonce     string
	Algorithm string
	QOP       string
}

type Info struct {
	NextNonce string
}

type Authorization struct {
	Nonce      string
	URI        string
	Response   string
	Username   string
	Realm      string
	QOP        string
	NonceCount string
	CNonce     string
}

type Identity struct {
	PrivateIdentity string
	RegisterURI     string
	Realm           string
}

type AKAProvider interface {
	AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error)
}

type AKAResult struct {
	Authorization Authorization
	IntegrityKey  []byte
}

func NormalizeParam(p Param) (Param, bool) {
	if !strings.EqualFold(p.Mechanism, "ipsec-3gpp") {
		return Param{}, false
	}
	if p.Mod == "" {
		p.Mod = "trans"
	}
	if p.Prot == "" {
		p.Prot = "esp"
	}
	if !strings.EqualFold(p.EAlg, "null") || !strings.EqualFold(p.Mod, "trans") || !strings.EqualFold(p.Prot, "esp") {
		return Param{}, false
	}
	alg, ok := normalizeIntegrityAlg(p.Alg)
	if !ok || p.PortC == 0 || p.PortS == 0 || p.SPIC == 0 || p.SPIS == 0 {
		return Param{}, false
	}
	p.Alg = alg
	return p, true
}

func (c Challenge) SelectedQOP() (string, error) {
	if strings.TrimSpace(c.QOP) == "" {
		return "", nil
	}
	for _, candidate := range strings.Split(c.QOP, ",") {
		if strings.EqualFold(strings.TrimSpace(candidate), "auth") {
			return "auth", nil
		}
	}
	return "", fmt.Errorf("selecting auth qop: unsupported qop %q", c.QOP)
}

func BuildAKAAuthorization(ctx context.Context, card AKAProvider, id Identity, challenge Challenge, nonceCount uint32) (AKAResult, error) {
	nonceBytes, err := base64.StdEncoding.DecodeString(challenge.Nonce)
	if err != nil {
		return AKAResult{}, fmt.Errorf("decoding auth nonce: %w", err)
	}
	if len(nonceBytes) < 32 {
		return AKAResult{}, fmt.Errorf("decoding auth nonce: expected at least 32 bytes")
	}
	aka, err := card.AKA(ctx, nonceBytes[:16], nonceBytes[16:32])
	if err != nil {
		return AKAResult{}, fmt.Errorf("calculating AKA response: %w", err)
	}

	auth := Authorization{
		Nonce:    challenge.Nonce,
		URI:      id.RegisterURI,
		Username: id.PrivateIdentity,
		Realm:    id.Realm,
	}
	if strings.TrimSpace(auth.Realm) == "" {
		auth.Realm = strings.TrimPrefix(id.RegisterURI, "sip:")
	}
	qop, err := challenge.SelectedQOP()
	if err != nil {
		return AKAResult{}, err
	}
	if qop != "" {
		auth.QOP = qop
		auth.NonceCount = fmt.Sprintf("%08x", nonceCount)
		auth.CNonce = randomHex(16)
	}
	response, err := computeAKAResponse(id.PrivateIdentity, auth.Realm, id.RegisterURI, challenge.Nonce, aka, auth.QOP, auth.CNonce, auth.NonceCount)
	if err != nil {
		return AKAResult{}, err
	}
	auth.Response = response
	return AKAResult{
		Authorization: auth,
		IntegrityKey:  append([]byte(nil), aka.IK...),
	}, nil
}

func (p Param) MarshalText() ([]byte, error) {
	value := fmt.Sprintf("%s;alg=%s;ealg=%s;mod=%s;port-c=%d;port-s=%d;prot=%s;spi-c=%d;spi-s=%d", p.Mechanism, p.Alg, p.EAlg, p.Mod, p.PortC, p.PortS, p.Prot, p.SPIC, p.SPIS)
	if p.Q != "" {
		value += ";q=" + p.Q
	}
	return []byte(value), nil
}

func (p *Param) UnmarshalText(text []byte) error {
	return p.unmarshalText(string(text))
}

func (ps *Params) UnmarshalText(text []byte) error {
	parts := strings.Split(string(text), ",")
	params := make(Params, 0, len(parts))
	for _, part := range parts {
		var param Param
		if err := param.unmarshalText(part); err != nil {
			return err
		}
		params = append(params, param)
	}
	*ps = params
	return nil
}

func (c *Challenge) UnmarshalText(text []byte) error {
	value := string(text)
	if !strings.HasPrefix(value, "Digest ") {
		return fmt.Errorf("parsing auth challenge: unsupported scheme")
	}
	challenge := Challenge{}
	for _, field := range splitHeaderFields(value[len("Digest "):]) {
		name, rawValue, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			continue
		}
		value := strings.Trim(strings.TrimSpace(rawValue), "\"")
		switch strings.ToLower(name) {
		case "realm":
			challenge.Realm = value
		case "nonce":
			challenge.Nonce = value
		case "algorithm":
			challenge.Algorithm = value
		case "qop":
			challenge.QOP = value
		}
	}
	if challenge.Nonce == "" {
		return fmt.Errorf("parsing auth challenge: nonce is empty")
	}
	*c = challenge
	return nil
}

func (i *Info) UnmarshalText(text []byte) error {
	info := Info{}
	for _, field := range splitHeaderFields(string(text)) {
		name, rawValue, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok || !strings.EqualFold(name, "nextnonce") {
			continue
		}
		info.NextNonce = strings.Trim(rawValue, "\"")
		break
	}
	*i = info
	return nil
}

func (a Authorization) MarshalText() ([]byte, error) {
	value := fmt.Sprintf(`Digest nonce="%s",uri="%s",response="%s",username="%s",algorithm=AKAv1-MD5,realm="%s"`, a.Nonce, a.URI, a.Response, a.Username, a.Realm)
	if a.QOP != "" {
		value += fmt.Sprintf(`,qop=%s,nc=%s,cnonce="%s"`, a.QOP, a.NonceCount, a.CNonce)
	}
	return []byte(value), nil
}

func (p Param) String() string {
	text, _ := p.MarshalText()
	return string(text)
}

func (a Authorization) String() string {
	text, _ := a.MarshalText()
	return string(text)
}

func (p *Param) unmarshalText(text string) error {
	fields := strings.Split(strings.TrimSpace(text), ";")
	if len(fields) == 0 {
		*p = Param{}
		return nil
	}
	param := Param{Mechanism: strings.TrimSpace(fields[0])}
	for _, field := range fields[1:] {
		name, rawValue, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			continue
		}
		switch strings.ToLower(name) {
		case "alg":
			param.Alg = rawValue
		case "ealg":
			param.EAlg = rawValue
		case "mod":
			param.Mod = rawValue
		case "prot":
			param.Prot = rawValue
		case "port-c":
			port, err := strconv.Atoi(rawValue)
			if err != nil {
				return fmt.Errorf("parsing security header port-c %q: %w", rawValue, err)
			}
			param.PortC = port
		case "port-s":
			port, err := strconv.Atoi(rawValue)
			if err != nil {
				return fmt.Errorf("parsing security header port-s %q: %w", rawValue, err)
			}
			param.PortS = port
		case "spi-c":
			value64, err := strconv.ParseUint(rawValue, 10, 32)
			if err != nil {
				return fmt.Errorf("parsing security header spi-c %q: %w", rawValue, err)
			}
			param.SPIC = uint32(value64)
		case "spi-s":
			value64, err := strconv.ParseUint(rawValue, 10, 32)
			if err != nil {
				return fmt.Errorf("parsing security header spi-s %q: %w", rawValue, err)
			}
			param.SPIS = uint32(value64)
		case "q":
			param.Q = rawValue
		}
	}
	*p = param
	return nil
}

func normalizeIntegrityAlg(alg string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(alg)) {
	case "hmac-md5-96":
		return "hmac-md5-96", true
	case "hmac-sha-1-96", "hmac-sha1-96":
		return "hmac-sha1-96", true
	case "hmac-sha-256-128", "hmac-sha256-128":
		return "hmac-sha256-128", true
	default:
		return "", false
	}
}

func splitHeaderFields(value string) []string {
	fields := make([]string, 0, strings.Count(value, ",")+1)
	start := 0
	inQuotes := false
	for i := range len(value) {
		switch value[i] {
		case '"':
			inQuotes = !inQuotes
		case ',':
			if inQuotes {
				continue
			}
			fields = append(fields, value[start:i])
			start = i + 1
		}
	}
	fields = append(fields, value[start:])
	return fields
}

func computeAKAResponse(privateIdentity, realm, registerURI, nonce string, result usim.AKAResult, qop, cnonce, nonceCount string) (string, error) {
	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return "", fmt.Errorf("decoding nonce: %w", err)
	}
	if len(nonceBytes) < 32 {
		return "", fmt.Errorf("decoding nonce: expected at least 32 bytes, got %d", len(nonceBytes))
	}
	a1 := privateIdentity + ":" + realm + ":" + string(result.RES)
	a2 := "REGISTER:" + registerURI
	h1 := md5.Sum([]byte(a1))
	h2 := md5.Sum([]byte(a2))
	data := hex.EncodeToString(h1[:]) + ":" + nonce + ":"
	if qop != "" {
		if cnonce == "" || nonceCount == "" {
			return "", fmt.Errorf("computing AKA response: qop requires cnonce and nonce count")
		}
		data += nonceCount + ":" + cnonce + ":" + qop + ":"
	}
	data += hex.EncodeToString(h2[:])
	h3 := md5.Sum([]byte(data))
	return hex.EncodeToString(h3[:]), nil
}

func randomHex(length int) string {
	return randomString(length, "0123456789abcdef")
}

func randomString(length int, alphabet string) string {
	buf := make([]byte, length)
	rnd := make([]byte, length)
	_, _ = rand.Read(rnd)
	for i, b := range rnd {
		buf[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(buf)
}
