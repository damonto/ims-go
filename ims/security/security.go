package security

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"github.com/damonto/vowifi-go/usim"
)

const AlgorithmAKAv1MD5 = "AKAv1-MD5"
const AlgorithmAKAv2MD5 = "AKAv2-MD5"
const AlgorithmAKAv2SHA256 = "AKAv2-SHA-256"

const (
	digestAKAv2PasswordLabel = "http-digest-akav2-password"
	digestAKAv2IKLabel       = "http-digest-akav2-integritykey"
	digestAKAv2CKLabel       = "http-digest-akav2-cipherkey"
	digestCNonceHexLength    = 16
	digestNonceCountWidth    = 8
	akaRANDLength            = 16
	akaAUTNLength            = 16
	akaNonceMinLength        = akaRANDLength + akaAUTNLength
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
	NextNonce  string
	QOP        string
	RSPAuth    string
	CNonce     string
	NonceCount string
}

type Authorization struct {
	Nonce              string
	URI                string
	Response           string
	Username           string
	Realm              string
	Algorithm          string
	IntegrityProtected string
	QOP                string
	NonceCount         string
	CNonce             string
	AUTS               string
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
	Authorization  Authorization
	EncryptionKey  []byte
	IntegrityKey   []byte
	DigestPassword string
}

type AKAChallengeFailure struct {
	AUTS   []byte
	Reject bool
}

func (e *AKAChallengeFailure) Error() string {
	if e.SynchronizationFailure() {
		return "aka synchronization failure"
	}
	return "aka network authentication failure"
}

func (e *AKAChallengeFailure) SynchronizationFailure() bool {
	return len(e.AUTS) != 0
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
	if !supportedEncryptionAlg(p.EAlg) || !strings.EqualFold(p.Mod, "trans") || !strings.EqualFold(p.Prot, "esp") {
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
	algorithm, ok := normalizeAKAAlgorithm(challenge.Algorithm)
	if !ok {
		return AKAResult{}, fmt.Errorf("selecting AKA algorithm: unsupported algorithm %q", challenge.Algorithm)
	}
	nonceBytes, err := base64.StdEncoding.DecodeString(challenge.Nonce)
	if err != nil {
		return AKAResult{}, fmt.Errorf("decoding auth nonce: %w", err)
	}
	if len(nonceBytes) < akaNonceMinLength {
		return AKAResult{}, errors.New("decoding auth nonce: expected at least 32 bytes")
	}
	aka, err := authenticateDigestAKA(ctx, card, nonceBytes)
	if err != nil {
		return AKAResult{}, fmt.Errorf("calculating AKA response: %w", err)
	}

	password, ck, ik := akaDigestMaterial(algorithm, aka)
	auth, err := BuildDigestAuthorization(id, challenge, nonceCount, password)
	if err != nil {
		return AKAResult{}, err
	}
	return AKAResult{
		Authorization:  auth,
		EncryptionKey:  ck,
		IntegrityKey:   ik,
		DigestPassword: password,
	}, nil
}

func BuildDigestAuthorization(id Identity, challenge Challenge, nonceCount uint32, password string) (Authorization, error) {
	algorithm, ok := normalizeAKAAlgorithm(challenge.Algorithm)
	if !ok {
		return Authorization{}, fmt.Errorf("selecting AKA algorithm: unsupported algorithm %q", challenge.Algorithm)
	}
	if password == "" {
		return Authorization{}, errors.New("building AKA authorization: digest password is empty")
	}
	auth := Authorization{
		Nonce:     challenge.Nonce,
		URI:       id.RegisterURI,
		Username:  id.PrivateIdentity,
		Realm:     id.Realm,
		Algorithm: algorithm.name,
	}
	if strings.TrimSpace(auth.Realm) == "" {
		auth.Realm = strings.TrimPrefix(id.RegisterURI, "sip:")
	}
	qop, err := challenge.SelectedQOP()
	if err != nil {
		return Authorization{}, err
	}
	if qop != "" {
		auth.QOP = qop
		auth.NonceCount = fmt.Sprintf("%0*x", digestNonceCountWidth, nonceCount)
		auth.CNonce = randomHex(digestCNonceHexLength)
	}
	response, err := computeAKAResponse(algorithm.hash, "REGISTER", id.PrivateIdentity, auth.Realm, id.RegisterURI, challenge.Nonce, password, auth.QOP, auth.CNonce, auth.NonceCount)
	if err != nil {
		return Authorization{}, err
	}
	auth.Response = response
	return auth, nil
}

func VerifyAuthenticationInfo(auth Authorization, info Info, password string) error {
	if strings.TrimSpace(info.RSPAuth) == "" {
		return nil
	}
	algorithm, ok := normalizeAKAAlgorithm(auth.Algorithm)
	if !ok {
		return fmt.Errorf("verifying authentication-info: unsupported algorithm %q", auth.Algorithm)
	}
	if password == "" {
		return errors.New("verifying authentication-info: digest password is empty")
	}
	qop := auth.QOP
	if info.QOP != "" {
		if qop != "" && !strings.EqualFold(info.QOP, qop) {
			return fmt.Errorf("verifying authentication-info: qop %q does not match authorization qop %q", info.QOP, qop)
		}
		qop = info.QOP
	}
	cnonce := auth.CNonce
	if info.CNonce != "" {
		if cnonce != "" && info.CNonce != cnonce {
			return errors.New("verifying authentication-info: cnonce does not match authorization")
		}
		cnonce = info.CNonce
	}
	nonceCount := auth.NonceCount
	if info.NonceCount != "" {
		if nonceCount != "" && !strings.EqualFold(info.NonceCount, nonceCount) {
			return errors.New("verifying authentication-info: nonce count does not match authorization")
		}
		nonceCount = info.NonceCount
	}
	expected, err := computeAKAResponse(algorithm.hash, "", auth.Username, auth.Realm, auth.URI, auth.Nonce, password, qop, cnonce, nonceCount)
	if err != nil {
		return fmt.Errorf("verifying authentication-info: %w", err)
	}
	if !strings.EqualFold(info.RSPAuth, expected) {
		return errors.New("verifying authentication-info: rspauth mismatch")
	}
	return nil
}

func authenticateDigestAKA(ctx context.Context, card AKAProvider, nonce []byte) (usim.AKAResult, error) {
	aka, err := card.AKA(ctx, nonce[:akaRANDLength], nonce[akaRANDLength:akaNonceMinLength])
	if err == nil {
		if digestAKAUsable(aka) {
			return aka, nil
		}
		if failure := akaChallengeFailure(aka); failure != nil {
			return usim.AKAResult{}, failure
		}
		err = errors.New("standard nonce order response missing RES, CK, or IK")
	}
	reversed, reverseErr := card.AKA(ctx, nonce[akaRANDLength:akaNonceMinLength], nonce[:akaRANDLength])
	if reverseErr == nil {
		if digestAKAUsable(reversed) {
			return reversed, nil
		}
		if failure := akaChallengeFailure(reversed); failure != nil {
			return usim.AKAResult{}, failure
		}
		reverseErr = errors.New("reversed nonce order response missing RES, CK, or IK")
	}
	return usim.AKAResult{}, errors.Join(err, reverseErr)
}

func digestAKAUsable(aka usim.AKAResult) bool {
	return len(aka.RES) != 0 && len(aka.CK) != 0 && len(aka.IK) != 0
}

func akaChallengeFailure(aka usim.AKAResult) *AKAChallengeFailure {
	if aka.IsSynchronizationFailure() {
		return &AKAChallengeFailure{AUTS: append([]byte(nil), aka.AUTS...)}
	}
	if aka.IsAuthenticationReject() {
		return &AKAChallengeFailure{Reject: true}
	}
	return nil
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

func (ps Params) MarshalText() ([]byte, error) {
	values := make([]string, 0, len(ps))
	for _, param := range ps {
		text, err := param.MarshalText()
		if err != nil {
			return nil, err
		}
		values = append(values, string(text))
	}
	return []byte(strings.Join(values, ",")), nil
}

func (c *Challenge) UnmarshalText(text []byte) error {
	value := string(text)
	if !strings.HasPrefix(strings.ToLower(value), "digest ") {
		return errors.New("parsing auth challenge: unsupported scheme")
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
		return errors.New("parsing auth challenge: nonce is empty")
	}
	algorithm, ok := normalizeAKAAlgorithm(challenge.Algorithm)
	if !ok {
		return fmt.Errorf("parsing auth challenge: unsupported algorithm %q", challenge.Algorithm)
	}
	challenge.Algorithm = algorithm.name
	*c = challenge
	return nil
}

func (i *Info) UnmarshalText(text []byte) error {
	info := Info{}
	for _, field := range splitHeaderFields(string(text)) {
		name, rawValue, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			continue
		}
		value := strings.Trim(strings.TrimSpace(rawValue), "\"")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "nextnonce":
			info.NextNonce = value
		case "qop":
			info.QOP = value
		case "rspauth":
			info.RSPAuth = value
		case "cnonce":
			info.CNonce = value
		case "nc":
			info.NonceCount = value
		}
	}
	*i = info
	return nil
}

func (i Info) MarshalText() ([]byte, error) {
	fields := make([]string, 0, 5)
	if i.NextNonce != "" {
		fields = append(fields, fmt.Sprintf(`nextnonce="%s"`, i.NextNonce))
	}
	if i.QOP != "" {
		fields = append(fields, "qop="+i.QOP)
	}
	if i.RSPAuth != "" {
		fields = append(fields, fmt.Sprintf(`rspauth="%s"`, i.RSPAuth))
	}
	if i.CNonce != "" {
		fields = append(fields, fmt.Sprintf(`cnonce="%s"`, i.CNonce))
	}
	if i.NonceCount != "" {
		fields = append(fields, "nc="+i.NonceCount)
	}
	return []byte(strings.Join(fields, ",")), nil
}

func (a Authorization) MarshalText() ([]byte, error) {
	algorithm := a.Algorithm
	if algorithm == "" {
		algorithm = AlgorithmAKAv1MD5
	}
	value := fmt.Sprintf(`Digest nonce="%s",uri="%s",realm="%s",username="%s",response="%s",algorithm=%s`, a.Nonce, a.URI, a.Realm, a.Username, a.Response, algorithm)
	if a.IntegrityProtected != "" {
		value += fmt.Sprintf(`,integrity-protected=%s`, a.IntegrityProtected)
	}
	if a.QOP != "" {
		value += fmt.Sprintf(`,qop=%s,nc=%s,cnonce="%s"`, a.QOP, a.NonceCount, a.CNonce)
	}
	if a.AUTS != "" {
		value += fmt.Sprintf(`,auts="%s"`, a.AUTS)
	}
	return []byte(value), nil
}

func (p Param) String() string {
	text, _ := p.MarshalText()
	return string(text)
}

func (ps Params) String() string {
	text, _ := ps.MarshalText()
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
		name = strings.ToLower(strings.TrimSpace(name))
		value := strings.TrimSpace(rawValue)
		switch name {
		case "alg":
			param.Alg = value
		case "ealg":
			param.EAlg = value
		case "mod":
			param.Mod = value
		case "prot":
			param.Prot = value
		case "port-c":
			port, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("parsing security header port-c %q: %w", value, err)
			}
			param.PortC = port
		case "port-s":
			port, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("parsing security header port-s %q: %w", value, err)
			}
			param.PortS = port
		case "spi-c":
			value64, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return fmt.Errorf("parsing security header spi-c %q: %w", value, err)
			}
			param.SPIC = uint32(value64)
		case "spi-s":
			value64, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return fmt.Errorf("parsing security header spi-s %q: %w", value, err)
			}
			param.SPIS = uint32(value64)
		case "q":
			param.Q = value
		}
	}
	*p = param
	return nil
}

func normalizeIntegrityAlg(alg string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(alg)) {
	case "hmac-sha-1-96", "hmac-sha1-96":
		return "hmac-sha1-96", true
	case "hmac-sha-256-128", "hmac-sha256-128":
		return "hmac-sha256-128", true
	default:
		return "", false
	}
}

func supportedEncryptionAlg(alg string) bool {
	switch strings.ToLower(strings.TrimSpace(alg)) {
	case "aes-cbc", "null":
		return true
	default:
		return false
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

type akaAlgorithm struct {
	name    string
	version int
	hash    func() hash.Hash
}

func normalizeAKAAlgorithm(algorithm string) (akaAlgorithm, bool) {
	name, ok := NormalizeAKAAlgorithm(algorithm)
	if !ok {
		return akaAlgorithm{}, false
	}
	switch {
	case name == AlgorithmAKAv1MD5:
		return akaAlgorithm{name: AlgorithmAKAv1MD5, version: 1, hash: md5.New}, true
	case name == AlgorithmAKAv2MD5:
		return akaAlgorithm{name: AlgorithmAKAv2MD5, version: 2, hash: md5.New}, true
	case name == AlgorithmAKAv2SHA256:
		return akaAlgorithm{name: AlgorithmAKAv2SHA256, version: 2, hash: sha256.New}, true
	default:
		return akaAlgorithm{}, false
	}
}

func NormalizeAKAAlgorithm(algorithm string) (string, bool) {
	switch {
	case strings.EqualFold(strings.TrimSpace(algorithm), AlgorithmAKAv1MD5):
		return AlgorithmAKAv1MD5, true
	case strings.EqualFold(strings.TrimSpace(algorithm), AlgorithmAKAv2MD5):
		return AlgorithmAKAv2MD5, true
	case strings.EqualFold(strings.TrimSpace(algorithm), AlgorithmAKAv2SHA256):
		return AlgorithmAKAv2SHA256, true
	default:
		return "", false
	}
}

func akaDigestMaterial(algorithm akaAlgorithm, aka usim.AKAResult) (password string, ck, ik []byte) {
	if algorithm.version == 2 {
		secret := make([]byte, 0, len(aka.RES)+len(aka.IK)+len(aka.CK))
		secret = append(secret, aka.RES...)
		secret = append(secret, aka.IK...)
		secret = append(secret, aka.CK...)
		return base64.StdEncoding.EncodeToString(hmacDigest(algorithm.hash, secret, []byte(digestAKAv2PasswordLabel))),
			hmacDigest(algorithm.hash, aka.CK, []byte(digestAKAv2CKLabel)),
			hmacDigest(algorithm.hash, aka.IK, []byte(digestAKAv2IKLabel))
	}
	return string(aka.RES), append([]byte(nil), aka.CK...), append([]byte(nil), aka.IK...)
}

func hmacDigest(newHash func() hash.Hash, secret, data []byte) []byte {
	mac := hmac.New(newHash, secret)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func computeAKAResponse(newHash func() hash.Hash, method, privateIdentity, realm, registerURI, nonce, password, qop, cnonce, nonceCount string) (string, error) {
	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return "", fmt.Errorf("decoding nonce: %w", err)
	}
	if len(nonceBytes) < akaNonceMinLength {
		return "", fmt.Errorf("decoding nonce: expected at least %d bytes, got %d", akaNonceMinLength, len(nonceBytes))
	}
	a1 := privateIdentity + ":" + realm + ":" + password
	a2 := method + ":" + registerURI
	h1 := digestHex(newHash, a1)
	h2 := digestHex(newHash, a2)
	data := h1 + ":" + nonce + ":"
	if qop != "" {
		if cnonce == "" || nonceCount == "" {
			return "", errors.New("computing AKA response: qop requires cnonce and nonce count")
		}
		data += nonceCount + ":" + cnonce + ":" + qop + ":"
	}
	data += h2
	return digestHex(newHash, data), nil
}

func digestHex(newHash func() hash.Hash, value string) string {
	digest := newHash()
	_, _ = digest.Write([]byte(value))
	return hex.EncodeToString(digest.Sum(nil))
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
