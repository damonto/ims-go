package security

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	usim "github.com/damonto/wwan-go/sim"
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
	maxIPPort                = 65535
	standardSIPPort          = 5060
	standardSIPSPort         = 5061
	minUnreservedESPSPI      = 256
	// Keep locally generated SPI values in the TS 33.203 10DIGIT wire form.
	ipsecSPIDecimalWidth = 10
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
	Opaque    string
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
	Opaque             string
}

var (
	_ encoding.TextMarshaler   = Param{}
	_ encoding.TextUnmarshaler = (*Param)(nil)
	_ fmt.Stringer             = Param{}

	_ encoding.TextMarshaler   = Params{}
	_ encoding.TextUnmarshaler = (*Params)(nil)
	_ fmt.Stringer             = Params{}

	_ encoding.TextUnmarshaler = (*Challenge)(nil)

	_ encoding.TextMarshaler   = Info{}
	_ encoding.TextUnmarshaler = (*Info)(nil)

	_ encoding.TextMarshaler = Authorization{}
	_ fmt.Stringer           = Authorization{}
)

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
	if p.EAlg == "" {
		p.EAlg = "null"
	}
	mode, ok := normalizeIPSecMode(p.Mod)
	if !ok || !strings.EqualFold(p.Prot, "esp") {
		return Param{}, false
	}
	ealg, ok := normalizeEncryptionAlg(p.EAlg)
	if !ok {
		return Param{}, false
	}
	alg, ok := normalizeIntegrityAlg(p.Alg)
	if !ok || !validIPSecPorts(p.PortC, p.PortS) || !validIPSecSPIs(p.SPIC, p.SPIS) {
		return Param{}, false
	}
	if !compatibleIPSecAlgorithms(alg, ealg) {
		return Param{}, false
	}
	p.Alg = alg
	p.EAlg = ealg
	p.Mod = mode
	return p, true
}

func ValidESPSPI(spi uint32) bool {
	return spi >= minUnreservedESPSPI
}

func validIPSecSPIs(client, server uint32) bool {
	return ValidESPSPI(client) && ValidESPSPI(server) && client != server
}

func validIPPort(port int) bool {
	return port > 0 && port <= maxIPPort
}

func validIPSecPorts(client, server int) bool {
	return validProtectedIPPort(client) && validProtectedIPPort(server) && client != server
}

func validProtectedIPPort(port int) bool {
	return validIPPort(port) && port != standardSIPPort && port != standardSIPSPort
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
	realm := challenge.Realm
	if strings.TrimSpace(realm) == "" {
		realm = id.Realm
	}
	auth := Authorization{
		Nonce:     challenge.Nonce,
		URI:       id.RegisterURI,
		Username:  id.PrivateIdentity,
		Realm:     realm,
		Algorithm: algorithm.name,
		Opaque:    challenge.Opaque,
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
	if auth.QOP != "" {
		if info.RSPAuth == "" {
			return errors.New("verifying authentication-info: qop requires rspauth")
		}
		if info.QOP == "" {
			return errors.New("verifying authentication-info: qop is missing")
		}
		if info.CNonce == "" {
			return errors.New("verifying authentication-info: qop requires cnonce")
		}
		if info.NonceCount == "" {
			return errors.New("verifying authentication-info: qop requires nonce count")
		}
	} else if info.QOP != "" || info.CNonce != "" || info.NonceCount != "" {
		return errors.New("verifying authentication-info: unexpected qop parameters")
	}
	if info.RSPAuth == "" {
		return nil
	}
	algorithm, ok := normalizeAKAAlgorithm(auth.Algorithm)
	if !ok {
		return fmt.Errorf("verifying authentication-info: unsupported algorithm %q", auth.Algorithm)
	}
	if password == "" {
		return errors.New("verifying authentication-info: digest password is empty")
	}
	if info.QOP != "" {
		if !strings.EqualFold(info.QOP, auth.QOP) {
			return fmt.Errorf("verifying authentication-info: qop %q does not match authorization qop %q", info.QOP, auth.QOP)
		}
	}
	if info.CNonce != "" {
		if info.CNonce != auth.CNonce {
			return errors.New("verifying authentication-info: cnonce does not match authorization")
		}
	}
	if info.NonceCount != "" {
		if info.NonceCount != auth.NonceCount {
			return errors.New("verifying authentication-info: nonce count does not match authorization")
		}
	}
	expected, err := computeAKAResponse(algorithm.hash, "", auth.Username, auth.Realm, auth.URI, auth.Nonce, password, auth.QOP, auth.CNonce, auth.NonceCount)
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
	if err != nil {
		return usim.AKAResult{}, err
	}
	if digestAKAUsable(aka) {
		return aka, nil
	}
	if failure := akaChallengeFailure(aka); failure != nil {
		return usim.AKAResult{}, failure
	}
	return usim.AKAResult{}, errors.New("AKA response missing RES, CK, or IK")
}

func digestAKAUsable(aka usim.AKAResult) bool {
	return len(aka.RES) != 0 && len(aka.CK) != 0 && len(aka.IK) != 0
}

func akaChallengeFailure(aka usim.AKAResult) *AKAChallengeFailure {
	if aka.SynchronizationFailed() {
		return &AKAChallengeFailure{AUTS: append([]byte(nil), aka.AUTS...)}
	}
	if aka.AuthenticationRejected() {
		return &AKAChallengeFailure{Reject: true}
	}
	return nil
}

func (p Param) MarshalText() ([]byte, error) {
	return []byte(paramString(p)), nil
}

func paramString(p Param) string {
	spiC := fmt.Sprintf("%0*d", ipsecSPIDecimalWidth, p.SPIC)
	spiS := fmt.Sprintf("%0*d", ipsecSPIDecimalWidth, p.SPIS)
	value := fmt.Sprintf("%s;alg=%s;ealg=%s;mod=%s;port-c=%d;port-s=%d;prot=%s;spi-c=%s;spi-s=%s", p.Mechanism, p.Alg, p.EAlg, p.Mod, p.PortC, p.PortS, p.Prot, spiC, spiS)
	if p.Q != "" {
		value += ";q=" + p.Q
	}
	return value
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
	return []byte(paramsString(ps)), nil
}

func paramsString(ps Params) string {
	values := make([]string, 0, len(ps))
	for _, param := range ps {
		values = append(values, paramString(param))
	}
	return strings.Join(values, ",")
}

func (c *Challenge) UnmarshalText(text []byte) error {
	value := string(text)
	if !strings.HasPrefix(strings.ToLower(value), "digest ") {
		return errors.New("parsing auth challenge: unsupported scheme")
	}
	challenge := Challenge{}
	seen := make(map[string]struct{})
	for _, field := range splitHeaderFields(value[len("Digest "):]) {
		name, rawValue, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			return errors.New("parsing auth challenge: directive is missing value")
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return errors.New("parsing auth challenge: directive name is empty")
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("parsing auth challenge: duplicate %s directive", name)
		}
		seen[name] = struct{}{}
		value, err := parseHeaderValue(rawValue)
		if err != nil {
			return fmt.Errorf("parsing auth challenge %s: %w", name, err)
		}
		switch name {
		case "realm":
			challenge.Realm = value
		case "nonce":
			challenge.Nonce = value
		case "algorithm":
			challenge.Algorithm = value
		case "qop":
			challenge.QOP = value
		case "opaque":
			challenge.Opaque = value
		}
	}
	if challenge.Realm == "" {
		return errors.New("parsing auth challenge: realm is empty")
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
	if strings.TrimSpace(string(text)) == "" {
		*i = info
		return nil
	}
	seen := make(map[string]struct{})
	for _, field := range splitHeaderFields(string(text)) {
		if strings.TrimSpace(field) == "" {
			return errors.New("parsing authentication-info: directive is empty")
		}
		name, rawValue, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			return errors.New("parsing authentication-info: directive is missing value")
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return errors.New("parsing authentication-info: directive name is empty")
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("parsing authentication-info: duplicate %s directive", name)
		}
		seen[name] = struct{}{}
		value, err := parseHeaderValue(rawValue)
		if err != nil {
			return fmt.Errorf("parsing authentication-info %s: %w", name, err)
		}
		switch name {
		case "nextnonce":
			info.NextNonce = value
		case "qop":
			info.QOP = value
		case "rspauth":
			if !lowerHexDigits(value, 0) {
				return fmt.Errorf("parsing authentication-info rspauth %q: expected lowercase hexadecimal digits", value)
			}
			info.RSPAuth = value
		case "cnonce":
			info.CNonce = value
		case "nc":
			if !lowerHexDigits(value, digestNonceCountWidth) {
				return fmt.Errorf("parsing authentication-info nc %q: expected %d lowercase hexadecimal digits", value, digestNonceCountWidth)
			}
			info.NonceCount = value
		}
	}
	*i = info
	return nil
}

func (i Info) MarshalText() ([]byte, error) {
	fields := make([]string, 0, 5)
	if i.NextNonce != "" {
		fields = append(fields, "nextnonce="+quoteHeaderValue(i.NextNonce))
	}
	if i.QOP != "" {
		fields = append(fields, "qop="+i.QOP)
	}
	if i.RSPAuth != "" {
		fields = append(fields, "rspauth="+quoteHeaderValue(i.RSPAuth))
	}
	if i.CNonce != "" {
		fields = append(fields, "cnonce="+quoteHeaderValue(i.CNonce))
	}
	if i.NonceCount != "" {
		fields = append(fields, "nc="+i.NonceCount)
	}
	return []byte(strings.Join(fields, ",")), nil
}

func (a Authorization) MarshalText() ([]byte, error) {
	return []byte(authorizationString(a)), nil
}

func authorizationString(a Authorization) string {
	algorithm := a.Algorithm
	if algorithm == "" {
		algorithm = AlgorithmAKAv1MD5
	}
	value := fmt.Sprintf("Digest nonce=%s,uri=%s,realm=%s,username=%s,response=%s,algorithm=%s", quoteHeaderValue(a.Nonce), quoteHeaderValue(a.URI), quoteHeaderValue(a.Realm), quoteHeaderValue(a.Username), quoteHeaderValue(a.Response), algorithm)
	if a.IntegrityProtected != "" {
		value += fmt.Sprintf(`,integrity-protected=%s`, a.IntegrityProtected)
	}
	if a.QOP != "" {
		value += fmt.Sprintf(",qop=%s,nc=%s,cnonce=%s", a.QOP, a.NonceCount, quoteHeaderValue(a.CNonce))
	}
	if a.AUTS != "" {
		value += ",auts=" + quoteHeaderValue(a.AUTS)
	}
	if a.Opaque != "" {
		value += ",opaque=" + quoteHeaderValue(a.Opaque)
	}
	return value
}

func (p Param) String() string {
	return paramString(p)
}

func (ps Params) String() string {
	return paramsString(ps)
}

func (a Authorization) String() string {
	return authorizationString(a)
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
			if !decimalDigits(value, 0) {
				return fmt.Errorf("parsing security header port-c %q: expected decimal digits", value)
			}
			port, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("parsing security header port-c %q: %w", value, err)
			}
			param.PortC = port
		case "port-s":
			if !decimalDigits(value, 0) {
				return fmt.Errorf("parsing security header port-s %q: expected decimal digits", value)
			}
			port, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("parsing security header port-s %q: %w", value, err)
			}
			param.PortS = port
		case "spi-c":
			if !decimalDigits(value, 0) || len(value) > ipsecSPIDecimalWidth {
				return fmt.Errorf("parsing security header spi-c %q: expected 1 to %d decimal digits", value, ipsecSPIDecimalWidth)
			}
			value64, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return fmt.Errorf("parsing security header spi-c %q: %w", value, err)
			}
			param.SPIC = uint32(value64)
		case "spi-s":
			if !decimalDigits(value, 0) || len(value) > ipsecSPIDecimalWidth {
				return fmt.Errorf("parsing security header spi-s %q: expected 1 to %d decimal digits", value, ipsecSPIDecimalWidth)
			}
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

func decimalDigits(value string, width int) bool {
	if value == "" || width > 0 && len(value) != width {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func lowerHexDigits(value string, width int) bool {
	if value == "" || width > 0 && len(value) != width {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			if value[i] < 'a' || value[i] > 'f' {
				return false
			}
		}
	}
	return true
}

func normalizeIntegrityAlg(alg string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(alg)) {
	case "hmac-sha-1-96", "hmac-sha1-96":
		return "hmac-sha-1-96", true
	case "aes-gmac":
		return "aes-gmac", true
	case "null":
		return "null", true
	default:
		return "", false
	}
}

func normalizeEncryptionAlg(alg string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(alg)) {
	case "aes-cbc":
		return "aes-cbc", true
	case "aes-gcm":
		return "aes-gcm", true
	case "null":
		return "null", true
	default:
		return "", false
	}
}

func normalizeIPSecMode(mode string) (string, bool) {
	switch {
	case strings.EqualFold(strings.TrimSpace(mode), "trans"):
		return "trans", true
	case strings.EqualFold(strings.TrimSpace(mode), "UDP-enc-tun"):
		return "UDP-enc-tun", true
	default:
		return "", false
	}
}

func compatibleIPSecAlgorithms(alg, ealg string) bool {
	switch {
	case alg == "null":
		return ealg == "aes-gcm"
	case ealg == "aes-gcm":
		return alg == "null"
	case alg == "aes-gmac":
		return ealg == "null"
	default:
		return alg == "hmac-sha-1-96" && (ealg == "null" || ealg == "aes-cbc")
	}
}

func splitHeaderFields(value string) []string {
	fields := make([]string, 0, strings.Count(value, ",")+1)
	start := 0
	inQuotes := false
	escaped := false
	for i := range len(value) {
		if escaped {
			escaped = false
			continue
		}
		switch value[i] {
		case '\\':
			if inQuotes {
				escaped = true
			}
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

func parseHeaderValue(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if value[0] != '"' {
		if strings.ContainsAny(value, "\"\r\n") {
			return "", errors.New("invalid token")
		}
		return value, nil
	}
	if len(value) < 2 || value[len(value)-1] != '"' {
		return "", errors.New("unterminated quoted string")
	}

	payload := value[1 : len(value)-1]
	var parsed strings.Builder
	parsed.Grow(len(payload))
	for i := 0; i < len(payload); i++ {
		switch payload[i] {
		case '\\':
			if i+1 == len(payload) {
				return "", errors.New("unterminated quoted pair")
			}
			i++
			if payload[i] == '\r' || payload[i] == '\n' {
				return "", errors.New("quoted pair contains CR or LF")
			}
			parsed.WriteByte(payload[i])
		case '"':
			return "", errors.New("unescaped quote in quoted string")
		case '\r', '\n':
			return "", errors.New("quoted string contains CR or LF")
		default:
			parsed.WriteByte(payload[i])
		}
	}
	return parsed.String(), nil
}

func quoteHeaderValue(value string) string {
	var quoted strings.Builder
	quoted.Grow(len(value) + 2)
	quoted.WriteByte('"')
	for i := range len(value) {
		switch value[i] {
		case '\\', '"':
			quoted.WriteByte('\\')
			quoted.WriteByte(value[i])
		case '\r':
			quoted.WriteString(`\r`)
		case '\n':
			quoted.WriteString(`\n`)
		default:
			quoted.WriteByte(value[i])
		}
	}
	quoted.WriteByte('"')
	return quoted.String()
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
	// crypto/rand.Read always fills the buffer and never returns an error in Go 1.26.
	_, _ = rand.Read(rnd)
	for i, b := range rnd {
		buf[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(buf)
}
