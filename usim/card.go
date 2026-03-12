package usim

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/damonto/ims-client/apdu"
)

var (
	fileMF       = mustHex("3F00")
	fileEFDir    = mustHex("2F00")
	fileEFICCID  = mustHex("2FE2")
	fileEFIMSI   = mustHex("6F07")
	fileEFSMSP   = mustHex("6F42")
	fileEFIMPI   = mustHex("6F02")
	fileEFDomain = mustHex("6F03")
	fileEFIMPU   = mustHex("6F04")
	errNoUSIMAID = errors.New("USIM application not found")
	errNoISIMAID = errors.New("ISIM application not found")
)

type AKAResult struct {
	RES    []byte
	CK     []byte
	IK     []byte
	AUTS   []byte
	Reject bool
}

func (r AKAResult) IsSuccess() bool {
	return len(r.RES) != 0 && len(r.CK) != 0 && len(r.IK) != 0
}

func (r AKAResult) IsSynchronizationFailure() bool {
	return len(r.AUTS) != 0
}

func (r AKAResult) IsAuthenticationReject() bool {
	return r.Reject
}

type Card struct {
	tx     apdu.Driver
	logger *slog.Logger

	aid             []byte
	iccid           string
	imsi            string
	mcc             string
	mnc             string
	smsc            string
	privateIdentity string
	publicIdentity  string
	homeDomain      string
	akaState        AKAIdentityState
}

func (u *Card) ICCID() string                              { return u.iccid }
func (u *Card) IMSI() string                               { return u.imsi }
func (u *Card) MCC() string                                { return u.mcc }
func (u *Card) MNC() string                                { return u.mnc }
func (u *Card) SMSC() string                               { return u.smsc }
func (u *Card) PrivateIdentity() string                    { return u.privateIdentity }
func (u *Card) PublicIdentity() string                     { return u.publicIdentity }
func (u *Card) HomeDomain() string                         { return u.homeDomain }
func (u *Card) AKAIdentityState() AKAIdentityState         { return u.akaState.clone() }
func (u *Card) SetAKAIdentityState(state AKAIdentityState) { u.akaState = state.clone() }

func Load(ctx context.Context, tx apdu.Driver, logger *slog.Logger) (*Card, error) {
	if tx == nil {
		return nil, fmt.Errorf("loading USIM: driver is nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	card := &Card{tx: tx, logger: logger.With("component", "usim")}
	if err := card.load(ctx); err != nil {
		return nil, err
	}
	return card, nil
}

func (u *Card) Close() error {
	return u.tx.Close()
}

func (u *Card) AKA(ctx context.Context, rand, autn []byte) (AKAResult, error) {
	if len(rand) != 16 || len(autn) != 16 {
		return AKAResult{}, errors.New("authenticating USIM: rand and autn must be 16 bytes")
	}
	res, err := u.exchange(ctx, apdu.Authenticate3G(rand, autn))
	if err != nil {
		return AKAResult{}, fmt.Errorf("authenticating USIM: %w", err)
	}
	var aka AKAResult
	if err := aka.UnmarshalBinary(res.Data()); err != nil {
		return AKAResult{}, err
	}
	return aka, nil
}

func readAKAChunk(data []byte, name string, original []byte) ([]byte, []byte, error) {
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("authenticating USIM: missing %s length in %X", name, original)
	}
	length := int(data[0])
	data = data[1:]
	if len(data) < length {
		return nil, nil, fmt.Errorf("authenticating USIM: truncated %s in %X", name, original)
	}
	chunk := append([]byte(nil), data[:length]...)
	return chunk, data[length:], nil
}

func (r *AKAResult) UnmarshalBinary(data []byte) error {
	if len(data) < 1 {
		return errors.New("authenticating USIM: authenticate response is empty")
	}
	original := append([]byte(nil), data...)
	payload := data[1:]
	switch original[0] {
	case 0xDB:
		parsed := AKAResult{}
		var err error
		parsed.RES, payload, err = readAKAChunk(payload, "RES", original)
		if err != nil {
			return err
		}
		parsed.CK, payload, err = readAKAChunk(payload, "CK", original)
		if err != nil {
			return err
		}
		parsed.IK, payload, err = readAKAChunk(payload, "IK", original)
		if err != nil {
			return err
		}
		*r = parsed
		return nil
	case 0xDC:
		if len(payload) == 0 {
			*r = AKAResult{Reject: true}
			return nil
		}
		auts, _, err := readAKAChunk(payload, "AUTS", original)
		if err != nil {
			return err
		}
		if len(auts) == 0 {
			*r = AKAResult{Reject: true}
			return nil
		}
		if len(auts) != 14 {
			return fmt.Errorf("authenticating USIM: invalid AUTS length %d in %X", len(auts), original)
		}
		*r = AKAResult{AUTS: auts}
		return nil
	default:
		return fmt.Errorf("authenticating USIM: unexpected authenticate response %X", original)
	}
}

func (u *Card) load(ctx context.Context) error {
	aid, err := u.findUSIMAID(ctx)
	if err != nil {
		return fmt.Errorf("loading USIM: %w", err)
	}
	u.aid = aid

	iccid, err := u.readICCID(ctx)
	if err != nil {
		return fmt.Errorf("loading ICCID: %w", err)
	}
	u.iccid = iccid

	imsi, mcc, mnc, err := u.readIMSI(ctx)
	if err != nil {
		return fmt.Errorf("loading IMSI: %w", err)
	}
	u.imsi = imsi
	u.mcc = mcc
	u.mnc = mnc

	smsc, err := u.readSMSC(ctx)
	if err == nil {
		u.smsc = smsc
	}
	if err := u.loadISIM(ctx); err != nil {
		u.logger.Debug("skipping ISIM load", "err", err)
	}
	u.logger.Debug("loaded USIM card", "iccid", u.iccid, "imsi", u.imsi, "mcc", u.mcc, "mnc", u.mnc, "smsc", u.smsc, "private_identity", u.privateIdentity, "public_identity", u.publicIdentity, "home_domain", u.homeDomain)

	return nil
}

func (u *Card) findUSIMAID(ctx context.Context) ([]byte, error) {
	return u.findAID(ctx, "USIM", []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}, errNoUSIMAID)
}

func (u *Card) findISIMAID(ctx context.Context) ([]byte, error) {
	return u.findAID(ctx, "ISIM", []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04}, errNoISIMAID)
}

func (u *Card) findAID(ctx context.Context, label string, prefix []byte, notFound error) ([]byte, error) {
	if _, err := u.selectID(ctx, fileMF); err != nil {
		return nil, err
	}
	fci, err := u.selectID(ctx, fileEFDir)
	if err != nil {
		return nil, err
	}
	if fci.FileStruct != fileStructLinearFixed {
		return nil, errors.New("reading EF_DIR: unexpected file structure")
	}
	for recordID := byte(1); recordID <= fci.RecordCount; recordID++ {
		res, err := u.exchange(ctx, apdu.ReadRecord(recordID, byte(fci.RecordSize)))
		if err != nil {
			return nil, err
		}
		var record efDirRecord
		if err := record.UnmarshalBinary(res.Data()); err != nil {
			return nil, fmt.Errorf("parsing EF_DIR record %d: %w", recordID, err)
		}
		if len(record.AID) == 0 {
			continue
		}
		if strings.EqualFold(record.Label, label) || (len(prefix) > 0 && bytes.HasPrefix(record.AID, prefix)) {
			return record.AID, nil
		}
	}
	return nil, notFound
}

func (u *Card) readICCID(ctx context.Context) (string, error) {
	if err := u.selectApp(ctx); err != nil {
		return "", err
	}
	fci, err := u.selectPath(ctx, fileEFICCID)
	if err != nil {
		return "", err
	}
	if fci.FileStruct != fileStructTransparent {
		return "", errors.New("reading EF_ICCID: unexpected file structure")
	}
	res, err := u.exchange(ctx, apdu.ReadBinary(byte(fci.FileSize), 0))
	if err != nil {
		return "", err
	}
	return decodeSwappedBCD(res.Data(), true), nil
}

func (u *Card) readIMSI(ctx context.Context) (string, string, string, error) {
	if err := u.selectApp(ctx); err != nil {
		return "", "", "", err
	}
	fci, err := u.selectID(ctx, fileEFIMSI)
	if err != nil {
		return "", "", "", err
	}
	if fci.FileStruct != fileStructTransparent {
		return "", "", "", errors.New("reading EF_IMSI: unexpected file structure")
	}
	res, err := u.exchange(ctx, apdu.ReadBinary(byte(fci.FileSize), 0))
	if err != nil {
		return "", "", "", err
	}
	data := res.Data()
	if len(data) == 0 {
		return "", "", "", errors.New("reading EF_IMSI: empty payload")
	}
	length := int(data[0])
	if len(data) < length+1 {
		return "", "", "", errors.New("reading EF_IMSI: truncated payload")
	}
	imsi := decodeSwappedBCD(data[1:1+length], true)
	mcc := imsi[:3]
	mnc := imsi[3:6]
	if imsi[3] == '0' || imsi[3] == '1' {
		mnc = "0" + imsi[3:5]
	}
	return imsi, mcc, mnc, nil
}

func (u *Card) loadISIM(ctx context.Context) error {
	aid, err := u.findISIMAID(ctx)
	if err != nil {
		return err
	}
	u.logger.Debug("found ISIM AID", "aid", fmt.Sprintf("%X", aid))
	if _, err := u.selectName(ctx, aid); err != nil {
		return fmt.Errorf("selecting ISIM application: %w", err)
	}
	if impi, err := u.readTLVTransparent(ctx, fileEFIMPI); err == nil {
		u.privateIdentity = impi
	} else {
		u.logger.Debug("reading EF_IMPI failed", "err", err)
	}
	if domain, err := u.readTLVTransparent(ctx, fileEFDomain); err == nil {
		u.homeDomain = domain
	} else {
		u.logger.Debug("reading EF_DOMAIN failed", "err", err)
	}
	if impu, err := u.readTLVLinearFixedFirst(ctx, fileEFIMPU); err == nil {
		u.publicIdentity = impu
	} else {
		u.logger.Debug("reading EF_IMPU failed", "err", err)
	}
	if u.homeDomain == "" && strings.Contains(u.privateIdentity, "@") {
		if _, domain, ok := strings.Cut(u.privateIdentity, "@"); ok {
			u.homeDomain = domain
		}
	}
	return nil
}

func (u *Card) readTLVTransparent(ctx context.Context, id []byte) (string, error) {
	fci, err := u.selectID(ctx, id)
	if err != nil {
		return "", err
	}
	if fci.FileStruct != fileStructTransparent {
		return "", errors.New("reading TLV EF: unexpected file structure")
	}
	res, err := u.exchange(ctx, apdu.ReadBinary(byte(fci.FileSize), 0))
	if err != nil {
		return "", err
	}
	return decodeTLVText(res.Data())
}

func (u *Card) readTLVLinearFixedFirst(ctx context.Context, id []byte) (string, error) {
	fci, err := u.selectID(ctx, id)
	if err != nil {
		return "", err
	}
	if fci.FileStruct != fileStructLinearFixed {
		return "", errors.New("reading TLV EF record: unexpected file structure")
	}
	for recordID := byte(1); recordID <= fci.RecordCount; recordID++ {
		res, err := u.exchange(ctx, apdu.ReadRecord(recordID, byte(fci.RecordSize)))
		if err != nil {
			return "", err
		}
		value, err := decodeTLVText(res.Data())
		if err != nil {
			continue
		}
		if value != "" {
			return value, nil
		}
	}
	return "", errors.New("reading TLV EF record: no populated record")
}

func (u *Card) readSMSC(ctx context.Context) (string, error) {
	if err := u.selectApp(ctx); err != nil {
		return "", err
	}
	fci, err := u.selectID(ctx, fileEFSMSP)
	if err != nil {
		return "", err
	}
	if fci.FileStruct != fileStructLinearFixed {
		return "", errors.New("reading EF_SMSP: unexpected file structure")
	}
	y := int(fci.RecordSize) - 28
	for recordID := byte(1); recordID <= fci.RecordCount; recordID++ {
		res, err := u.exchange(ctx, apdu.ReadRecord(recordID, byte(fci.RecordSize)))
		if err != nil {
			return "", err
		}
		data := res.Data()
		if len(data) != int(fci.RecordSize) || y+26 > len(data) {
			return "", errors.New("reading EF_SMSP: malformed record")
		}
		sca := data[y+13 : y+25]
		if len(sca) < 2 {
			continue
		}
		length := int(sca[0])
		if length <= 1 || length > len(sca) {
			continue
		}
		if sca[1] != 0x91 {
			continue
		}
		number := decodeSwappedBCD(sca[2:length+1], false)
		if number != "" {
			return "+" + number, nil
		}
	}
	return "", errors.New("reading EF_SMSP: SMSC not found")
}

func (u *Card) selectApp(ctx context.Context) error {
	_, err := u.selectName(ctx, u.aid)
	return err
}

func (u *Card) selectID(ctx context.Context, id []byte) (fileControlInfo, error) {
	return u.selectFCI(ctx, apdu.SelectID(id, true))
}

func (u *Card) selectName(ctx context.Context, name []byte) (fileControlInfo, error) {
	return u.selectFCI(ctx, apdu.SelectName(name, true))
}

func (u *Card) selectPath(ctx context.Context, path []byte) (fileControlInfo, error) {
	return u.selectFCI(ctx, apdu.SelectPath(path, true))
}

func (u *Card) selectFCI(ctx context.Context, req *apdu.Request) (fileControlInfo, error) {
	res, err := u.exchange(ctx, req)
	if err != nil {
		return fileControlInfo{}, err
	}
	var info fileControlInfo
	if err := info.UnmarshalBinary(res.Data()); err != nil {
		return fileControlInfo{}, fmt.Errorf("parsing FCI: %w", err)
	}
	return info, nil
}

func (u *Card) exchange(ctx context.Context, req *apdu.Request) (apdu.Response, error) {
	res, err := u.tx.Transmit(ctx, req)
	if err != nil {
		return nil, err
	}
	if res.HasMore() {
		follow, err := u.tx.Transmit(ctx, apdu.GetResponse(res.SW2()))
		if err != nil {
			return nil, fmt.Errorf("reading response body: %w", err)
		}
		if err := checkResponse(follow); err != nil {
			return nil, err
		}
		return follow, nil
	}
	if err := checkResponse(res); err != nil {
		return nil, err
	}
	return res, nil
}

func checkResponse(res apdu.Response) error {
	if len(res) < 2 {
		return apdu.ErrMalformedResponse
	}
	if !res.OK() {
		return apdu.StatusError{SW: res.SW()}
	}
	return nil
}

func decodeSwappedBCD(data []byte, stripLeadingNine bool) string {
	encoded := strings.ToLower(hex.EncodeToString(data))
	parts := strings.SplitAfterN(encoded, "", len(encoded)+1)
	_ = parts
	buf := strings.Builder{}
	for i := 0; i+1 < len(encoded); i += 2 {
		buf.WriteByte(encoded[i+1])
		buf.WriteByte(encoded[i])
	}
	out := strings.TrimRight(buf.String(), "f")
	if stripLeadingNine {
		out = strings.TrimLeft(out, "9")
	}
	return out
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
