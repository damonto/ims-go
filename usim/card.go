package usim

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/damonto/ims-client/usim/command"
	usimreader "github.com/damonto/ims-client/usim/reader"
)

var (
	fileEFICCID   = mustHex("2FE2")
	fileEFIMSI    = mustHex("6F07")
	fileEFAD      = mustHex("6FAD")
	fileEFSMSP    = mustHex("6F42")
	fileEFGID1    = mustHex("6F3E")
	pathEFPSISMSC = mustHex("7F106FE5")
	fileEFIMPI    = mustHex("6F02")
	fileEFDomain  = mustHex("6F03")
	fileEFIMPU    = mustHex("6F04")
	errNoUSIMAID  = errors.New("USIM application not found")
	errNoISIMAID  = errors.New("ISIM application not found")
)

type Card struct {
	tx     usimreader.Reader
	logger *slog.Logger

	aid             []byte
	iccid           string
	imsi            string
	mcc             string
	mnc             string
	mncLength       int
	gid1            string
	serviceCentre   ServiceCentre
	privateIdentity string
	publicIdentity  string
	homeDomain      string
	akaState        AKAIdentityState
}

type SMSPPDownloadRequest = usimreader.SMSPPDownloadRequest
type SMSPPDownloadResponse = usimreader.SMSPPDownloadResponse

func (u *Card) ICCID() string                              { return u.iccid }
func (u *Card) IMSI() string                               { return u.imsi }
func (u *Card) MCC() string                                { return u.mcc }
func (u *Card) MNC() string                                { return u.mnc }
func (u *Card) MNCLength() int                             { return u.mncLength }
func (u *Card) GID1() string                               { return u.gid1 }
func (u *Card) SMSC() string                               { return u.serviceCentre.Address }
func (u *Card) ServiceCentre() ServiceCentre               { return u.serviceCentre }
func (u *Card) PrivateIdentity() string                    { return u.privateIdentity }
func (u *Card) PublicIdentity() string                     { return u.publicIdentity }
func (u *Card) HomeDomain() string                         { return u.homeDomain }
func (u *Card) AKAIdentityState() AKAIdentityState         { return u.akaState.clone() }
func (u *Card) SetAKAIdentityState(state AKAIdentityState) { u.akaState = state.clone() }

func Load(ctx context.Context, tx usimreader.Reader, logger *slog.Logger) (*Card, error) {
	if tx == nil {
		return nil, errors.New("loading USIM: reader is nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	card := &Card{
		tx:     tx,
		logger: logger.With("component", "usim"),
	}
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

	payload, err := u.tx.Authenticate3G(ctx, usimreader.AuthenticateRequest{
		AID:  u.aid,
		Rand: rand,
		AUTN: autn,
	})
	if err != nil {
		return AKAResult{}, fmt.Errorf("authenticating USIM: %w", err)
	}
	result, err := command.Authenticate3G{}.Decode(payload)
	if err != nil {
		return AKAResult{}, fmt.Errorf("authenticating USIM: %w", err)
	}
	return AKAResult{
		RES:    result.RES,
		CK:     result.CK,
		IK:     result.IK,
		AUTS:   result.AUTS,
		Reject: result.Reject,
	}, nil
}

func (u *Card) SMSPPDownload(ctx context.Context, req SMSPPDownloadRequest) (SMSPPDownloadResponse, error) {
	resp, err := u.tx.SMSPPDownload(ctx, req)
	if err != nil {
		return SMSPPDownloadResponse{}, fmt.Errorf("running SMS-PP data download: %w", err)
	}
	return resp, nil
}

func (u *Card) load(ctx context.Context) error {
	aid, err := command.FindAID{
		Label:    "USIM",
		Prefix:   []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02},
		NotFound: errNoUSIMAID,
	}.Run(ctx, u.tx)
	if err != nil {
		return fmt.Errorf("loading USIM: %w", err)
	}
	u.aid = aid
	rootApp := command.App{Reader: u.tx}
	usimApp := command.App{Reader: u.tx, AID: u.aid}

	iccid, err := rootApp.ReadICCID(ctx, fileEFICCID)
	if err != nil {
		return fmt.Errorf("loading ICCID: %w", err)
	}
	u.iccid = iccid

	imsi, err := usimApp.ReadIMSI(ctx, fileEFIMSI)
	if err != nil {
		return fmt.Errorf("loading IMSI: %w", err)
	}
	mncLength, err := usimApp.ReadMNCLength(ctx, fileEFAD)
	if err != nil {
		return fmt.Errorf("loading EF_AD: %w", err)
	}
	mnc, err := formatMNC(imsi.Digits, mncLength)
	if err != nil {
		return fmt.Errorf("loading IMSI: %w", err)
	}
	u.imsi = imsi.Digits
	u.mcc = imsi.MCC
	u.mnc = mnc
	u.mncLength = mncLength

	if gid1, err := usimApp.ReadTransparentHex(ctx, fileEFGID1, "reading EF_GID1"); err == nil {
		u.gid1 = gid1
	} else {
		u.logger.Debug("reading EF_GID1 from USIM failed", "err", err)
	}

	smsc, err := usimApp.ReadSMSC(ctx, fileEFSMSP)
	if err == nil {
		u.serviceCentre.Address = smsc
	}
	if psi, err := usimApp.ReadLinearFixedTextPathFirst(ctx, pathEFPSISMSC, "reading EFPSISMSC"); err == nil {
		u.serviceCentre.PSI = psi
	} else {
		u.logger.Debug("reading EFPSISMSC from USIM failed", "err", err)
	}
	if err := u.loadISIM(ctx); err != nil {
		u.logger.Debug("skipping ISIM load", "err", err)
	}

	u.logger.Debug(
		"loaded USIM card",
		"iccid", u.iccid,
		"imsi", u.imsi,
		"mcc", u.mcc,
		"mnc", u.mnc,
		"smsc", u.serviceCentre.Address,
		"smsc_psi", u.serviceCentre.PSI,
		"private_identity", u.privateIdentity,
		"public_identity", u.publicIdentity,
		"home_domain", u.homeDomain,
	)

	return nil
}

func (u *Card) loadISIM(ctx context.Context) error {
	aid, err := command.FindAID{
		Label:    "ISIM",
		Prefix:   []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04},
		NotFound: errNoISIMAID,
	}.Run(ctx, u.tx)
	if err != nil {
		return err
	}
	isimApp := command.App{Reader: u.tx, AID: aid}

	u.logger.Debug("found ISIM AID", "aid", fmt.Sprintf("%X", aid))
	impi, err := isimApp.ReadTransparentText(ctx, fileEFIMPI, "reading EF_IMPI")
	if err != nil {
		return fmt.Errorf("reading EF_IMPI: %w", err)
	}
	privateIdentity := impi
	var homeDomain string
	if domain, err := isimApp.ReadTransparentText(ctx, fileEFDomain, "reading EF_DOMAIN"); err == nil {
		homeDomain = domain
	} else {
		u.logger.Debug("reading EF_DOMAIN failed", "err", err)
	}
	impu, err := isimApp.ReadLinearFixedTextFirst(ctx, fileEFIMPU, "reading EF_IMPU")
	if err != nil {
		return fmt.Errorf("reading EF_IMPU: %w", err)
	}
	publicIdentity := impu
	serviceCentre := u.serviceCentre
	if psi, err := isimApp.ReadLinearFixedTextPathFirst(ctx, pathEFPSISMSC, "reading EFPSISMSC"); err == nil {
		serviceCentre.PSI = psi
	} else {
		u.logger.Debug("reading EFPSISMSC from ISIM failed", "err", err)
	}
	if homeDomain == "" && strings.Contains(privateIdentity, "@") {
		if _, domain, ok := strings.Cut(privateIdentity, "@"); ok {
			homeDomain = domain
		}
	}
	u.privateIdentity = privateIdentity
	u.publicIdentity = publicIdentity
	u.homeDomain = homeDomain
	u.serviceCentre = serviceCentre
	return nil
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func formatMNC(imsi string, mncLength int) (string, error) {
	if len(imsi) < 3+mncLength {
		return "", errors.New("IMSI is too short for MNC length")
	}
	switch mncLength {
	case 2:
		return "0" + imsi[3:5], nil
	case 3:
		return imsi[3:6], nil
	default:
		return "", fmt.Errorf("unsupported MNC length %d", mncLength)
	}
}
