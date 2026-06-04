package uim

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/damonto/vowifi-go/driver/qmi/protocol"
	"github.com/damonto/vowifi-go/usim/command"
	usimreader "github.com/damonto/vowifi-go/usim/reader"
	"github.com/damonto/vowifi-go/usim/simfile"
)

const (
	DefaultRequestTimeout = 30 * time.Second
	defaultCloseTimeout   = 5 * time.Second
	slotStatusTimeout     = 1 * time.Second
	slotReadyTimeout      = 5 * time.Second
	slotPollInterval      = 500 * time.Millisecond
)

var (
	usimAIDPrefix  = []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}
	isimAIDPrefix  = []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04}
	masterFilePath = []byte{0x3F, 0x00}
	currentADFPath = []byte{0x7F, 0xFF}
)

type Reader struct {
	Transport   protocol.Transport
	Slot        uint8
	ClientID    uint8
	CATClientID uint8
	CATService  protocol.ServiceType
	txn         atomic.Uint32
	closeOnce   sync.Once
	closeErr    error
}

type sessionRequest struct {
	session Session
	aid     []byte
}

func Open(ctx context.Context, transport protocol.Transport, slot uint8, device string) (*Reader, error) {
	device = strings.TrimSpace(device)
	if slot < 1 || slot > 5 {
		return nil, fmt.Errorf("opening QMI reader: slot %d is out of range", slot)
	}
	if transport == nil {
		return nil, errors.New("opening QMI reader: transport is nil")
	}

	reader := &Reader{
		Transport: transport,
		Slot:      slot,
	}
	if device != "" {
		if err := reader.openProxy(ctx, device); err != nil {
			_ = transport.Close()
			if errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("opening QMI reader: device %s is not connected", device)
			}
			return nil, fmt.Errorf("opening QMI reader: %w", err)
		}
		if err := reader.allocateClientID(ctx); err != nil {
			_ = transport.Close()
			if errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("opening QMI reader: device %s does not expose QMI over qmi-proxy", device)
			}
			return nil, fmt.Errorf("opening QMI reader: %w", err)
		}
	}
	if err := reader.ensureSlotActivated(ctx); err != nil {
		_ = reader.Close()
		return nil, err
	}
	return reader, nil
}

func (r *Reader) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultCloseTimeout)
	defer cancel()
	r.closeOnce.Do(func() {
		transport := r.Transport
		if transport == nil {
			r.ClientID = 0
			return
		}

		var releaseErr error
		if r.CATClientID != 0 {
			releaseErr = r.releaseServiceClientID(ctx, r.CATService, r.CATClientID)
			r.CATClientID = 0
			r.CATService = 0
		}
		if r.ClientID != 0 {
			releaseErr = errors.Join(releaseErr, r.releaseClientID(ctx))
			r.ClientID = 0
		}

		closeErr := transport.Close()
		r.Transport = nil
		if releaseErr == nil {
			r.closeErr = closeErr
			return
		}
		r.closeErr = errors.Join(releaseErr, closeErr)
	})
	return r.closeErr
}

func (r *Reader) ListApplications(ctx context.Context) ([]usimreader.Application, error) {
	attrs, err := r.FileAttributes(ctx, usimreader.FileRef{Path: []byte{0x2F, 0x00}})
	if err != nil {
		return nil, fmt.Errorf("reading EF_DIR: %w", err)
	}
	if attrs.FileStructure != simfile.StructureLinearFixed {
		return nil, errors.New("reading EF_DIR: unexpected file structure")
	}

	apps := make([]usimreader.Application, 0, attrs.RecordCount)
	for recordID := uint16(1); recordID <= attrs.RecordCount; recordID++ {
		record, err := r.ReadRecord(ctx, usimreader.RecordRead{
			File:   usimreader.FileRef{Path: []byte{0x2F, 0x00}},
			Record: recordID,
			Length: attrs.RecordSize,
		})
		if err != nil {
			return nil, fmt.Errorf("reading EF_DIR record %d: %w", recordID, err)
		}

		parsed, err := command.ReadEFDirRecord{RecordSize: attrs.RecordSize}.Decode(record)
		if err != nil {
			return nil, fmt.Errorf("parsing EF_DIR record %d: %w", recordID, err)
		}
		if len(parsed.AID) == 0 {
			continue
		}

		apps = append(apps, usimreader.Application{
			AID:   slices.Clone(parsed.AID),
			Label: parsed.Label,
		})
	}
	return apps, nil
}

func (r *Reader) FileAttributes(ctx context.Context, file usimreader.FileRef) (usimreader.FileAttributes, error) {
	path := r.requestFilePath(file)
	response, err := r.withFileSession(ctx, file, func(ctx context.Context, session sessionRequest) (protocol.Response, error) {
		return r.getFileAttributesResponse(ctx, session, path)
	})
	if err != nil {
		return usimreader.FileAttributes{}, err
	}
	return decodeReaderFileAttributes(response)
}

func (r *Reader) ReadTransparent(ctx context.Context, req usimreader.TransparentRead) ([]byte, error) {
	path := r.requestFilePath(req.File)
	length := req.Length
	if length == 0 {
		attrs, err := r.FileAttributes(ctx, req.File)
		if err != nil {
			return nil, err
		}
		if attrs.FileStructure != simfile.StructureTransparent {
			return nil, errors.New("reading transparent file: unexpected file structure")
		}
		if req.Offset > attrs.FileSize {
			return nil, errors.New("reading transparent file: offset exceeds file size")
		}
		length = attrs.FileSize - req.Offset
	}

	response, err := r.withFileSession(ctx, req.File, func(ctx context.Context, session sessionRequest) (protocol.Response, error) {
		return r.readTransparentResponse(ctx, session, path, req.Offset, length)
	})
	if err != nil {
		return nil, err
	}

	value, ok := tlvValue(response.TLVs, 0x11)
	if !ok {
		return nil, errors.New("reading transparent file: read result TLV missing")
	}
	return decodeLengthPrefixedBytes(value)
}

func (r *Reader) ReadRecord(ctx context.Context, req usimreader.RecordRead) ([]byte, error) {
	path := r.requestFilePath(req.File)
	if req.Record == 0 {
		return nil, errors.New("reading record file: record number is zero")
	}

	length := req.Length
	if length == 0 {
		attrs, err := r.FileAttributes(ctx, req.File)
		if err != nil {
			return nil, err
		}
		if attrs.FileStructure != simfile.StructureLinearFixed {
			return nil, errors.New("reading record file: unexpected file structure")
		}
		length = attrs.RecordSize
	}

	response, err := r.withFileSession(ctx, req.File, func(ctx context.Context, session sessionRequest) (protocol.Response, error) {
		return r.readRecordResponse(ctx, session, path, req.Record, length)
	})
	if err != nil {
		return nil, err
	}

	value, ok := tlvValue(response.TLVs, 0x11)
	if !ok {
		return nil, errors.New("reading record file: read result TLV missing")
	}
	return decodeLengthPrefixedBytes(value)
}

func (r *Reader) Authenticate3G(ctx context.Context, req usimreader.AuthenticateRequest) ([]byte, error) {
	sessions, err := r.sessionsForAID(req.AID)
	if err != nil {
		return nil, err
	}
	authContext := authenticateContext(req)
	response, err := r.withSessions(ctx, sessions, func(ctx context.Context, session sessionRequest) (protocol.Response, error) {
		return r.authenticateResponse(ctx, session, authContext, packAuthenticateRequest(req))
	})
	if err != nil {
		return nil, err
	}

	value, ok := tlvValue(response.TLVs, 0x11)
	if !ok {
		return nil, errors.New("authenticating USIM: authenticate result TLV missing")
	}
	return decodeLengthPrefixedBytes(value)
}

func authenticateContext(req usimreader.AuthenticateRequest) byte {
	if req.EAPAKA {
		return authenticateIMSAKAContext
	}
	return authenticateContextForAID(req.AID)
}

func authenticateContextForAID(aid []byte) byte {
	if hasPrefix(aid, isimAIDPrefix) {
		return authenticateIMSAKAContext
	}
	return authenticate3GContext
}

func (r *Reader) withSessions(
	ctx context.Context,
	sessions []sessionRequest,
	fn func(context.Context, sessionRequest) (protocol.Response, error),
) (protocol.Response, error) {
	var lastErr error
	for i, session := range sessions {
		resp, err := fn(ctx, session)
		if err == nil {
			return resp, nil
		}

		lastErr = err
		if i == 0 && len(sessions) > 1 && retryableSessionError(err) {
			continue
		}
		break
	}
	return protocol.Response{}, lastErr
}

func (r *Reader) withFileSession(
	ctx context.Context,
	file usimreader.FileRef,
	fn func(context.Context, sessionRequest) (protocol.Response, error),
) (protocol.Response, error) {
	sessions, err := r.sessionsForFile(file)
	if err != nil {
		return protocol.Response{}, err
	}
	return r.withSessions(ctx, sessions, fn)
}

func (r *Reader) sessionsForAID(aid []byte) ([]sessionRequest, error) {
	if len(aid) == 0 {
		return []sessionRequest{{session: SessionPrimaryGWProvisioning}}, nil
	}
	return r.sessionsForFile(usimreader.FileRef{AID: aid})
}

func (r *Reader) sessionsForFile(file usimreader.FileRef) ([]sessionRequest, error) {
	if len(file.AID) == 0 {
		return []sessionRequest{{session: SessionPrimaryGWProvisioning}}, nil
	}

	if hasPrefix(file.AID, isimAIDPrefix) {
		cardSession, err := cardSessionForSlot(r.Slot)
		if err != nil {
			return nil, err
		}
		nonProvisioningSession, err := nonProvisioningSessionForSlot(r.Slot)
		if err != nil {
			return nil, err
		}
		return []sessionRequest{
			{session: cardSession, aid: slices.Clone(file.AID)},
			{session: nonProvisioningSession, aid: slices.Clone(file.AID)},
		}, nil
	}

	return []sessionRequest{{session: SessionPrimaryGWProvisioning}}, nil
}

func (r *Reader) requestFilePath(file usimreader.FileRef) []byte {
	if len(file.AID) != 0 {
		if hasPrefix(file.AID, usimAIDPrefix) {
			return joinBytes(masterFilePath, currentADFPath, file.Path)
		}
		return slices.Clone(file.Path)
	}
	if hasPrefix(file.Path, masterFilePath) {
		return slices.Clone(file.Path)
	}
	return joinBytes(masterFilePath, file.Path)
}

func hasPrefix(value, prefix []byte) bool {
	return len(value) >= len(prefix) && slices.Equal(value[:len(prefix)], prefix)
}
