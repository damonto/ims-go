package core

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/damonto/ims-client/usim/command"
	usimreader "github.com/damonto/ims-client/usim/reader"
	"github.com/damonto/ims-client/usim/simfile"
)

const (
	DefaultRequestTimeout = 30 * time.Second
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
	Transport Transport
	Slot      uint8
	ClientID  uint8
	txn       atomic.Uint32
	closeOnce sync.Once
	closeErr  error
}

type sessionRequest struct {
	session Session
	aid     []byte
}

func Open(ctx context.Context, transport Transport, slot uint8, device string) (*Reader, error) {
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
	r.closeOnce.Do(func() {
		transport := r.Transport
		if transport == nil {
			r.ClientID = 0
			return
		}

		ctx := context.Background()

		var releaseErr error
		if r.ClientID != 0 {
			releaseErr = r.releaseClientID(ctx)
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
	attrs, err := r.GetFileAttributes(ctx, usimreader.FileRef{Path: []byte{0x2F, 0x00}})
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

func (r *Reader) GetFileAttributes(ctx context.Context, file usimreader.FileRef) (usimreader.FileAttributes, error) {
	path := r.requestFilePath(file)
	response, err := r.withFileSession(ctx, file, func(ctx context.Context, session sessionRequest) (Response, error) {
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
		attrs, err := r.GetFileAttributes(ctx, req.File)
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

	response, err := r.withFileSession(ctx, req.File, func(ctx context.Context, session sessionRequest) (Response, error) {
		return r.readTransparentResponse(ctx, session, path, req.Offset, length)
	})
	if err != nil {
		return nil, err
	}

	value, ok := response.TLVs.Find(0x11)
	if !ok {
		return nil, errors.New("reading transparent file: read result TLV missing")
	}
	return DecodeLengthPrefixedBytes(value)
}

func (r *Reader) ReadRecord(ctx context.Context, req usimreader.RecordRead) ([]byte, error) {
	path := r.requestFilePath(req.File)
	if req.Record == 0 {
		return nil, errors.New("reading record file: record number is zero")
	}

	length := req.Length
	if length == 0 {
		attrs, err := r.GetFileAttributes(ctx, req.File)
		if err != nil {
			return nil, err
		}
		if attrs.FileStructure != simfile.StructureLinearFixed {
			return nil, errors.New("reading record file: unexpected file structure")
		}
		length = attrs.RecordSize
	}

	response, err := r.withFileSession(ctx, req.File, func(ctx context.Context, session sessionRequest) (Response, error) {
		return r.readRecordResponse(ctx, session, path, req.Record, length)
	})
	if err != nil {
		return nil, err
	}

	value, ok := response.TLVs.Find(0x11)
	if !ok {
		return nil, errors.New("reading record file: read result TLV missing")
	}
	return DecodeLengthPrefixedBytes(value)
}

func (r *Reader) Authenticate3G(ctx context.Context, req usimreader.AuthenticateRequest) ([]byte, error) {
	response, err := r.authenticateResponse(ctx, sessionRequest{session: SessionPrimaryGWProvisioning}, packAuthenticateRequest(req))
	if err != nil {
		return nil, err
	}

	value, ok := response.TLVs.Find(0x11)
	if !ok {
		return nil, errors.New("authenticating USIM: authenticate result TLV missing")
	}
	return DecodeLengthPrefixedBytes(value)
}

func (r *Reader) withFileSession(
	ctx context.Context,
	file usimreader.FileRef,
	fn func(context.Context, sessionRequest) (Response, error),
) (Response, error) {
	sessions, err := r.sessionsForFile(file)
	if err != nil {
		return Response{}, err
	}

	var lastErr error
	for i, session := range sessions {
		resp, err := fn(ctx, session)
		if err == nil {
			return resp, nil
		}

		lastErr = err
		if i == 0 && len(sessions) > 1 && RetryableSessionError(err) {
			continue
		}
		break
	}
	return Response{}, lastErr
}

func (r *Reader) sessionsForFile(file usimreader.FileRef) ([]sessionRequest, error) {
	if len(file.AID) == 0 {
		return []sessionRequest{{session: SessionPrimaryGWProvisioning}}, nil
	}

	if hasPrefix(file.AID, isimAIDPrefix) {
		cardSession, err := CardSessionForSlot(r.Slot)
		if err != nil {
			return nil, err
		}
		nonProvisioningSession, err := NonProvisioningSessionForSlot(r.Slot)
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
			return Buffer(masterFilePath, currentADFPath, file.Path)
		}
		return slices.Clone(file.Path)
	}
	if hasPrefix(file.Path, masterFilePath) {
		return slices.Clone(file.Path)
	}
	return Buffer(masterFilePath, file.Path)
}

func (r *Reader) ensureSlotActivated(ctx context.Context) error {
	activeSlot, err := r.currentActivatedSlot(ctx)
	if err != nil {
		if errors.Is(err, ErrorNotSupported) {
			return nil
		}
		return fmt.Errorf("activating slot %d: %w", r.Slot, err)
	}
	if activeSlot == r.Slot {
		return nil
	}
	if err := r.switchSlot(ctx, r.Slot); err != nil {
		return fmt.Errorf("activating slot %d: %w", r.Slot, err)
	}
	if err := r.waitForSlotReady(ctx); err != nil {
		return fmt.Errorf("activating slot %d: %w", r.Slot, err)
	}
	return nil
}

func (r *Reader) currentActivatedSlot(ctx context.Context) (uint8, error) {
	resp, err := r.request(ctx, ServiceUIM, r.ClientID, MessageGetSlotStatus, nil, slotStatusTimeout)
	if err != nil {
		return 0, err
	}
	if err := MustResultOK(resp); err != nil {
		return 0, err
	}

	status, err := DecodeSlotStatus(resp)
	if err != nil {
		return 0, err
	}
	return status.ActiveSlot, nil
}

func (r *Reader) switchSlot(ctx context.Context, slot uint8) error {
	resp, err := r.request(ctx, ServiceUIM, r.ClientID, MessageSwitchSlot, TLVs{
		TLVUint8(0x01, 1),
		TLVUint32(0x02, uint32(slot)),
	}, DefaultRequestTimeout)
	if err != nil {
		return err
	}
	return MustResultOK(resp)
}

func (r *Reader) waitForSlotReady(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, slotReadyTimeout)
	defer cancel()

	for {
		status, err := r.getCardStatus(ctx)
		if err == nil && status.Ready() {
			return nil
		}
		if ctx.Err() != nil {
			if err != nil {
				return fmt.Errorf("waiting for card readiness: %w", err)
			}
			return errors.New("waiting for card readiness: timeout")
		}

		timer := time.NewTimer(slotPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			if err != nil {
				return fmt.Errorf("waiting for card readiness: %w", err)
			}
			return errors.New("waiting for card readiness: timeout")
		case <-timer.C:
		}
	}
}

func (r *Reader) getCardStatus(ctx context.Context) (CardStatus, error) {
	resp, err := r.request(ctx, ServiceUIM, r.ClientID, MessageGetCardStatus, nil, DefaultRequestTimeout)
	if err != nil {
		return CardStatus{}, err
	}
	if err := MustResultOK(resp); err != nil {
		return CardStatus{}, err
	}
	return DecodeCardStatus(resp)
}

func (r *Reader) openProxy(ctx context.Context, device string) error {
	if strings.TrimSpace(device) == "" {
		return errors.New("opening QMI reader: device is empty")
	}

	resp, err := r.request(ctx, ServiceControl, 0, MessageProxyOpen, TLVs{
		TLVBytes(0x01, []byte(device)),
	}, DefaultRequestTimeout)
	if err != nil {
		return err
	}
	return MustResultOK(resp)
}

func (r *Reader) allocateClientID(ctx context.Context) error {
	resp, err := r.request(ctx, ServiceControl, 0, MessageAllocateClientID, TLVs{
		TLVUint8(0x01, byte(ServiceUIM)),
	}, DefaultRequestTimeout)
	if err != nil {
		return err
	}
	if err := MustResultOK(resp); err != nil {
		return err
	}

	value, ok := resp.TLVs.Find(0x01)
	if !ok || len(value) < 2 {
		return errors.New("allocating QMI client ID: allocated client TLV missing")
	}
	r.ClientID = value[1]
	return nil
}

func (r *Reader) releaseClientID(ctx context.Context) error {
	resp, err := r.request(ctx, ServiceControl, 0, MessageReleaseClientID, TLVs{
		TLVBytes(0x01, []byte{byte(ServiceUIM), r.ClientID}),
	}, DefaultRequestTimeout)
	if err != nil {
		return err
	}
	return MustResultOK(resp)
}

func (r *Reader) readTransparentResponse(
	ctx context.Context,
	session sessionRequest,
	path []byte,
	offset uint16,
	length uint16,
) (Response, error) {
	fileValue, err := PutFileValue(path)
	if err != nil {
		return Response{}, err
	}

	info := Buffer(
		binary.LittleEndian.AppendUint16(nil, offset),
		binary.LittleEndian.AppendUint16(nil, length),
	)
	resp, err := r.request(ctx, ServiceUIM, r.ClientID, MessageReadTransparent, TLVs{
		TLVBytes(0x01, PutSessionValue(session.session, session.aid)),
		TLVBytes(0x02, fileValue),
		TLVBytes(0x03, info),
	}, DefaultRequestTimeout)
	if err != nil {
		return Response{}, err
	}
	if err := WithCardResult(resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}

func (r *Reader) readRecordResponse(
	ctx context.Context,
	session sessionRequest,
	path []byte,
	record uint16,
	length uint16,
) (Response, error) {
	fileValue, err := PutFileValue(path)
	if err != nil {
		return Response{}, err
	}

	recordValue := Buffer(
		binary.LittleEndian.AppendUint16(nil, record),
		binary.LittleEndian.AppendUint16(nil, length),
	)
	resp, err := r.request(ctx, ServiceUIM, r.ClientID, MessageReadRecord, TLVs{
		TLVBytes(0x01, PutSessionValue(session.session, session.aid)),
		TLVBytes(0x02, fileValue),
		TLVBytes(0x03, recordValue),
	}, DefaultRequestTimeout)
	if err != nil {
		return Response{}, err
	}
	if err := WithCardResult(resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}

func (r *Reader) getFileAttributesResponse(
	ctx context.Context,
	session sessionRequest,
	path []byte,
) (Response, error) {
	fileValue, err := PutFileValue(path)
	if err != nil {
		return Response{}, err
	}

	resp, err := r.request(ctx, ServiceUIM, r.ClientID, MessageGetFileAttrs, TLVs{
		TLVBytes(0x01, PutSessionValue(session.session, session.aid)),
		TLVBytes(0x02, fileValue),
	}, DefaultRequestTimeout)
	if err != nil {
		return Response{}, err
	}
	if err := WithCardResult(resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}

func (r *Reader) authenticateResponse(
	ctx context.Context,
	session sessionRequest,
	data []byte,
) (Response, error) {
	value := append([]byte{Authenticate3GContext}, binary.LittleEndian.AppendUint16(nil, uint16(len(data)))...)
	value = append(value, data...)

	resp, err := r.request(ctx, ServiceUIM, r.ClientID, MessageAuthenticate, TLVs{
		TLVBytes(0x01, PutSessionValue(session.session, session.aid)),
		TLVBytes(0x02, value),
	}, DefaultRequestTimeout)
	if err != nil {
		return Response{}, err
	}
	if err := WithCardResult(resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}

func (r *Reader) request(
	ctx context.Context,
	service Service,
	clientID uint8,
	id MessageID,
	tlvs TLVs,
	timeout time.Duration,
) (Response, error) {
	return r.Transport.Do(ctx, Request{
		Service:       service,
		ClientID:      clientID,
		TransactionID: uint16(r.txn.Add(1)),
		MessageID:     id,
		Timeout:       timeout,
		TLVs:          tlvs,
	})
}

func decodeReaderFileAttributes(resp Response) (usimreader.FileAttributes, error) {
	value, ok := resp.TLVs.Find(0x11)
	if !ok {
		return usimreader.FileAttributes{}, errors.New("reading file attributes: attributes TLV missing")
	}

	attrs, err := DecodeFileAttributes(value)
	if err != nil {
		return usimreader.FileAttributes{}, err
	}

	result := usimreader.FileAttributes{
		FileSize:    attrs.FileSize,
		RecordSize:  attrs.RecordSize,
		RecordCount: attrs.RecordCount,
		FileType:    fileTypeToSIMFileType(attrs.FileType),
	}
	if len(attrs.Raw) == 0 {
		result.FileStructure = fileTypeToSIMFileStructure(attrs.FileType)
		return result, nil
	}

	var fci simfile.FCI
	if err := fci.UnmarshalBinary(attrs.Raw); err != nil {
		result.FileStructure = fileTypeToSIMFileStructure(attrs.FileType)
		return result, nil
	}

	result.FileStructure = fci.FileStructure
	result.FileType = fci.FileType
	if result.FileSize == 0 {
		result.FileSize = fci.FileSize
	}
	if result.RecordSize == 0 {
		result.RecordSize = fci.RecordSize
	}
	if result.RecordCount == 0 {
		result.RecordCount = uint16(fci.RecordCount)
	}
	return result, nil
}

func packAuthenticateRequest(req usimreader.AuthenticateRequest) []byte {
	data := make([]byte, 0, len(req.Rand)+len(req.AUTN)+2)
	data = append(data, byte(len(req.Rand)))
	data = append(data, req.Rand...)
	data = append(data, byte(len(req.AUTN)))
	data = append(data, req.AUTN...)
	return data
}

func fileTypeToSIMFileStructure(fileType byte) byte {
	switch fileType {
	case 0:
		return simfile.StructureTransparent
	case 2:
		return simfile.StructureLinearFixed
	default:
		return 0
	}
}

func fileTypeToSIMFileType(fileType byte) byte {
	switch fileType {
	case 0, 1, 2:
		return 0x21
	case 3, 4:
		return 0x38
	default:
		return fileType
	}
}

func hasPrefix(value, prefix []byte) bool {
	return len(value) >= len(prefix) && slices.Equal(value[:len(prefix)], prefix)
}
