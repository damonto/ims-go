package mbim

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	usimreader "github.com/damonto/ims-client/usim/reader"
	"github.com/damonto/ims-client/usim/simfile"
)

const (
	slotPollInterval = 500 * time.Millisecond
	slotReadyTimeout = 5 * time.Second
)

type Reader struct {
	conn net.Conn
	slot uint32
	txn  atomic.Uint32

	mu     sync.Mutex
	closed bool
}

func Open(ctx context.Context, device string, slot int) (usimreader.Reader, error) {
	return New(ctx, device, slot)
}

func New(ctx context.Context, device string, slot int) (usimreader.Reader, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	device = strings.TrimSpace(device)
	if device == "" {
		return nil, errors.New("opening MBIM reader: device is empty")
	}
	if slot < 1 {
		return nil, fmt.Errorf("opening MBIM reader: slot %d is out of range", slot)
	}

	conn, err := openProxyConnection()
	if err != nil {
		return nil, err
	}

	reader := &Reader{
		conn: conn,
		slot: uint32(slot - 1),
	}
	if err := reader.connect(ctx, device); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return reader, nil
}

func (r *Reader) ListApplications(ctx context.Context) ([]usimreader.Application, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil, errors.New("listing MBIM applications: reader is closed")
	}

	request := ApplicationListRequest{TransactionID: r.nextTransactionID()}
	if err := request.Request().Transmit(ctx, r.conn); err != nil {
		return nil, fmt.Errorf("listing MBIM applications: %w", err)
	}

	apps := make([]usimreader.Application, 0, len(request.Response.Applications))
	for _, app := range request.Response.Applications {
		if len(app.AID) == 0 {
			continue
		}
		apps = append(apps, usimreader.Application{
			AID:   slices.Clone(app.AID),
			Label: app.Label,
		})
	}
	return apps, nil
}

func (r *Reader) GetFileAttributes(ctx context.Context, file usimreader.FileRef) (usimreader.FileAttributes, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(file.Path) == 0 {
		return usimreader.FileAttributes{}, errors.New("reading MBIM file attributes: path is empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return usimreader.FileAttributes{}, errors.New("reading MBIM file attributes: reader is closed")
	}

	request := FileStatusRequest{
		TransactionID: r.nextTransactionID(),
		ApplicationID: slices.Clone(file.AID),
		FilePath:      mbimFilePath(file),
	}
	if err := request.Request().Transmit(ctx, r.conn); err != nil {
		return usimreader.FileAttributes{}, fmt.Errorf("reading MBIM file attributes %X: %w", file.Path, err)
	}
	if err := cardStatusError(request.Response.StatusWord1, request.Response.StatusWord2); err != nil {
		return usimreader.FileAttributes{}, fmt.Errorf("reading MBIM file attributes %X: %w", file.Path, err)
	}
	return fileStatusAttributes(request.Response), nil
}

func (r *Reader) ReadTransparent(ctx context.Context, req usimreader.TransparentRead) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(req.File.Path) == 0 {
		return nil, errors.New("reading MBIM transparent file: path is empty")
	}

	length := req.Length
	if length == 0 {
		attrs, err := r.GetFileAttributes(ctx, req.File)
		if err != nil {
			return nil, err
		}
		if attrs.FileStructure != simfile.StructureTransparent {
			return nil, errors.New("reading MBIM transparent file: unexpected file structure")
		}
		if req.Offset > attrs.FileSize {
			return nil, errors.New("reading MBIM transparent file: offset exceeds file size")
		}
		length = attrs.FileSize - req.Offset
	}
	if length == 0 {
		return nil, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil, errors.New("reading MBIM transparent file: reader is closed")
	}

	request := ReadBinaryRequest{
		TransactionID: r.nextTransactionID(),
		ApplicationID: slices.Clone(req.File.AID),
		FilePath:      mbimFilePath(req.File),
		Offset:        uint32(req.Offset),
		Size:          uint32(length),
	}
	if err := request.Request().Transmit(ctx, r.conn); err != nil {
		return nil, fmt.Errorf("reading MBIM transparent file %X: %w", req.File.Path, err)
	}
	if err := cardStatusError(request.Response.StatusWord1, request.Response.StatusWord2); err != nil {
		return nil, fmt.Errorf("reading MBIM transparent file %X: %w", req.File.Path, err)
	}
	return slices.Clone(request.Response.Data), nil
}

func (r *Reader) ReadRecord(ctx context.Context, req usimreader.RecordRead) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(req.File.Path) == 0 {
		return nil, errors.New("reading MBIM record file: path is empty")
	}
	if req.Record == 0 {
		return nil, errors.New("reading MBIM record file: record number is zero")
	}

	if req.Length == 0 {
		attrs, err := r.GetFileAttributes(ctx, req.File)
		if err != nil {
			return nil, err
		}
		if attrs.FileStructure != simfile.StructureLinearFixed {
			return nil, errors.New("reading MBIM record file: unexpected file structure")
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil, errors.New("reading MBIM record file: reader is closed")
	}

	request := ReadRecordRequest{
		TransactionID: r.nextTransactionID(),
		ApplicationID: slices.Clone(req.File.AID),
		FilePath:      mbimFilePath(req.File),
		Record:        uint32(req.Record),
	}
	if err := request.Request().Transmit(ctx, r.conn); err != nil {
		return nil, fmt.Errorf("reading MBIM record file %X record %d: %w", req.File.Path, req.Record, err)
	}
	if err := cardStatusError(request.Response.StatusWord1, request.Response.StatusWord2); err != nil {
		return nil, fmt.Errorf("reading MBIM record file %X record %d: %w", req.File.Path, req.Record, err)
	}
	return slices.Clone(request.Response.Data), nil
}

func (r *Reader) Authenticate3G(ctx context.Context, req usimreader.AuthenticateRequest) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(req.Rand) != 16 {
		return nil, fmt.Errorf("authenticating MBIM AKA: RAND length %d, want 16", len(req.Rand))
	}
	if len(req.AUTN) != 16 {
		return nil, fmt.Errorf("authenticating MBIM AKA: AUTN length %d, want 16", len(req.AUTN))
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil, errors.New("authenticating MBIM AKA: reader is closed")
	}

	request := AuthAKARequest{
		TransactionID: r.nextTransactionID(),
		Rand:          slices.Clone(req.Rand),
		AUTN:          slices.Clone(req.AUTN),
	}
	if err := request.Request().Transmit(ctx, r.conn); err != nil {
		return nil, fmt.Errorf("authenticating MBIM AKA: %w", err)
	}
	return akaPayload(request.Response), nil
}

func (r *Reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true

	request := CloseRequest{TransactionID: r.nextTransactionID()}
	err := request.Request().Transmit(context.Background(), r.conn)
	return errors.Join(err, r.conn.Close())
}

func (r *Reader) connect(ctx context.Context, device string) error {
	if err := r.configureProxy(ctx, device); err != nil {
		return err
	}
	if err := r.openDevice(ctx); err != nil {
		return err
	}
	if err := r.ensureSlotActivated(ctx); err != nil {
		return err
	}
	return nil
}

func (r *Reader) configureProxy(ctx context.Context, device string) error {
	request := ProxyConfigRequest{
		TransactionID: r.nextTransactionID(),
		DevicePath:    device,
		Timeout:       30,
	}
	if err := request.Request().Transmit(ctx, r.conn); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("opening MBIM reader: device %s is not connected", device)
		}
		return fmt.Errorf("configuring MBIM proxy for %s: %w", device, err)
	}
	return nil
}

func (r *Reader) openDevice(ctx context.Context) error {
	request := OpenDeviceRequest{TransactionID: r.nextTransactionID()}
	if err := request.Request().Transmit(ctx, r.conn); err != nil {
		return fmt.Errorf("opening MBIM device: %w", err)
	}
	return nil
}

func (r *Reader) ensureSlotActivated(ctx context.Context) error {
	slot, err := r.currentActivatedSlot(ctx)
	if err != nil {
		return fmt.Errorf("activating MBIM slot %d: %w", r.slot+1, err)
	}
	if slot == r.slot {
		return nil
	}
	if err := r.activateSlot(ctx, r.slot); err != nil {
		return fmt.Errorf("activating MBIM slot %d: %w", r.slot+1, err)
	}
	if err := r.waitForSlotReady(ctx); err != nil {
		return fmt.Errorf("activating MBIM slot %d: %w", r.slot+1, err)
	}
	return nil
}

func (r *Reader) currentActivatedSlot(ctx context.Context) (uint32, error) {
	request := DeviceSlotMappingsRequest{TransactionID: r.nextTransactionID()}
	if err := request.Request().Transmit(ctx, r.conn); err != nil {
		return 0, err
	}
	if len(request.Response.SlotMappings) == 0 {
		return 0, errors.New("reading MBIM slot mappings: mapping is empty")
	}
	return request.Response.SlotMappings[0].Slot, nil
}

func (r *Reader) activateSlot(ctx context.Context, slot uint32) error {
	request := DeviceSlotMappingsRequest{
		TransactionID: r.nextTransactionID(),
		SlotMappings:  []SlotMapping{{Slot: slot}},
	}
	return request.Request().Transmit(ctx, r.conn)
}

func (r *Reader) waitForSlotReady(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, slotReadyTimeout)
	defer cancel()

	var lastReadyState uint32
	var sawReadyState bool
	for {
		request := SubscriberReadyStatusRequest{TransactionID: r.nextTransactionID()}
		err := request.Request().Transmit(ctx, r.conn)
		if err == nil {
			sawReadyState = true
			lastReadyState = request.Response.ReadyState
			if lastReadyState == SubscriberReadyStateInitialized || lastReadyState == SubscriberReadyStateNoESIMProfile {
				return nil
			}
		}
		if ctx.Err() != nil {
			if err != nil {
				return fmt.Errorf("waiting for MBIM SIM readiness: %w", err)
			}
			if sawReadyState {
				return fmt.Errorf("waiting for MBIM SIM readiness: last ready state %#x", lastReadyState)
			}
			return errors.New("waiting for MBIM SIM readiness: timeout")
		}

		timer := time.NewTimer(slotPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (r *Reader) nextTransactionID() uint32 {
	return r.txn.Add(1)
}

func mbimFilePath(file usimreader.FileRef) []byte {
	if len(file.AID) != 0 || hasPrefix(file.Path, masterFilePath) {
		return slices.Clone(file.Path)
	}
	return append(slices.Clone(masterFilePath), file.Path...)
}

func fileStatusAttributes(status *FileStatusResponse) usimreader.FileAttributes {
	attrs := usimreader.FileAttributes{
		FileStructure: mbimFileStructure(status.FileStructure),
		FileType:      mbimFileType(status.FileType),
		RecordSize:    uint16(status.FileItemSize),
		RecordCount:   uint16(status.FileItemCount),
	}
	if status.FileStructure == UiccFileStructureTransparent {
		attrs.FileSize = uint16(status.FileItemSize)
	} else {
		attrs.FileSize = uint16(status.FileItemCount * status.FileItemSize)
	}
	return attrs
}

func mbimFileStructure(structure uint32) byte {
	switch structure {
	case UiccFileStructureTransparent:
		return simfile.StructureTransparent
	case UiccFileStructureLinear, UiccFileStructureCyclic:
		return simfile.StructureLinearFixed
	default:
		return 0
	}
}

func mbimFileType(fileType uint32) byte {
	switch fileType {
	case UiccFileTypeWorkingEF, UiccFileTypeInternalEF:
		return 0x21
	case UiccFileTypeDFOrADF:
		return 0x38
	default:
		return byte(fileType)
	}
}

func cardStatusError(sw1, sw2 uint32) error {
	if sw1 == 0x90 && sw2 == 0x00 {
		return nil
	}
	return fmt.Errorf("unexpected status word 0x%02X%02X", sw1, sw2)
}

func akaPayload(resp *AuthAKAResponse) []byte {
	if hasNonZero(resp.AUTS) {
		out := []byte{0xDC, byte(len(resp.AUTS))}
		return append(out, resp.AUTS...)
	}

	out := make([]byte, 0, 1+1+len(resp.RES)+1+len(resp.CK)+1+len(resp.IK))
	out = append(out, 0xDB, byte(len(resp.RES)))
	out = append(out, resp.RES...)
	out = append(out, byte(len(resp.CK)))
	out = append(out, resp.CK...)
	out = append(out, byte(len(resp.IK)))
	out = append(out, resp.IK...)
	return out
}

func hasNonZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return true
		}
	}
	return false
}

func hasPrefix(data, prefix []byte) bool {
	return len(data) >= len(prefix) && slices.Equal(data[:len(prefix)], prefix)
}

var (
	masterFilePath = []byte{0x3F, 0x00}

	_ usimreader.Reader = (*Reader)(nil)
)
