package uim

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/damonto/vowifi-go/driver/qmi/protocol"
)

func (r *Reader) openProxy(ctx context.Context, device string) error {
	if strings.TrimSpace(device) == "" {
		return errors.New("opening QMI reader: device is empty")
	}

	resp, err := r.request(ctx, protocol.QMIServiceControl, 0, protocol.QMICtlInternalProxyOpen, protocol.TLVs{
		tlvBytes(0x01, []byte(device)),
	}, DefaultRequestTimeout)
	if err != nil {
		return err
	}
	return resultOK(resp)
}

func (r *Reader) allocateClientID(ctx context.Context) error {
	clientID, err := r.allocateServiceClientID(ctx, protocol.QMIServiceUIM)
	if err != nil {
		return err
	}
	r.ClientID = clientID
	return nil
}

func (r *Reader) releaseClientID(ctx context.Context) error {
	return r.releaseServiceClientID(ctx, protocol.QMIServiceUIM, r.ClientID)
}

func (r *Reader) allocateServiceClientID(ctx context.Context, service protocol.ServiceType) (uint8, error) {
	resp, err := r.request(ctx, protocol.QMIServiceControl, 0, protocol.QMICtlCmdAllocateClientID, protocol.TLVs{
		tlvUint8(0x01, byte(service)),
	}, DefaultRequestTimeout)
	if err != nil {
		return 0, err
	}
	if err := resultOK(resp); err != nil {
		return 0, err
	}

	value, ok := tlvValue(resp.TLVs, 0x01)
	if !ok || len(value) < 2 {
		return 0, errors.New("allocating QMI client ID: allocated client TLV missing")
	}
	return value[1], nil
}

func (r *Reader) releaseServiceClientID(ctx context.Context, service protocol.ServiceType, clientID uint8) error {
	resp, err := r.request(ctx, protocol.QMIServiceControl, 0, protocol.QMICtlCmdReleaseClientID, protocol.TLVs{
		tlvBytes(0x01, []byte{byte(service), clientID}),
	}, DefaultRequestTimeout)
	if err != nil {
		return err
	}
	return resultOK(resp)
}

func (r *Reader) request(
	ctx context.Context,
	service protocol.ServiceType,
	clientID uint8,
	id protocol.MessageID,
	tlvs protocol.TLVs,
	timeout time.Duration,
) (protocol.Response, error) {
	return r.Transport.Do(ctx, protocol.Request{
		Service:       service,
		ClientID:      clientID,
		TransactionID: uint16(r.txn.Add(1)),
		MessageID:     id,
		Timeout:       timeout,
		TLVs:          tlvs,
	})
}
