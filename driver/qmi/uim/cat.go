package uim

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/damonto/vowifi-go/driver/qmi/protocol"
	"github.com/damonto/vowifi-go/usim/command"
	usimreader "github.com/damonto/vowifi-go/usim/reader"
)

func (r *Reader) SMSPPDownload(ctx context.Context, req usimreader.SMSPPDownloadRequest) (usimreader.SMSPPDownloadResponse, error) {
	envelope, err := command.SMSPPDownload{
		ServiceCenterAddress: req.ServiceCenterAddress,
		TPDU:                 slices.Clone(req.TPDU),
	}.Envelope()
	if err != nil {
		return usimreader.SMSPPDownloadResponse{}, err
	}
	if len(envelope) > 0xFFFF {
		return usimreader.SMSPPDownloadResponse{}, fmt.Errorf("running QMI SMS-PP data download: envelope length %d exceeds QMI CAT limit", len(envelope))
	}

	return r.sendSMSPPDownloadEnvelope(ctx, envelope)
}

func (r *Reader) sendSMSPPDownloadEnvelope(ctx context.Context, envelope []byte) (usimreader.SMSPPDownloadResponse, error) {
	service, clientID, err := r.ensureCATClientID(ctx)
	if err != nil {
		return usimreader.SMSPPDownloadResponse{}, err
	}

	value := binary.LittleEndian.AppendUint16(nil, envelopeCommandSMSPP)
	value = binary.LittleEndian.AppendUint16(value, uint16(len(envelope)))
	value = append(value, envelope...)
	tlvs := protocol.TLVs{tlvBytes(0x01, value)}
	if service == protocol.QMIServiceCAT2 {
		tlvs = append(tlvs, tlvUint8(0x10, r.Slot))
	}
	resp, err := r.request(ctx, service, clientID, protocol.QMICATSendEnvelope, tlvs, DefaultRequestTimeout)
	if err != nil {
		return usimreader.SMSPPDownloadResponse{}, fmt.Errorf("running QMI SMS-PP data download: %w", err)
	}
	if err := resultOK(resp); err != nil {
		return usimreader.SMSPPDownloadResponse{}, fmt.Errorf("running QMI SMS-PP data download: %w", err)
	}

	result, ok := tlvValue(resp.TLVs, 0x10)
	if !ok {
		return usimreader.SMSPPDownloadResponse{SW1: 0x90, SW2: 0x00}, nil
	}
	if len(result) < 3 {
		return usimreader.SMSPPDownloadResponse{}, errors.New("running QMI SMS-PP data download: raw response TLV is truncated")
	}
	length := int(result[2])
	if len(result) < 3+length {
		return usimreader.SMSPPDownloadResponse{}, errors.New("running QMI SMS-PP data download: envelope response data is truncated")
	}
	return usimreader.SMSPPDownloadResponse{
		SW1:  result[0],
		SW2:  result[1],
		Data: slices.Clone(result[3 : 3+length]),
	}, nil
}

func (r *Reader) ensureCATClientID(ctx context.Context) (protocol.ServiceType, uint8, error) {
	if r.CATClientID != 0 {
		return r.CATService, r.CATClientID, nil
	}
	if r.CATService == 0 {
		service, err := r.detectCATService(ctx)
		if err != nil {
			return 0, 0, err
		}
		r.CATService = service
	}

	clientID, err := r.allocateServiceClientID(ctx, r.CATService)
	if err != nil {
		return 0, 0, err
	}
	r.CATClientID = clientID
	return r.CATService, r.CATClientID, nil
}

func (r *Reader) detectCATService(ctx context.Context) (protocol.ServiceType, error) {
	versions, err := r.serviceVersions(ctx)
	if err != nil {
		return 0, err
	}
	for _, version := range versions {
		if version.Service == protocol.QMIServiceCAT2 {
			return protocol.QMIServiceCAT2, nil
		}
	}
	for _, version := range versions {
		if version.Service == protocol.QMIServiceCAT {
			return protocol.QMIServiceCAT, nil
		}
	}
	return 0, errors.New("detecting QMI CAT service: CAT2/CAT service is not exposed")
}

func (r *Reader) serviceVersions(ctx context.Context) ([]serviceVersion, error) {
	resp, err := r.request(ctx, protocol.QMIServiceControl, 0, protocol.QMICtlCmdGetVersionInfo, nil, DefaultRequestTimeout)
	if err != nil {
		return nil, err
	}
	if err := resultOK(resp); err != nil {
		return nil, err
	}
	return decodeServiceVersions(resp)
}
