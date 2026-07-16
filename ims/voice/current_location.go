package voice

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/damonto/ims-go/ims/pidf"
	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
	"mime"
	"strings"
)

type currentLocationDiscoveryRequest struct {
	XMLName      xml.Name  `xml:"requestForLocationInformation"`
	OneShot      *struct{} `xml:"oneShot"`
	StartSending *struct{} `xml:"startSending"`
	StopSending  *struct{} `xml:"stopSending"`
}

func (r *currentLocationDiscoveryRequest) UnmarshalBinary(data []byte) error {
	if len(data) == 0 {
		return errors.New("parsing current location discovery: empty body")
	}
	if err := xml.Unmarshal(data, r); err != nil {
		return fmt.Errorf("parsing current location discovery: %w", err)
	}
	if r.OneShot == nil && r.StartSending == nil && r.StopSending == nil {
		return errors.New("parsing current location discovery: request action is missing")
	}
	return nil
}

func (r currentLocationDiscoveryRequest) RequestsOneShot() bool {
	return r.OneShot != nil
}

func (c *Call) handleINFO(ctx context.Context, req session.Request) error {
	if !req.Message.HeaderHasToken("Info-Package", currentLocationDiscoveryInfoPackage) {
		return c.endpoint.writeStatus(ctx, req, sipStatusBadInfoPackage, "Bad Info Package")
	}
	c.mu.Lock()
	emergency := c.emergency
	currentLocation := c.currentLocation
	state := c.state
	c.mu.Unlock()
	if !emergency || !currentLocation {
		return c.endpoint.writeStatus(ctx, req, sipStatusBadInfoPackage, "Bad Info Package")
	}
	if state != CallStateConfirmed && state != CallStateActive {
		return c.endpoint.writeStatus(ctx, req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist")
	}
	locationReq, code, reason, err := decodeCurrentLocationDiscoveryINFO(req.Message)
	if err != nil {
		return c.endpoint.writeStatus(ctx, req, code, reason)
	}
	if err := c.endpoint.writeStatus(ctx, req, sipStatusOK, "OK"); err != nil {
		return err
	}
	if !locationReq.RequestsOneShot() {
		return nil
	}
	if err := c.publishCurrentLocation(ctx); err != nil {
		return fmt.Errorf("handling current location discovery INFO: %w", err)
	}
	return nil
}

func decodeCurrentLocationDiscoveryINFO(msg sip.Message) (currentLocationDiscoveryRequest, int, string, error) {
	contentType, _, err := mime.ParseMediaType(msg.Header("Content-Type"))
	if err != nil || !strings.EqualFold(contentType, currentLocationDiscoveryContentType) {
		return currentLocationDiscoveryRequest{}, sipStatusUnsupportedMediaType, "Unsupported Media Type", errors.New("unsupported current location discovery content type")
	}
	if disposition := strings.TrimSpace(msg.Header("Content-Disposition")); disposition != "" {
		dispositionType, _, err := mime.ParseMediaType(disposition)
		if err != nil || !strings.EqualFold(dispositionType, currentLocationDiscoveryDisposition) {
			return currentLocationDiscoveryRequest{}, sipStatusBadRequest, "Bad Request", errors.New("bad current location discovery content disposition")
		}
	}
	var req currentLocationDiscoveryRequest
	if err := req.UnmarshalBinary(msg.Body); err != nil {
		return currentLocationDiscoveryRequest{}, sipStatusBadRequest, "Bad Request", err
	}
	return req, 0, "", nil
}

func (c *Call) publishCurrentLocation(ctx context.Context) error {
	c.mu.Lock()
	snap := c.dialogSnapshot()
	localURI := c.localURI
	c.mu.Unlock()
	msg := snap.buildCurrentLocationPUBLISH(c.nextCSeq(), pidf.Build(localURI, c.endpoint.cfg.GeolocationCountry))
	resp, err := c.endpoint.sess.Exchange(ctx, msg)
	if err != nil {
		return fmt.Errorf("publishing current location: %w", err)
	}
	if resp.StatusCode() < sipStatusOK || resp.StatusCode() >= sipStatusMultipleChoices {
		return fmt.Errorf("publishing current location: expected 2xx, got %w", sip.NewResponseError(resp))
	}
	return nil
}

func (s dialogSnapshot) buildCurrentLocationPUBLISH(cseq int64, body []byte) sip.Message {
	msg := s.buildDialogRequest("PUBLISH", cseq)
	msg.Headers.Add("Event", presenceEventPackage)
	msg.Headers.Add("Content-Type", "application/pidf+xml")
	msg.Body = append([]byte(nil), body...)
	return msg
}
