package registration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/damonto/ims-go/ims/security"
	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
)

type attachmentDrain struct {
	cancel      context.CancelFunc
	closeOnce   sync.Once
	attachments []session.Attachment
	closeErr    error
}

type secureAssociationExpiry struct {
	stopOnce sync.Once
	stopCh   chan struct{}
}

type secureResources struct {
	serverAttachments   []session.Attachment
	responseAttachments []session.Attachment
	unprotectedPrimary  session.Transport
	drains              []*attachmentDrain
	expiry              *secureAssociationExpiry
	keepalive           *registrationKeepAlive
}

type registerSecurity struct {
	outbound            session.Transport
	outboundAttachment  session.Attachment
	inboundTransports   []session.Transport
	inboundAttachments  []session.Attachment
	responseAttachments []session.Attachment
}

// TS 33.203 encodes the SA direction in bit 0 and the source role in bit 1.
const (
	saltUEClientToPCSCFServer byte = 0b00
	saltPCSCFClientToUEServer byte = 0b01
	saltUEServerToPCSCFClient byte = 0b10
	saltPCSCFServerToUEClient byte = 0b11
)

func (s *Registrar) protectedRegisterExchangeOptions() session.ExchangeOptions {
	return protectedExchangeOptions(s.sess.PrimaryTransport(), s.currentSecureServerTransports())
}

func (s *Registrar) currentSecurityVerify() *security.Param {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flow.SecurityVerify == nil {
		return nil
	}
	verify := *s.flow.SecurityVerify
	return &verify
}

func securityVerifyValueForFlow(flow Flow, verify *security.Param) string {
	if verify == nil {
		return ""
	}
	if value := flow.SecurityVerifyValue(); value != "" {
		return value
	}
	return verify.String()
}

func (s *Registrar) applySelectedSecurityServer(verify *security.Param, raw []string, publicContactHost string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flow.SecurityServerRaw = append([]string(nil), raw...)
	s.flow.SecurityVerify = verify
	if publicContactHost != "" {
		s.flow.ContactHost = publicContactHost
	}
	if verify == nil {
		s.flow.MessagePort = s.flow.RegisterPort
		return
	}
	s.flow.SecurityClient.Mod = verify.Mod
	s.flow.MessagePort = s.flow.SecurityClient.PortS
}

func acceptResponseFrom(inbound []session.Transport) func(session.Transport) bool {
	allowed := make(map[session.Transport]struct{}, len(inbound))
	for _, transport := range inbound {
		allowed[transport] = struct{}{}
	}
	return func(transport session.Transport) bool {
		_, ok := allowed[transport]
		return ok
	}
}

func reauthResponseTransports(outbound session.Transport, inbound []session.Transport) []session.Transport {
	if outbound == nil {
		return nil
	}
	protocol := sip.TransportToken(outbound.LocalAddr())
	transports := make([]session.Transport, 0, len(inbound)+1)
	for _, transport := range inbound {
		if strings.EqualFold(sip.TransportToken(transport.LocalAddr()), protocol) {
			transports = append(transports, transport)
		}
	}
	if strings.EqualFold(protocol, "TCP") {
		transports = append([]session.Transport{outbound}, transports...)
	}
	return uniqueSessionTransports(transports)
}

func protectedExchangeOptions(outbound session.Transport, inbound []session.Transport) session.ExchangeOptions {
	transports := reauthResponseTransports(outbound, inbound)
	if len(transports) == 0 {
		return session.ExchangeOptions{}
	}
	return session.ExchangeOptions{
		AcceptResponseTransport: acceptResponseFrom(transports),
		ResponseTransports:      transports,
	}
}

func uniqueSessionTransports(transports []session.Transport) []session.Transport {
	unique := transports[:0]
	for _, transport := range transports {
		if slices.Contains(unique, transport) {
			continue
		}
		unique = append(unique, transport)
	}
	return unique
}

func closeAttachments(attachments []session.Attachment) error {
	var closeErr error
	for _, attachment := range attachments {
		if attachment != nil {
			closeErr = errors.Join(closeErr, attachment.Close())
		}
	}
	return closeErr
}

func (r *registerSecurity) close() error {
	if r == nil {
		return nil
	}
	var closeErr error
	closeErr = errors.Join(closeErr, closeAttachments(r.inboundAttachments))
	r.inboundAttachments = nil
	r.inboundTransports = nil
	closeErr = errors.Join(closeErr, closeAttachments(r.responseAttachments))
	r.responseAttachments = nil
	if r.outboundAttachment != nil {
		closeErr = errors.Join(closeErr, r.outboundAttachment.Close())
		r.outboundAttachment = nil
	}
	r.outbound = nil
	return closeErr
}

func (r *registerSecurity) exchangeOptions() session.ExchangeOptions {
	if r == nil || r.outbound == nil {
		return session.ExchangeOptions{}
	}
	return protectedExchangeOptions(r.outbound, r.inboundTransports)
}

func (s *Registrar) replaceSecureServerAttachments(next []session.Attachment) []session.Attachment {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.secureServerAttachments
	s.secureServerAttachments = append([]session.Attachment(nil), next...)
	return old
}

func (s *Registrar) replaceSecureResponseAttachments(next []session.Attachment) []session.Attachment {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.secureResponseAttachments
	s.secureResponseAttachments = append([]session.Attachment(nil), next...)
	return old
}

func (s *Registrar) currentSecureServerTransports() []session.Transport {
	s.mu.Lock()
	attachments := append([]session.Attachment(nil), s.secureServerAttachments...)
	s.mu.Unlock()
	return attachmentTransports(attachments)
}

func (s *Registrar) closeAttachmentsAfter(attachments []session.Attachment, delay time.Duration) {
	attachments = compactAttachments(attachments)
	if len(attachments) == 0 {
		return
	}
	if delay <= 0 {
		s.logAttachmentCloseError(closeAttachments(attachments))
		return
	}
	drain := &attachmentDrain{
		attachments: append([]session.Attachment(nil), attachments...),
	}
	transports := attachmentTransports(attachments)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.logAttachmentCloseError(closeAttachments(attachments))
		return
	}
	ctx, cancel := contextWithDoneTimeout(s.done, delay)
	drain.cancel = cancel
	s.drainTimers = append(s.drainTimers, drain)
	s.startBackgroundTaskLocked(func() {
		defer cancel()
		if len(transports) == 0 {
			<-ctx.Done()
		} else {
			if err := s.sess.WaitTransportsIdle(ctx, transports...); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				s.logger.Warn("waiting for IMS security transports to become idle", "err", err)
			}
		}
		s.logAttachmentCloseError(drain.close())
		s.forgetDrain(drain)
	})
	s.mu.Unlock()
}

func (s *Registrar) closeOldSecurityAfterNewInbound(attachments []session.Attachment, expiresAt time.Time, watch *session.InboundWatch) {
	attachments = compactAttachments(attachments)
	if len(attachments) == 0 {
		watch.Close()
		return
	}
	if !expiresAt.IsZero() && !expiresAt.After(time.Now()) {
		watch.Close()
		s.logAttachmentCloseError(closeAttachments(attachments))
		return
	}
	drain := &attachmentDrain{attachments: append([]session.Attachment(nil), attachments...)}
	oldTransports := attachmentTransports(attachments)

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		watch.Close()
		s.logAttachmentCloseError(closeAttachments(attachments))
		return
	}
	ctx, cancel := contextWithDoneDeadline(s.done, expiresAt)
	drain.cancel = cancel
	s.drainTimers = append(s.drainTimers, drain)
	s.startBackgroundTaskLocked(func() {
		defer cancel()
		if watch.Wait(ctx) == nil {
			delay := saDrainDelayBefore(expiresAt, s.sess.TransactionTimers())
			if delay > 0 && len(oldTransports) != 0 {
				idleCtx, idleCancel := context.WithTimeout(ctx, delay)
				if err := s.sess.WaitTransportsIdle(idleCtx, oldTransports...); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					s.logger.Warn("waiting for replaced IMS security transports to become idle", "err", err)
				}
				idleCancel()
			}
		}
		s.logAttachmentCloseError(drain.close())
		s.forgetDrain(drain)
	})
	s.mu.Unlock()
}

func compactAttachments(attachments []session.Attachment) []session.Attachment {
	kept := attachments[:0]
	for _, attachment := range attachments {
		if attachment != nil {
			kept = append(kept, attachment)
		}
	}
	return kept
}

func attachmentTransports(attachments []session.Attachment) []session.Transport {
	transports := make([]session.Transport, 0, len(attachments))
	for _, attachment := range attachments {
		transportAttachment, ok := attachment.(session.TransportAttachment)
		if !ok {
			continue
		}
		transports = append(transports, transportAttachment.Transport())
	}
	return transports
}

func (d *attachmentDrain) close() error {
	d.closeOnce.Do(func() {
		d.closeErr = closeAttachments(d.attachments)
	})
	return d.closeErr
}

func (s *Registrar) logAttachmentCloseError(err error) {
	if err != nil {
		s.logger.Warn("closing IMS security attachment failed", "err", err)
	}
}

func newSecureAssociationExpiry() *secureAssociationExpiry {
	return &secureAssociationExpiry{
		stopCh: make(chan struct{}),
	}
}

func (e *secureAssociationExpiry) stop() {
	e.stopOnce.Do(func() {
		close(e.stopCh)
	})
}

func (e *secureAssociationExpiry) done() <-chan struct{} {
	return e.stopCh
}

func (s *Registrar) forgetDrain(drain *attachmentDrain) {
	s.mu.Lock()
	s.drainTimers = slices.DeleteFunc(s.drainTimers, func(candidate *attachmentDrain) bool {
		return candidate == drain
	})
	s.mu.Unlock()
}

func (s *Registrar) closeSecureResources() error {
	s.registrationCommitMu.Lock()
	resources := s.takeSecureResourcesForClose()
	s.registrationCommitMu.Unlock()
	stopErr := resources.stop()
	s.bgWG.Wait()
	err := errors.Join(stopErr, resources.close(s.sess))
	s.secureCleanupWG.Wait()
	s.replacementWG.Wait()
	return err
}

func (s *Registrar) clearSecureResources() error {
	resources, _, started := s.beginSecureResourceReset()
	if !started {
		return nil
	}
	defer s.secureCleanupWG.Done()
	stopErr := resources.stop()
	s.bgWG.Wait()
	return errors.Join(stopErr, resources.close(s.sess))
}

func (s *Registrar) clearSecureResourcesAfter(delay time.Duration, after func()) {
	resources, done, started := s.beginSecureResourceReset()
	if !started {
		if after != nil {
			after()
		}
		return
	}
	if err := resources.stop(); err != nil {
		s.logger.Warn("stopping IMS security resources failed", "err", err)
	}
	s.bgWG.Wait()
	if delay <= 0 {
		defer s.secureCleanupWG.Done()
		if err := resources.close(s.sess); err != nil {
			s.logger.Error("deleting IMS security association", "err", err)
		}
		if after != nil {
			after()
		}
		return
	}
	go func() {
		defer s.secureCleanupWG.Done()
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-done:
		}
		if err := resources.close(s.sess); err != nil {
			s.logger.Error("deleting IMS security association", "err", err)
		}
		if after != nil {
			after()
		}
	}()
}

func (s *Registrar) beginSecureResourceReset() (secureResources, <-chan struct{}, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return secureResources{}, nil, false
	}
	resources := s.takeSecureResourcesForResetLocked()
	done := s.done
	s.secureCleanupWG.Add(1)
	return resources, done, true
}

func (s *Registrar) takeSecureResourcesForClose() secureResources {
	s.mu.Lock()
	resources := s.takeSecureResourcesLocked()
	s.mu.Unlock()
	return resources
}

func (s *Registrar) takeSecureResourcesForResetLocked() secureResources {
	resources := secureResources{
		serverAttachments:   s.secureServerAttachments,
		responseAttachments: s.secureResponseAttachments,
		unprotectedPrimary:  s.unprotectedPrimary,
		drains:              s.drainTimers,
		expiry:              s.activeSecureSAExpiry,
		keepalive:           s.registrationKeepAlive,
	}
	s.secureServerAttachments = nil
	s.secureResponseAttachments = nil
	s.unprotectedPrimary = nil
	s.drainTimers = nil
	s.activeSecureSAExpiry = nil
	s.activeSecureSAExpiresAt = time.Time{}
	s.registrationKeepAlive = nil
	return resources
}

func (s *Registrar) takeSecureResourcesForExpiry(expiry *secureAssociationExpiry) (secureResources, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.activeSecureSAExpiry != expiry {
		return secureResources{}, false
	}
	return s.takeSecureResourcesLocked(), true
}

func (s *Registrar) takeSecureResourcesLocked() secureResources {
	resources := secureResources{
		serverAttachments:   s.secureServerAttachments,
		responseAttachments: s.secureResponseAttachments,
		unprotectedPrimary:  s.unprotectedPrimary,
		drains:              s.drainTimers,
		expiry:              s.activeSecureSAExpiry,
		keepalive:           s.registrationKeepAlive,
	}
	s.secureServerAttachments = nil
	s.secureResponseAttachments = nil
	s.unprotectedPrimary = nil
	s.drainTimers = nil
	s.activeSecureSAExpiry = nil
	s.activeSecureSAExpiresAt = time.Time{}
	s.registrationKeepAlive = nil
	s.closeDoneLocked()
	return resources
}

func (r secureResources) stop() error {
	var stopErr error
	if r.expiry != nil {
		r.expiry.stop()
	}
	if r.keepalive != nil {
		r.keepalive.stop()
	}
	for _, drain := range r.drains {
		drain.cancel()
		stopErr = errors.Join(stopErr, drain.close())
	}
	return stopErr
}

func (r secureResources) close(sess *session.Stack) error {
	var restoreErr error
	if r.unprotectedPrimary != nil {
		securePrimary, err := sess.PromotePrimary(r.unprotectedPrimary)
		if err != nil {
			restoreErr = fmt.Errorf("restoring unprotected IMS transport: %w", err)
		} else if securePrimary != nil {
			if err := securePrimary.Close(); err != nil {
				restoreErr = fmt.Errorf("deleting secure IMS transport: %w", err)
			}
		}
	}
	return errors.Join(restoreErr, closeAttachments(r.serverAttachments), closeAttachments(r.responseAttachments))
}

func saDrainDelay(timers session.TransactionTimers) time.Duration {
	return max(timers.TB, timers.TD, timers.TF, timers.TH, timers.TJ, timers.T4)
}

func saDrainDelayBefore(expiresAt time.Time, timers session.TransactionTimers) time.Duration {
	delay := saDrainDelay(timers)
	if expiresAt.IsZero() {
		return delay
	}
	remaining := time.Until(expiresAt)
	if remaining <= 0 {
		return 0
	}
	return min(delay, remaining)
}

func contextWithDoneDeadline(done <-chan struct{}, deadline time.Time) (context.Context, context.CancelFunc) {
	var ctx context.Context
	var cancel context.CancelFunc
	if deadline.IsZero() {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithDeadline(context.Background(), deadline)
	}
	stop := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-done:
			cancel()
		case <-stop:
		}
	}()
	return ctx, func() {
		once.Do(func() {
			close(stop)
			cancel()
		})
	}
}

func (s *Registrar) secureAssociationExpiresAt(now time.Time) time.Time {
	if s.currentSecurityVerify() == nil {
		return time.Time{}
	}
	return now.Add(s.currentRegisterExpires() + secureAssociationLifetimeGrace)
}

func (s *Registrar) currentSecureAssociationExpiresAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeSecureSAExpiresAt
}

func (s *Registrar) extendActiveSecureAssociationLifetime(expiresAt time.Time) {
	if expiresAt.IsZero() {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if !s.activeSecureSAExpiresAt.IsZero() && !expiresAt.After(s.activeSecureSAExpiresAt) {
		s.mu.Unlock()
		return
	}
	s.activeSecureSAExpiresAt = expiresAt
	delay := time.Until(expiresAt)

	delay = max(delay, 0)

	oldExpiry := s.activeSecureSAExpiry
	expiry := newSecureAssociationExpiry()
	done := s.done
	s.activeSecureSAExpiry = expiry
	if !s.startBackgroundTaskLocked(func() {
		s.runSecureAssociationExpiry(done, expiry, delay)
	}) {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	if oldExpiry != nil {
		oldExpiry.stop()
	}
}

func (s *Registrar) runSecureAssociationExpiry(done <-chan struct{}, expiry *secureAssociationExpiry, delay time.Duration) {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		s.expireActiveSecureAssociation(expiry)
	case <-done:
	case <-expiry.done():
	}
}

func (s *Registrar) expireActiveSecureAssociation(expiry *secureAssociationExpiry) {
	resources, ok := s.takeSecureResourcesForExpiry(expiry)
	if !ok {
		return
	}
	if err := errors.Join(resources.stop(), resources.close(s.sess)); err != nil {
		s.logger.Error("deleting expired IMS security association", "err", err)
	}
	s.setRegistered(false)
	s.publishRegistrationEvent(errSecureSAExpired)
}

func (s *Registrar) commitReauthentication(challenge security.Challenge, authorizationHeader string, flow Flow, ck, ik []byte, password string) {
	realm := strings.TrimSpace(challenge.Realm)
	if realm == "" {
		realm = strings.TrimPrefix(s.State().RegisterURI, "sip:")
	}
	authorizationHeader = registerAuthorizationHeaderName(authorizationHeader)
	s.mu.Lock()
	s.flow = flow.clone()
	s.authRealm = realm
	s.authNonce = challenge.Nonce
	s.authAlgorithm = challenge.Algorithm
	s.authQOP = challenge.QOP
	s.authOpaque = challenge.Opaque
	s.authHeader = authorizationHeader
	s.authNonceCount = 1
	s.authDigestNonce = challenge.Nonce
	s.authDigestAlgorithm = challenge.Algorithm
	s.authDigestPassword = password
	s.authCK = append([]byte(nil), ck...)
	s.authIK = append([]byte(nil), ik...)
	s.mu.Unlock()
}

func (s *Registrar) openRegisterSecurity(ctx context.Context) (*registerSecurity, error) {
	verify := s.currentSecurityVerify()
	if verify == nil {
		return nil, nil
	}
	flow := s.CurrentFlow()
	outbound, err := s.dialSecureTransport(ctx, verify, flow, s.authCK, s.authIK)
	if err != nil {
		return nil, err
	}
	registration := &registerSecurity{outbound: outbound}
	if !sameSessionEndpoint(outbound, s.sess.LocalAddr(), s.sess.RemoteAddr()) {
		attachment, err := s.sess.AddTransport(outbound)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("adding secure IMS transport: %w", err), outbound.Close())
		}
		registration.outboundAttachment = attachment
	}
	inboundTransports, inboundAttachments, err := s.startSecureServerTransports(ctx, verify)
	if err != nil {
		return nil, errors.Join(err, registration.close())
	}
	registration.inboundTransports = inboundTransports
	registration.inboundAttachments = inboundAttachments
	s.addReliableOutboundTransport(ctx, registration, verify, flow)
	responseAttachments, err := s.startSecureResponseTransportsWithKeys(ctx, verify, flow, outbound, inboundTransports, s.authCK, s.authIK)
	if err != nil {
		return nil, errors.Join(err, registration.close())
	}
	registration.responseAttachments = responseAttachments
	return registration, nil
}

func (s *Registrar) addReliableOutboundTransport(ctx context.Context, registration *registerSecurity, verify *security.Param, flow Flow) {
	if registration == nil || registration.outbound == nil || s.cfg.DialSecureTCP == nil ||
		!strings.EqualFold(sip.TransportToken(registration.outbound.LocalAddr()), "UDP") {
		return
	}
	reliable, err := s.cfg.DialSecureTCP(ctx, secureTransportConfigWithKeys(secureConfigParams{
		verify: verify, contactHost: flow.ContactHost,
		localPort: flow.SecurityClient.PortC, remotePort: verify.PortS,
		outboundSPI: verify.SPIS, inboundSPI: flow.SecurityClient.SPIC,
		ck: s.authCK, ik: s.authIK, outboundSaltBits: saltUEClientToPCSCFServer, inboundSaltBits: saltPCSCFServerToUEClient,
	}))
	if err != nil {
		s.logger.Warn("secure TCP fallback is unavailable", "err", err)
		return
	}
	attachment, err := s.sess.AddTransport(reliable)
	if err != nil {
		if closeErr := reliable.Close(); closeErr != nil {
			s.logger.Warn("closing unavailable secure TCP fallback", "err", closeErr)
		}
		s.logger.Warn("adding secure TCP fallback", "err", err)
		return
	}
	registration.inboundTransports = append(registration.inboundTransports, reliable)
	registration.inboundAttachments = append(registration.inboundAttachments, attachment)
}

func (s *Registrar) exchangeProtectedRegister(ctx context.Context, registration *registerSecurity, auth *security.Authorization) (sip.Message, error) {
	req := s.buildRegister(auth, s.currentSecurityVerify())
	if registration == nil || registration.outbound == nil {
		return s.sess.ExchangeWithOptions(ctx, req, s.protectedRegisterExchangeOptions())
	}
	if err := setRegisterViaTransport(&req, sip.TransportToken(registration.outbound.LocalAddr())); err != nil {
		return sip.Message{}, err
	}
	return s.sess.ExchangeWithTransport(ctx, registration.outbound, req, registration.exchangeOptions())
}

func setRegisterViaTransport(req *sip.Message, transport string) error {
	via := strings.TrimSpace(req.Header("Via"))
	values := sip.SplitHeaderList(via)
	if len(values) == 0 {
		return errors.New("selecting protected REGISTER transport: Via header is missing")
	}
	top := strings.TrimSpace(values[0])
	separator := strings.IndexByte(top, ' ')
	if separator <= len("SIP/2.0/") || !strings.EqualFold(top[:len("SIP/2.0/")], "SIP/2.0/") {
		return errors.New("selecting protected REGISTER transport: Via header is malformed")
	}
	values[0] = "SIP/2.0/" + transport + top[separator:]
	req.Headers.Set("Via", strings.Join(values, ", "))
	return nil
}

func (s *Registrar) commitRegisterSecurity(registration *registerSecurity) error {
	if registration == nil || registration.outbound == nil {
		return nil
	}
	oldPrimary, err := s.sess.PromotePrimary(registration.outbound)
	if err != nil {
		return fmt.Errorf("promoting secure IMS transport: %w", err)
	}
	oldServers := s.replaceSecureServerAttachments(registration.inboundAttachments)
	oldResponses := s.replaceSecureResponseAttachments(registration.responseAttachments)
	registration.outboundAttachment = nil
	registration.inboundAttachments = nil
	registration.responseAttachments = nil
	closeErr := errors.Join(closeAttachments(oldServers), closeAttachments(oldResponses))
	if oldPrimary != nil && !s.retainUnprotectedPrimary(oldPrimary) {
		closeErr = errors.Join(closeErr, oldPrimary.Close())
	}
	return closeErr
}

func (s *Registrar) retainUnprotectedPrimary(attachment session.Attachment) bool {
	transportAttachment, ok := attachment.(session.TransportAttachment)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unprotectedPrimary != nil {
		return false
	}
	s.unprotectedPrimary = transportAttachment.Transport()
	return true
}

func sameSessionEndpoint(transport session.Transport, local, remote net.Addr) bool {
	if transport == nil {
		return false
	}
	return sameAddr(transport.LocalAddr(), local) && sameAddr(transport.RemoteAddr(), remote)
}

func secureDatagramTransport(transports []session.Transport) session.Transport {
	for _, transport := range transports {
		if transport != nil && strings.EqualFold(sip.TransportToken(transport.LocalAddr()), "UDP") {
			return transport
		}
	}
	return nil
}

func sameSessionDatagramEndpoint(local, remote net.Addr, localPort, remotePort int) bool {
	localUDP, ok := local.(*net.UDPAddr)
	if !ok || localUDP == nil {
		return false
	}
	remoteUDP, ok := remote.(*net.UDPAddr)
	if !ok || remoteUDP == nil {
		return false
	}
	return sameAddr(localUDP, &net.UDPAddr{IP: localUDP.IP, Port: localPort, Zone: localUDP.Zone}) &&
		sameAddr(remoteUDP, &net.UDPAddr{IP: remoteUDP.IP, Port: remotePort, Zone: remoteUDP.Zone})
}

func sameAddr(left, right net.Addr) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Network() == right.Network() && left.String() == right.String()
}

type secureConfigParams struct {
	verify           *security.Param
	contactHost      string
	localPort        int
	remotePort       int
	outboundSPI      uint32
	inboundSPI       uint32
	ck               []byte
	ik               []byte
	outboundSaltBits byte
	inboundSaltBits  byte
}

func secureTransportConfigWithKeys(params secureConfigParams) session.SecureTCPConfig {
	return session.SecureTCPConfig{
		InnerLocalIP:  secureInnerLocalIP(params.verify, params.contactHost),
		LocalPort:     params.localPort,
		RemotePort:    params.remotePort,
		OutboundSPI:   params.outboundSPI,
		InboundSPI:    params.inboundSPI,
		Encryption:    params.verify.EAlg,
		EncryptionKey: espEncryptionKey(params.verify.EAlg, params.ck),
		Integrity:     params.verify.Alg,
		IntegrityKey:  espIntegrityKey(params.verify.Alg, params.ck, params.ik),
		Mode:          params.verify.Mod,
		OutboundSalt:  espSalt(params.verify, params.ck, params.ik, params.outboundSaltBits),
		InboundSalt:   espSalt(params.verify, params.ck, params.ik, params.inboundSaltBits),
	}
}

func secureDatagramConfigWithKeys(params secureConfigParams) session.SecureUDPConfig {
	return session.SecureUDPConfig{
		InnerLocalIP:  secureInnerLocalIP(params.verify, params.contactHost),
		LocalPort:     params.localPort,
		RemotePort:    params.remotePort,
		OutboundSPI:   params.outboundSPI,
		InboundSPI:    params.inboundSPI,
		Encryption:    params.verify.EAlg,
		EncryptionKey: espEncryptionKey(params.verify.EAlg, params.ck),
		Integrity:     params.verify.Alg,
		IntegrityKey:  espIntegrityKey(params.verify.Alg, params.ck, params.ik),
		Mode:          params.verify.Mod,
		OutboundSalt:  espSalt(params.verify, params.ck, params.ik, params.outboundSaltBits),
		InboundSalt:   espSalt(params.verify, params.ck, params.ik, params.inboundSaltBits),
	}
}

func secureInnerLocalIP(verify *security.Param, contactHost string) net.IP {
	if verify == nil || !strings.EqualFold(verify.Mod, "UDP-enc-tun") {
		return nil
	}
	return net.ParseIP(strings.TrimSpace(contactHost))
}

func espEncryptionKey(ealg string, ck []byte) []byte {
	if strings.EqualFold(strings.TrimSpace(ealg), "null") {
		return nil
	}
	return append([]byte(nil), ck...)
}

func espIntegrityKey(alg string, ck, ik []byte) []byte {
	switch strings.ToLower(strings.TrimSpace(alg)) {
	case "hmac-md5-96":
		return append([]byte(nil), ik...)
	case "hmac-sha-1-96", "hmac-sha1-96":
		key := append([]byte(nil), ik...)
		if len(key) == 16 {
			key = append(key, 0, 0, 0, 0)
		}
		return key
	case "hmac-sha-2-256-128", "hmac-sha2-256-128", "hmac-sha256-128":
		key := make([]byte, 0, len(ck)+len(ik))
		key = append(key, ck...)
		key = append(key, ik...)
		return kdf33220(key, 0x5a, []byte("HMAC-SHA2-256-128"))
	case "aes-gmac", "aes-gmac-us":
		return append([]byte(nil), ik...)
	case "null":
		return nil
	default:
		return nil
	}
}

func espSalt(verify *security.Param, ck, ik []byte, uniqueBits byte) [4]byte {
	if verify == nil {
		return [4]byte{}
	}
	var fc byte
	var label string
	switch {
	case strings.EqualFold(verify.Alg, "aes-gmac"), strings.EqualFold(verify.Alg, "aes-gmac-us"):
		fc = 0x58
		label = "AES_GMAC_SALT"
	case strings.EqualFold(verify.EAlg, "aes-gcm"), strings.EqualFold(verify.EAlg, "aes-gcm-us"):
		fc = 0x59
		label = "AES_GCM_SALT"
	default:
		return [4]byte{}
	}
	key := make([]byte, 0, len(ck)+len(ik))
	key = append(key, ck...)
	key = append(key, ik...)
	digest := kdf33220(key, fc, []byte(label))
	var salt [4]byte
	copy(salt[:], digest[len(digest)-4:])
	if strings.HasSuffix(strings.ToLower(strings.TrimSpace(verify.Alg)), "-us") ||
		strings.HasSuffix(strings.ToLower(strings.TrimSpace(verify.EAlg)), "-us") {
		salt[len(salt)-1] ^= uniqueBits & 0x03
	}
	return salt
}

func kdf33220(key []byte, fc byte, params ...[]byte) []byte {
	s := []byte{fc}
	for _, param := range params {
		s = append(s, param...)
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(param)))
		s = append(s, length[:]...)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(s)
	return mac.Sum(nil)
}

func (s *Registrar) dialSecureTransport(ctx context.Context, verify *security.Param, flow Flow, ck, ik []byte) (session.Transport, error) {
	switch sip.TransportToken(s.sess.LocalAddr()) {
	case "TCP":
		if s.cfg.DialSecureTCP == nil {
			return nil, errors.New("dialing secure IMS transport: TCP dialer is not configured")
		}
		secureTransport, err := s.cfg.DialSecureTCP(ctx, secureTransportConfigWithKeys(secureConfigParams{
			verify: verify, contactHost: flow.ContactHost,
			localPort: flow.SecurityClient.PortC, remotePort: verify.PortS,
			outboundSPI: verify.SPIS, inboundSPI: flow.SecurityClient.SPIC,
			ck: ck, ik: ik, outboundSaltBits: saltUEClientToPCSCFServer, inboundSaltBits: saltPCSCFServerToUEClient,
		}))
		if err != nil {
			return nil, fmt.Errorf("dialing secure IMS transport: %w", err)
		}
		return secureTransport, nil
	default:
		if s.cfg.DialSecureUDP == nil {
			return nil, errors.New("dialing secure IMS datagram transport: UDP dialer is not configured")
		}
		secureTransport, err := s.cfg.DialSecureUDP(ctx, secureDatagramConfigWithKeys(secureConfigParams{
			verify: verify, contactHost: flow.ContactHost,
			localPort: flow.SecurityClient.PortC, remotePort: verify.PortS,
			outboundSPI: verify.SPIS, inboundSPI: flow.SecurityClient.SPIC,
			ck: ck, ik: ik, outboundSaltBits: saltUEClientToPCSCFServer, inboundSaltBits: saltPCSCFServerToUEClient,
		}))
		if err != nil {
			return nil, fmt.Errorf("dialing secure IMS datagram transport: %w", err)
		}
		return secureTransport, nil
	}
}

func (s *Registrar) startSecureServerTransports(ctx context.Context, verify *security.Param) ([]session.Transport, []session.Attachment, error) {
	flow := s.CurrentFlow()
	return s.startSecureServerTransportsWithKeys(ctx, verify, flow, s.authCK, s.authIK)
}

func (s *Registrar) startSecureServerTransportsWithKeys(ctx context.Context, verify *security.Param, flow Flow, ck, ik []byte) ([]session.Transport, []session.Attachment, error) {
	transports := make([]session.Transport, 0, 2)
	attachments := make([]session.Attachment, 0, 2)
	if s.cfg.ListenSecureTCP != nil {
		serverTransport, err := s.cfg.ListenSecureTCP(ctx, secureTransportConfigWithKeys(secureConfigParams{
			verify: verify, contactHost: flow.ContactHost,
			localPort: flow.SecurityClient.PortS, remotePort: verify.PortC,
			outboundSPI: verify.SPIC, inboundSPI: flow.SecurityClient.SPIS,
			ck: ck, ik: ik, outboundSaltBits: saltUEServerToPCSCFClient, inboundSaltBits: saltPCSCFClientToUEServer,
		}))
		if err != nil {
			return nil, nil, errors.Join(fmt.Errorf("listening secure IMS transport: %w", err), closeAttachments(attachments))
		}
		attachment, err := s.sess.AddTransport(serverTransport)
		if err != nil {
			closeErr := serverTransport.Close()
			return nil, nil, errors.Join(fmt.Errorf("adding secure IMS transport: %w", err), closeErr, closeAttachments(attachments))
		}
		transports = append(transports, serverTransport)
		attachments = append(attachments, attachment)
	}
	if s.cfg.ListenSecureUDP != nil {
		serverDatagramTransport, err := s.cfg.ListenSecureUDP(ctx, secureDatagramConfigWithKeys(secureConfigParams{
			verify: verify, contactHost: flow.ContactHost,
			localPort: flow.SecurityClient.PortS, remotePort: verify.PortC,
			outboundSPI: verify.SPIC, inboundSPI: flow.SecurityClient.SPIS,
			ck: ck, ik: ik, outboundSaltBits: saltUEServerToPCSCFClient, inboundSaltBits: saltPCSCFClientToUEServer,
		}))
		if err != nil {
			return nil, nil, errors.Join(fmt.Errorf("listening secure IMS datagram transport: %w", err), closeAttachments(attachments))
		}
		attachment, err := s.sess.AddTransport(serverDatagramTransport)
		if err != nil {
			closeErr := serverDatagramTransport.Close()
			return nil, nil, errors.Join(fmt.Errorf("adding secure IMS datagram transport: %w", err), closeErr, closeAttachments(attachments))
		}
		transports = append(transports, serverDatagramTransport)
		attachments = append(attachments, attachment)
	}
	return transports, attachments, nil
}

func (s *Registrar) startSecureResponseTransportsWithKeys(ctx context.Context, verify *security.Param, flow Flow, outbound session.Transport, inboundTransports []session.Transport, ck, ik []byte) ([]session.Attachment, error) {
	if outbound == nil || strings.EqualFold(sip.TransportToken(outbound.LocalAddr()), "UDP") {
		return nil, nil
	}
	if s.cfg.DialSecureUDP == nil {
		return nil, nil
	}
	inboundDatagramTransport := secureDatagramTransport(inboundTransports)
	if inboundDatagramTransport == nil {
		return nil, nil
	}
	if sameSessionDatagramEndpoint(s.sess.LocalAddr(), s.sess.RemoteAddr(), flow.SecurityClient.PortC, verify.PortS) {
		return nil, nil
	}
	responseTransport, err := s.cfg.DialSecureUDP(ctx, secureDatagramConfigWithKeys(secureConfigParams{
		verify: verify, contactHost: flow.ContactHost,
		localPort: flow.SecurityClient.PortC, remotePort: verify.PortS,
		outboundSPI: verify.SPIS, inboundSPI: flow.SecurityClient.SPIC,
		ck: ck, ik: ik, outboundSaltBits: saltUEClientToPCSCFServer, inboundSaltBits: saltPCSCFServerToUEClient,
	}))
	if err != nil {
		return nil, fmt.Errorf("dialing secure IMS datagram response transport: %w", err)
	}
	attachment, err := s.sess.AddTransport(responseTransport)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("adding secure IMS datagram response transport: %w", err), responseTransport.Close())
	}
	route, err := s.sess.RouteResponses(inboundDatagramTransport, responseTransport)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("routing secure IMS datagram responses: %w", err), attachment.Close())
	}
	return []session.Attachment{attachment, route}, nil
}

func selectSecurityServer(values []string, offered security.Params, requiredMode string) (*security.Param, []string, error) {
	raw := make([]string, 0, len(values))
	params := make(security.Params, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		raw = append(raw, value)
		var parsed security.Params
		if err := parsed.UnmarshalText([]byte(value)); err != nil {
			return nil, nil, err
		}
		params = append(params, parsed...)
	}
	if len(raw) == 0 {
		return nil, nil, errors.New("applying Security-Server: header is empty")
	}

	sharedSA, hasSharedSA := sharedSecurityServerAssociation(params, requiredMode)
	qValues := make(map[int]struct{})
	bestQ := -1
	var best *security.Param
	for _, param := range params {
		q, err := securityQValue(param.Q)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing Security-Server q-value %q: %w", param.Q, err)
		}
		if _, duplicate := qValues[q]; duplicate {
			return nil, nil, fmt.Errorf("parsing Security-Server: duplicate q-value %q", param.Q)
		}
		qValues[q] = struct{}{}
		if hasSharedSA && securityAssociationEmpty(param) &&
			(requiredMode == "" || strings.EqualFold(param.Mod, requiredMode)) {
			param.PortC = sharedSA.portC
			param.PortS = sharedSA.portS
			param.SPIC = sharedSA.spiC
			param.SPIS = sharedSA.spiS
		}
		normalized, ok := security.NormalizeParam(param)
		if !ok ||
			(requiredMode != "" && !strings.EqualFold(normalized.Mod, requiredMode)) ||
			!securityMechanismOffered(normalized, offered) {
			continue
		}
		if best != nil && q <= bestQ {
			continue
		}
		verify := normalized
		best = &verify
		bestQ = q
	}
	if best == nil {
		return nil, nil, errors.New("applying Security-Server: no compatible ipsec-3gpp security mechanism")
	}
	return best, raw, nil
}

type securityServerAssociation struct {
	portC int
	portS int
	spiC  uint32
	spiS  uint32
}

func sharedSecurityServerAssociation(params security.Params, mode string) (securityServerAssociation, bool) {
	var shared securityServerAssociation
	found := false
	for _, param := range params {
		if mode != "" && !strings.EqualFold(param.Mod, mode) {
			continue
		}
		if !securityAssociationComplete(param) {
			continue
		}
		candidate := securityServerAssociation{
			portC: param.PortC,
			portS: param.PortS,
			spiC:  param.SPIC,
			spiS:  param.SPIS,
		}
		if found && candidate != shared {
			return securityServerAssociation{}, false
		}
		shared = candidate
		found = true
	}
	return shared, found
}

func securityAssociationComplete(param security.Param) bool {
	return param.PortC != 0 && param.PortS != 0 && param.SPIC != 0 && param.SPIS != 0
}

func securityAssociationEmpty(param security.Param) bool {
	return param.PortC == 0 && param.PortS == 0 && param.SPIC == 0 && param.SPIS == 0
}

func securityMechanismOffered(selected security.Param, offered security.Params) bool {
	return slices.ContainsFunc(offered, func(candidate security.Param) bool {
		normalized, ok := security.NormalizeParam(candidate)
		if !ok {
			return false
		}
		return strings.EqualFold(normalized.Mechanism, selected.Mechanism) &&
			strings.EqualFold(normalized.Alg, selected.Alg) &&
			strings.EqualFold(normalized.EAlg, selected.EAlg) &&
			strings.EqualFold(normalized.Mod, selected.Mod) &&
			strings.EqualFold(normalized.Prot, selected.Prot) &&
			securitySPIsDisjoint(normalized, selected)
	})
}

func securitySPIsDisjoint(left, right security.Param) bool {
	return left.SPIC != right.SPIC &&
		left.SPIC != right.SPIS &&
		left.SPIS != right.SPIC &&
		left.SPIS != right.SPIS
}

func securityQValue(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 1000, nil
	}
	integer, fraction, hasFraction := strings.Cut(value, ".")
	if integer != "0" && integer != "1" {
		return 0, fmt.Errorf("invalid q-value %q", value)
	}
	if !hasFraction {
		if integer == "1" {
			return 1000, nil
		}
		return 0, nil
	}
	if len(fraction) > 3 {
		return 0, fmt.Errorf("invalid q-value precision %q", value)
	}
	q := 0
	for i := range len(fraction) {
		if fraction[i] < '0' || fraction[i] > '9' || integer == "1" && fraction[i] != '0' {
			return 0, fmt.Errorf("invalid q-value %q", value)
		}
		q = q*10 + int(fraction[i]-'0')
	}
	for range 3 - len(fraction) {
		q *= 10
	}
	if integer == "1" {
		return 1000, nil
	}
	return q, nil
}

type ipsecAlgorithms struct {
	integrity  []string
	encryption []string
	modes      []string
}

func ipsecAlgorithmsFromConfig(cfg Config) ipsecAlgorithms {
	return ipsecAlgorithms{
		integrity:  cfg.IPSecIntegrityAlgorithms,
		encryption: cfg.IPSecEncryptionAlgorithms,
		modes:      cfg.IPSecModes,
	}
}

func newFlow(host string, port int, algorithms ipsecAlgorithms) Flow {
	client := newSecurityClient(port, algorithms)
	return Flow{
		ContactHost:     host,
		RegisterPort:    port,
		MessagePort:     port,
		SecurityClient:  client,
		SecurityClients: securityClientCapabilities(client, algorithms),
	}
}

func newSecurityClient(registerPort int, algorithms ipsecAlgorithms) security.Param {
	clientPort := randomIMSPort()
	for clientPort == registerPort {
		clientPort = randomIMSPort()
	}
	serverPort := randomIMSPort()
	for serverPort == clientPort || serverPort == registerPort {
		serverPort = randomIMSPort()
	}
	clientSPI := randomNonZeroUint32Except(0)
	serverSPI := randomNonZeroUint32Except(clientSPI)
	integrity, encryption := preferredIPSecAlgorithms(algorithms)
	return security.Param{
		Mechanism: "ipsec-3gpp",
		Alg:       integrity,
		EAlg:      encryption,
		Mod:       algorithms.modes[0],
		PortC:     clientPort,
		PortS:     serverPort,
		Prot:      "esp",
		SPIC:      clientSPI,
		SPIS:      serverSPI,
	}
}

func securityClientCapabilities(base security.Param, algorithms ipsecAlgorithms) security.Params {
	return securityClientCapabilitiesForModes(base, algorithms, algorithms.modes)
}

func reauthenticationSecurityClientCapabilities(base security.Param, algorithms ipsecAlgorithms) (security.Params, error) {
	modes, err := security.NormalizeIPSecModes([]string{base.Mod})
	if err != nil {
		return nil, fmt.Errorf("building re-authentication Security-Client: %w", err)
	}
	return securityClientCapabilitiesForModes(base, algorithms, modes), nil
}

func securityClientCapabilitiesForModes(base security.Param, algorithms ipsecAlgorithms, modes []string) security.Params {
	params := make(security.Params, 0, len(algorithms.integrity)*len(algorithms.encryption)*len(modes))
	for _, integrity := range algorithms.integrity {
		for _, encryption := range algorithms.encryption {
			for _, mode := range modes {
				if !compatibleIPSecAlgorithms(integrity, encryption) {
					continue
				}
				param := base
				param.Alg = integrity
				param.EAlg = encryption
				param.Mod = mode
				params = append(params, param)
			}
		}
	}
	return params
}

func preferredIPSecAlgorithms(algorithms ipsecAlgorithms) (string, string) {
	for _, integrity := range algorithms.integrity {
		for _, encryption := range algorithms.encryption {
			if compatibleIPSecAlgorithms(integrity, encryption) {
				return integrity, encryption
			}
		}
	}
	return "", ""
}

func hasCompatibleIPSecAlgorithms(integrity, encryption []string) bool {
	alg, ealg := preferredIPSecAlgorithms(ipsecAlgorithms{integrity: integrity, encryption: encryption})
	return alg != "" && ealg != ""
}

func compatibleIPSecAlgorithms(integrity, encryption string) bool {
	integrity = strings.ToLower(strings.TrimSpace(integrity))
	encryption = strings.ToLower(strings.TrimSpace(encryption))
	switch {
	case integrity == "null":
		return encryption == "aes-gcm" || encryption == "aes-gcm-us"
	case encryption == "aes-gcm" || encryption == "aes-gcm-us":
		return false
	case integrity == "aes-gmac" || integrity == "aes-gmac-us":
		return encryption == "null"
	case integrity == "hmac-md5-96" || integrity == "hmac-sha-1-96" || integrity == "hmac-sha2-256-128":
		return encryption == "null" || encryption == "aes-cbc"
	default:
		return false
	}
}

func reauthSecurityClient(current, peer security.Param, registerPort int) security.Param {
	next := current
	next.PortC = randomIMSPort()
	for next.PortC == current.PortC || next.PortC == current.PortS || next.PortC == registerPort {
		next.PortC = randomIMSPort()
	}
	next.SPIC = randomNonZeroUint32Except(current.SPIC, current.SPIS, peer.SPIC, peer.SPIS)
	next.SPIS = randomNonZeroUint32Except(current.SPIC, current.SPIS, peer.SPIC, peer.SPIS, next.SPIC)
	return next
}

func (s *Registrar) rotateInitialNATProtectedPorts() {
	s.mu.Lock()
	defer s.mu.Unlock()
	rotateNATProtectedPorts(&s.flow, true)
}

func rotateNATProtectedPorts(flow *Flow, rotateServer bool) {
	oldClientPort := flow.SecurityClient.PortC
	oldServerPort := flow.SecurityClient.PortS
	flow.SecurityClient.PortC = randomIMSPortExcept(flow.RegisterPort, oldClientPort, oldServerPort)
	if rotateServer {
		flow.SecurityClient.PortS = randomIMSPortExcept(flow.RegisterPort, oldClientPort, oldServerPort, flow.SecurityClient.PortC)
	}
	for i := range flow.SecurityClients {
		flow.SecurityClients[i].PortC = flow.SecurityClient.PortC
		flow.SecurityClients[i].PortS = flow.SecurityClient.PortS
	}
}

func validateReauthenticationSecurityServer(current Flow, selected *security.Param) error {
	if current.SecurityVerify == nil || selected == nil {
		return nil
	}
	if selected.PortS != current.SecurityVerify.PortS {
		return fmt.Errorf("applying re-authentication Security-Server: protected server port changed from %d to %d", current.SecurityVerify.PortS, selected.PortS)
	}
	if selected.PortC == current.SecurityVerify.PortC {
		return errors.New("applying re-authentication Security-Server: protected client port did not change")
	}
	if strings.EqualFold(current.SecurityVerify.Mod, "UDP-enc-tun") && !strings.EqualFold(selected.Mod, "UDP-enc-tun") {
		return errors.New("applying re-authentication Security-Server: UDP encapsulated tunnel mode was not preserved")
	}
	if selected.SPIC == current.SecurityVerify.SPIC || selected.SPIC == current.SecurityVerify.SPIS ||
		selected.SPIS == current.SecurityVerify.SPIC || selected.SPIS == current.SecurityVerify.SPIS {
		return errors.New("applying re-authentication Security-Server: SPI reuses an active P-CSCF SPI")
	}
	return nil
}

func randomNonZeroUint32Except(except ...uint32) uint32 {
	value := sip.RandomUint32()
	for !security.ValidESPSPI(value) || slices.Contains(except, value) {
		value = sip.RandomUint32()
	}
	return value
}

func randomIMSPort() int {
	const base = 10000
	const span = 55535
	return base + int(sip.RandomUint32()%span)
}

func randomIMSPortExcept(except ...int) int {
	port := randomIMSPort()
	for slices.Contains(except, port) {
		port = randomIMSPort()
	}
	return port
}
