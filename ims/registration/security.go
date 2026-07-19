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

func closeAttachments(attachments []session.Attachment) {
	for _, attachment := range attachments {
		if attachment != nil {
			_ = attachment.Close()
		}
	}
}

func (r *registerSecurity) close() {
	if r == nil {
		return
	}
	closeAttachments(r.inboundAttachments)
	r.inboundAttachments = nil
	r.inboundTransports = nil
	closeAttachments(r.responseAttachments)
	r.responseAttachments = nil
	if r.outboundAttachment != nil {
		_ = r.outboundAttachment.Close()
		r.outboundAttachment = nil
	}
	r.outbound = nil
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
		closeAttachments(attachments)
		return
	}
	drain := &attachmentDrain{
		attachments: append([]session.Attachment(nil), attachments...),
	}
	transports := attachmentTransports(attachments)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		closeAttachments(attachments)
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
			_ = s.sess.WaitTransportsIdle(ctx, transports...)
		}
		drain.close()
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
		closeAttachments(attachments)
		return
	}
	drain := &attachmentDrain{attachments: append([]session.Attachment(nil), attachments...)}
	oldTransports := attachmentTransports(attachments)

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		watch.Close()
		closeAttachments(attachments)
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
				_ = s.sess.WaitTransportsIdle(idleCtx, oldTransports...)
				idleCancel()
			}
		}
		drain.close()
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

func (d *attachmentDrain) close() {
	d.closeOnce.Do(func() {
		closeAttachments(d.attachments)
	})
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
	resources := s.takeSecureResourcesForClose()
	resources.stop()
	s.bgWG.Wait()
	return resources.close(s.sess)
}

func (s *Registrar) clearSecureResources() error {
	resources := s.takeSecureResourcesForReset()
	resources.stop()
	s.bgWG.Wait()
	return resources.close(s.sess)
}

func (s *Registrar) clearSecureResourcesAfter(delay time.Duration) {
	resources := s.takeSecureResourcesForReset()
	resources.stop()
	s.bgWG.Wait()
	if delay <= 0 {
		if err := resources.close(s.sess); err != nil {
			s.logger.Error("deleting IMS security association", "err", err)
		}
		return
	}
	done := s.done
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-done:
		}
		if err := resources.close(s.sess); err != nil {
			s.logger.Error("deleting IMS security association", "err", err)
		}
	}()
}

func (s *Registrar) takeSecureResourcesForClose() secureResources {
	s.mu.Lock()
	resources := s.takeSecureResourcesLocked()
	s.mu.Unlock()
	return resources
}

func (s *Registrar) takeSecureResourcesForReset() secureResources {
	s.mu.Lock()
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
	s.mu.Unlock()
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

func (r secureResources) stop() {
	if r.expiry != nil {
		r.expiry.stop()
	}
	if r.keepalive != nil {
		r.keepalive.stop()
	}
	for _, drain := range r.drains {
		drain.cancel()
		drain.close()
	}
}

func (r secureResources) close(sess *session.Session) error {
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
	closeAttachments(r.serverAttachments)
	closeAttachments(r.responseAttachments)
	return restoreErr
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
	resources.stop()
	if err := resources.close(s.sess); err != nil {
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
			outbound.Close()
			return nil, fmt.Errorf("adding secure IMS transport: %w", err)
		}
		registration.outboundAttachment = attachment
	}
	inboundTransports, inboundAttachments, err := s.startSecureServerTransports(ctx, verify)
	if err != nil {
		registration.close()
		return nil, err
	}
	registration.inboundTransports = inboundTransports
	registration.inboundAttachments = inboundAttachments
	s.addReliableOutboundTransport(ctx, registration, verify, flow)
	responseAttachments, err := s.startSecureResponseTransportsWithKeys(ctx, verify, flow, outbound, inboundTransports, s.authCK, s.authIK)
	if err != nil {
		registration.close()
		return nil, err
	}
	registration.responseAttachments = responseAttachments
	return registration, nil
}

func (s *Registrar) addReliableOutboundTransport(ctx context.Context, registration *registerSecurity, verify *security.Param, flow Flow) {
	if registration == nil || registration.outbound == nil || s.cfg.DialSecureTCP == nil ||
		!strings.EqualFold(sip.TransportToken(registration.outbound.LocalAddr()), "UDP") {
		return
	}
	reliable, err := s.cfg.DialSecureTCP(ctx, secureTransportConfigWithKeys(
		verify,
		flow.SecurityClient.PortC,
		verify.PortS,
		verify.SPIS,
		flow.SecurityClient.SPIC,
		s.authCK,
		s.authIK,
	))
	if err != nil {
		s.logger.Warn("secure TCP fallback is unavailable", "err", err)
		return
	}
	attachment, err := s.sess.AddTransport(reliable)
	if err != nil {
		_ = reliable.Close()
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
	return s.sess.ExchangeWithTransport(ctx, registration.outbound, req, registration.exchangeOptions())
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
	closeAttachments(oldServers)
	closeAttachments(oldResponses)
	if oldPrimary != nil && !s.retainUnprotectedPrimary(oldPrimary) {
		_ = oldPrimary.Close()
	}
	return nil
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

func secureTransportConfigWithKeys(verify *security.Param, localPort, remotePort int, outboundSPI, inboundSPI uint32, ck, ik []byte) session.SecureTCPConfig {
	return session.SecureTCPConfig{
		LocalPort:     localPort,
		RemotePort:    remotePort,
		OutboundSPI:   outboundSPI,
		InboundSPI:    inboundSPI,
		Encryption:    verify.EAlg,
		EncryptionKey: append([]byte(nil), ck...),
		Integrity:     verify.Alg,
		IntegrityKey:  espIntegrityKey(verify.Alg, ik),
		Mode:          verify.Mod,
		Salt:          espSalt(verify, ck, ik),
	}
}

func secureDatagramConfigWithKeys(verify *security.Param, localPort, remotePort int, outboundSPI, inboundSPI uint32, ck, ik []byte) session.SecureUDPConfig {
	return session.SecureUDPConfig{
		LocalPort:     localPort,
		RemotePort:    remotePort,
		OutboundSPI:   outboundSPI,
		InboundSPI:    inboundSPI,
		Encryption:    verify.EAlg,
		EncryptionKey: append([]byte(nil), ck...),
		Integrity:     verify.Alg,
		IntegrityKey:  espIntegrityKey(verify.Alg, ik),
		Mode:          verify.Mod,
		Salt:          espSalt(verify, ck, ik),
	}
}

func espIntegrityKey(alg string, ik []byte) []byte {
	key := append([]byte(nil), ik...)
	switch strings.ToLower(strings.TrimSpace(alg)) {
	case "hmac-sha-1-96", "hmac-sha1-96":
		if len(key) == 16 {
			key = append(key, 0, 0, 0, 0)
		}
	}
	return key
}

func espSalt(verify *security.Param, ck, ik []byte) [4]byte {
	if verify == nil {
		return [4]byte{}
	}
	var fc byte
	var label string
	switch {
	case strings.EqualFold(verify.Alg, "aes-gmac"):
		fc = 0x58
		label = "AES_GMAC_SALT"
	case strings.EqualFold(verify.EAlg, "aes-gcm"):
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
		secureTransport, err := s.cfg.DialSecureTCP(ctx, secureTransportConfigWithKeys(verify, flow.SecurityClient.PortC, verify.PortS, verify.SPIS, flow.SecurityClient.SPIC, ck, ik))
		if err != nil {
			return nil, fmt.Errorf("dialing secure IMS transport: %w", err)
		}
		return secureTransport, nil
	default:
		if s.cfg.DialSecureUDP == nil {
			return nil, errors.New("dialing secure IMS datagram transport: UDP dialer is not configured")
		}
		secureTransport, err := s.cfg.DialSecureUDP(ctx, secureDatagramConfigWithKeys(verify, flow.SecurityClient.PortC, verify.PortS, verify.SPIS, flow.SecurityClient.SPIC, ck, ik))
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
		serverTransport, err := s.cfg.ListenSecureTCP(ctx, secureTransportConfigWithKeys(verify, flow.SecurityClient.PortS, verify.PortC, verify.SPIC, flow.SecurityClient.SPIS, ck, ik))
		if err != nil {
			closeAttachments(attachments)
			return nil, nil, fmt.Errorf("listening secure IMS transport: %w", err)
		}
		attachment, err := s.sess.AddTransport(serverTransport)
		if err != nil {
			serverTransport.Close()
			closeAttachments(attachments)
			return nil, nil, fmt.Errorf("adding secure IMS transport: %w", err)
		}
		transports = append(transports, serverTransport)
		attachments = append(attachments, attachment)
	}
	if s.cfg.ListenSecureUDP != nil {
		serverDatagramTransport, err := s.cfg.ListenSecureUDP(ctx, secureDatagramConfigWithKeys(verify, flow.SecurityClient.PortS, verify.PortC, verify.SPIC, flow.SecurityClient.SPIS, ck, ik))
		if err != nil {
			closeAttachments(attachments)
			return nil, nil, fmt.Errorf("listening secure IMS datagram transport: %w", err)
		}
		attachment, err := s.sess.AddTransport(serverDatagramTransport)
		if err != nil {
			serverDatagramTransport.Close()
			closeAttachments(attachments)
			return nil, nil, fmt.Errorf("adding secure IMS datagram transport: %w", err)
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
	responseTransport, err := s.cfg.DialSecureUDP(ctx, secureDatagramConfigWithKeys(verify, flow.SecurityClient.PortC, verify.PortS, verify.SPIS, flow.SecurityClient.SPIC, ck, ik))
	if err != nil {
		return nil, fmt.Errorf("dialing secure IMS datagram response transport: %w", err)
	}
	attachment, err := s.sess.AddTransport(responseTransport)
	if err != nil {
		responseTransport.Close()
		return nil, fmt.Errorf("adding secure IMS datagram response transport: %w", err)
	}
	route, err := s.sess.RouteResponses(inboundDatagramTransport, responseTransport)
	if err != nil {
		_ = attachment.Close()
		return nil, fmt.Errorf("routing secure IMS datagram responses: %w", err)
	}
	return []session.Attachment{attachment, route}, nil
}

func selectSecurityServer(values []string, offered security.Params) (*security.Param, []string, error) {
	raw := make([]string, 0, len(values))
	qValues := make(map[int]struct{})
	bestQ := -1
	var best *security.Param
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		raw = append(raw, value)
		var params security.Params
		if err := params.UnmarshalText([]byte(value)); err != nil {
			return nil, nil, err
		}
		for _, param := range params {
			q, err := securityQValue(param.Q)
			if err != nil {
				return nil, nil, fmt.Errorf("parsing Security-Server q-value %q: %w", param.Q, err)
			}
			if _, duplicate := qValues[q]; duplicate {
				return nil, nil, fmt.Errorf("parsing Security-Server: duplicate q-value %q", param.Q)
			}
			qValues[q] = struct{}{}
			normalized, ok := security.NormalizeParam(param)
			if !ok || !securityMechanismOffered(normalized, offered) {
				continue
			}
			if best != nil && q <= bestQ {
				continue
			}
			verify := normalized
			best = &verify
			bestQ = q
		}
	}
	if len(raw) == 0 {
		return nil, nil, errors.New("applying Security-Server: header is empty")
	}
	if best == nil {
		return nil, nil, errors.New("applying Security-Server: no compatible ipsec-3gpp security mechanism")
	}
	return best, raw, nil
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

func newFlow(host string, port int) Flow {
	client := newSecurityClient(port)
	return Flow{
		ContactHost:     host,
		RegisterPort:    port,
		MessagePort:     port,
		SecurityClient:  client,
		SecurityClients: securityClientCapabilities(client),
	}
}

func newSecurityClient(registerPort int) security.Param {
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
	return security.Param{
		Mechanism: "ipsec-3gpp",
		Alg:       "hmac-sha-1-96",
		EAlg:      "aes-cbc",
		Mod:       "trans",
		PortC:     clientPort,
		PortS:     serverPort,
		Prot:      "esp",
		SPIC:      clientSPI,
		SPIS:      serverSPI,
	}
}

func securityClientCapabilities(base security.Param) security.Params {
	// The supported IMS access paths terminate NAT before SIP reaches the
	// P-CSCF. Do not advertise UDP-enc-tun until IMS-level NAT traversal has a
	// complete public-inner/local-outer address implementation.
	algorithms := []struct {
		alg  string
		ealg string
	}{
		{alg: "hmac-sha-1-96", ealg: "null"},
		{alg: "hmac-sha-1-96", ealg: "aes-cbc"},
	}
	params := make(security.Params, 0, len(algorithms))
	for _, algorithm := range algorithms {
		param := base
		param.Alg = algorithm.alg
		param.EAlg = algorithm.ealg
		param.Mod = "trans"
		params = append(params, param)
	}
	return params
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
