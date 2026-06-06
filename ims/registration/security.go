package registration

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/damonto/vowifi-go/ims/security"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
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
	drains              []*attachmentDrain
	expiry              *secureAssociationExpiry
}

type registerSecurity struct {
	outbound            session.Transport
	outboundAttachment  session.Attachment
	inboundTransports   []session.Transport
	inboundAttachments  []session.Attachment
	responseAttachments []session.Attachment
}

func (s *Service) protectedRegisterExchangeOptions() session.ExchangeOptions {
	if !strings.EqualFold(sip.TransportToken(s.sess.LocalAddr()), "UDP") {
		return session.ExchangeOptions{}
	}
	transports := s.currentSecureServerTransports()
	if len(transports) == 0 {
		return session.ExchangeOptions{}
	}
	return session.ExchangeOptions{
		AcceptResponseTransport: acceptResponseFrom(transports),
		ResponseTransports:      transports,
	}
}

func (s *Service) currentSecurityVerify() *security.Param {
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

func (s *Service) applySelectedSecurityServer(verify *security.Param, raw []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flow.SecurityServerRaw = append([]string(nil), raw...)
	s.flow.SecurityVerify = verify
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
	transports := append([]session.Transport(nil), inbound...)
	if strings.EqualFold(sip.TransportToken(outbound.LocalAddr()), "TCP") {
		transports = append([]session.Transport{outbound}, transports...)
	}
	return uniqueSessionTransports(transports)
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
	if r == nil || r.outbound == nil || !strings.EqualFold(sip.TransportToken(r.outbound.LocalAddr()), "UDP") {
		return session.ExchangeOptions{}
	}
	if len(r.inboundTransports) == 0 {
		return session.ExchangeOptions{}
	}
	return session.ExchangeOptions{
		AcceptResponseTransport: acceptResponseFrom(r.inboundTransports),
		ResponseTransports:      r.inboundTransports,
	}
}

func (s *Service) replaceSecureServerAttachments(next []session.Attachment) []session.Attachment {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.secureServerAttachments
	s.secureServerAttachments = append([]session.Attachment(nil), next...)
	return old
}

func (s *Service) replaceSecureResponseAttachments(next []session.Attachment) []session.Attachment {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.secureResponseAttachments
	s.secureResponseAttachments = append([]session.Attachment(nil), next...)
	return old
}

func (s *Service) currentSecureServerTransports() []session.Transport {
	s.mu.Lock()
	attachments := append([]session.Attachment(nil), s.secureServerAttachments...)
	s.mu.Unlock()
	return attachmentTransports(attachments)
}

func (s *Service) closeAttachmentsAfter(attachments []session.Attachment, delay time.Duration) {
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

func (s *Service) forgetDrain(drain *attachmentDrain) {
	s.mu.Lock()
	s.drainTimers = slices.DeleteFunc(s.drainTimers, func(candidate *attachmentDrain) bool {
		return candidate == drain
	})
	s.mu.Unlock()
}

func (s *Service) closeSecureResources() {
	resources := s.takeSecureResourcesForClose()
	resources.stop()
	s.bgWG.Wait()
	resources.close()
}

func (s *Service) takeSecureResourcesForClose() secureResources {
	s.mu.Lock()
	resources := s.takeSecureResourcesLocked()
	s.mu.Unlock()
	return resources
}

func (s *Service) takeSecureResourcesForExpiry(expiry *secureAssociationExpiry) (secureResources, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.activeSecureSAExpiry != expiry {
		return secureResources{}, false
	}
	return s.takeSecureResourcesLocked(), true
}

func (s *Service) takeSecureResourcesLocked() secureResources {
	resources := secureResources{
		serverAttachments:   s.secureServerAttachments,
		responseAttachments: s.secureResponseAttachments,
		drains:              s.drainTimers,
		expiry:              s.activeSecureSAExpiry,
	}
	s.secureServerAttachments = nil
	s.secureResponseAttachments = nil
	s.drainTimers = nil
	s.activeSecureSAExpiry = nil
	s.activeSecureSAExpiresAt = time.Time{}
	s.closeDoneLocked()
	return resources
}

func (r secureResources) stop() {
	if r.expiry != nil {
		r.expiry.stop()
	}
	for _, drain := range r.drains {
		drain.cancel()
		drain.close()
	}
}

func (r secureResources) close() {
	closeAttachments(r.serverAttachments)
	closeAttachments(r.responseAttachments)
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

func (s *Service) secureAssociationExpiresAt(now time.Time) time.Time {
	if s.currentSecurityVerify() == nil {
		return time.Time{}
	}
	return now.Add(s.currentRegisterExpires() + secureAssociationLifetimeGrace)
}

func (s *Service) currentSecureAssociationExpiresAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeSecureSAExpiresAt
}

func (s *Service) extendActiveSecureAssociationLifetime(expiresAt time.Time) {
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
	if delay < 0 {
		delay = 0
	}
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
	go s.runSecureAssociationExpiry(done, expiry, delay)
}

func (s *Service) runSecureAssociationExpiry(done <-chan struct{}, expiry *secureAssociationExpiry, delay time.Duration) {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		s.expireActiveSecureAssociation(expiry)
	case <-done:
	case <-expiry.done():
	}
}

func (s *Service) expireActiveSecureAssociation(expiry *secureAssociationExpiry) {
	resources, ok := s.takeSecureResourcesForExpiry(expiry)
	if !ok {
		return
	}
	resources.stop()
	resources.close()
	s.setRegistered(false)
	s.publishRegistrationEvent(errSecureSAExpired)
}

func (s *Service) commitReauthentication(challenge security.Challenge, authorizationHeader string, flow Flow, ck, ik []byte, password string) {
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
	s.authHeader = authorizationHeader
	s.authNonceCount = 1
	s.authDigestNonce = challenge.Nonce
	s.authDigestAlgorithm = challenge.Algorithm
	s.authDigestPassword = password
	s.authCK = append([]byte(nil), ck...)
	s.authIK = append([]byte(nil), ik...)
	s.mu.Unlock()
}

func (s *Service) openRegisterSecurity(ctx context.Context) (*registerSecurity, error) {
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
	responseAttachments, err := s.startSecureResponseTransportsWithKeys(ctx, verify, flow, outbound, inboundTransports, s.authCK, s.authIK)
	if err != nil {
		registration.close()
		return nil, err
	}
	registration.responseAttachments = responseAttachments
	return registration, nil
}

func (s *Service) exchangeProtectedRegister(ctx context.Context, registration *registerSecurity, auth *security.Authorization) (sip.Message, error) {
	req := s.buildRegister(auth, s.currentSecurityVerify())
	if registration == nil || registration.outbound == nil {
		return s.sess.ExchangeWithOptions(ctx, req, s.protectedRegisterExchangeOptions())
	}
	return s.sess.ExchangeWithTransport(ctx, registration.outbound, req, registration.exchangeOptions())
}

func (s *Service) commitRegisterSecurity(registration *registerSecurity) error {
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
	if oldPrimary != nil {
		_ = oldPrimary.Close()
	}
	return nil
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

func (s *Service) dialSecureTransport(ctx context.Context, verify *security.Param, flow Flow, ck, ik []byte) (session.Transport, error) {
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

func (s *Service) startSecureServerTransports(ctx context.Context, verify *security.Param) ([]session.Transport, []session.Attachment, error) {
	flow := s.CurrentFlow()
	return s.startSecureServerTransportsWithKeys(ctx, verify, flow, s.authCK, s.authIK)
}

func (s *Service) startSecureServerTransportsWithKeys(ctx context.Context, verify *security.Param, flow Flow, ck, ik []byte) ([]session.Transport, []session.Attachment, error) {
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

func (s *Service) startSecureResponseTransportsWithKeys(ctx context.Context, verify *security.Param, flow Flow, outbound session.Transport, inboundTransports []session.Transport, ck, ik []byte) ([]session.Attachment, error) {
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

func selectSecurityServer(values []string) (*security.Param, []string, error) {
	raw := make([]string, 0, len(values))
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
			normalized, ok := security.NormalizeParam(param)
			if !ok {
				continue
			}
			q, err := securityQValue(param.Q)
			if err != nil {
				return nil, nil, fmt.Errorf("parsing Security-Server q-value %q: %w", param.Q, err)
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

func securityQValue(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 1000, nil
	}
	q, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, err
	}
	if q < 0 || q > 1 {
		return 0, fmt.Errorf("out of range q=%q", value)
	}
	return int(math.Round(q * 1000)), nil
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
	serverPort := randomIMSPort()
	for serverPort == clientPort || serverPort == registerPort {
		serverPort = randomIMSPort()
	}
	return security.Param{
		Mechanism: "ipsec-3gpp",
		Alg:       "hmac-sha-1-96",
		EAlg:      "aes-cbc",
		Mod:       "trans",
		PortC:     clientPort,
		PortS:     serverPort,
		Prot:      "esp",
		SPIC:      randomNonZeroUint32Except(0),
		SPIS:      randomNonZeroUint32Except(0),
	}
}

func securityClientCapabilities(base security.Param) security.Params {
	ealgs := []string{"null", "aes-cbc"}
	params := make(security.Params, 0, len(ealgs))
	for _, ealg := range ealgs {
		param := base
		param.EAlg = ealg
		params = append(params, param)
	}
	return params
}

func reauthSecurityClient(current security.Param, registerPort int) security.Param {
	next := current
	next.PortC = randomIMSPort()
	for next.PortC == current.PortC || next.PortC == current.PortS || next.PortC == registerPort {
		next.PortC = randomIMSPort()
	}
	next.SPIC = randomNonZeroUint32Except(current.SPIC)
	next.SPIS = randomNonZeroUint32Except(current.SPIS)
	return next
}

func randomNonZeroUint32Except(except uint32) uint32 {
	value := sip.RandomUint32()
	for !security.ValidESPSPI(value) || value == except {
		value = sip.RandomUint32()
	}
	return value
}

func randomIMSPort() int {
	const base = 10000
	const span = 55535
	return base + int(sip.RandomUint32()%span)
}
