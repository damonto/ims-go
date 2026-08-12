package tunnel

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/damonto/ims-go/ipsec/esp"
	"github.com/damonto/ims-go/swu/handshake"
	"github.com/damonto/ims-go/swu/ike"
	usim "github.com/damonto/wwan-go/sim"
)

const (
	defaultIKENonceLength     = 32
	maxCookieNotifyDataLength = 64
	maxIKESAInitCookieRetries = 4
	ikeSPISeedLength          = 16
)

// ErrIKESAInitNoResponse reports that every IKE_SA_INIT retransmission timed
// out without receiving a matching response from the peer.
var ErrIKESAInitNoResponse = errors.New("ike_sa_init response not received")

type connectState struct {
	input                     handshake.ConnectInput
	saInit                    handshake.SAInitState
	auth                      handshake.AuthState
	established               handshake.Established
	card                      Card
	imei                      string
	identity                  string
	identityType              akaIdentityType
	realm                     string
	initialAKAState           usim.AKAIdentityState
	crypto                    *ikeCrypto
	initiatorSPI              uint64
	responderSPI              uint64
	espInitiatorSPI           uint32
	nonceI                    []byte
	ikeInitCookie             []byte
	ikeInitRequest            []byte
	ikeInitResponse           []byte
	responderNonce            []byte
	nattSupported             bool
	natDetected               bool
	useNATT                   bool
	ikeFragmentationSupported bool
	responderAPN              string
	nextMessageID             uint32
	finalPayloads             []ike.Payload
	tunnel                    Info
	espKeys                   ESPKeys
}

func (s *Session) Connect(ctx context.Context, req ConnectRequest) error {
	state, finish, err := s.prepareConnect(req)
	if err != nil {
		return fmt.Errorf("connecting swu session: %w", err)
	}
	defer finish()
	if err := s.connectAttempt(ctx, state); err != nil {
		return fmt.Errorf("connecting swu session: %w", err)
	}
	s.commitConnect(state)
	s.startBackgroundLoops()
	s.logger.Info("SWu security associations established", "inner_ip", state.tunnel.DefaultInnerIP(), "pcscf_ip", state.tunnel.DefaultPCSCFIP(), "pcscf_ips", state.tunnel.PCSCFAddresses(), "esp_initiator_spi", state.tunnel.ESPInitiatorSPI, "esp_responder_spi", state.tunnel.ESPResponderSPI)
	return nil
}

func (s *Session) connectAttempt(ctx context.Context, state *connectState) error {
	s.logger.Info("starting SWu authentication", "remote_addr", s.outerRemote, "aka_identity_type", state.identityType.String())
	if err := s.exchangeIKESAInit(ctx, state); err != nil {
		return err
	}
	s.logger.Info("IKE_SA_INIT established", "initiator_spi", state.initiatorSPI, "responder_spi", state.responderSPI, "natt_supported", state.nattSupported, "nat_detected", state.natDetected, "ike_fragmentation_supported", state.ikeFragmentationSupported)
	if err := s.exchangeIKEAuth(ctx, state); err != nil {
		return err
	}
	return nil
}

func (s *Session) prepareConnect(req ConnectRequest) (*connectState, func(), error) {
	input := handshake.ConnectInput{
		IMEI:            req.IMEI,
		Card:            req.Card,
		AuthenticateAKA: handshake.AKAAuthenticator(req.AuthenticateAKA),
		OuterRemote:     cloneUDPAddr(s.outerRemote),
		Logger:          s.logger,
		Config:          handshakeConfig(s.cfg),
	}
	if err := input.Validate(); err != nil {
		return nil, nil, err
	}
	finish, err := s.beginConnect()
	if err != nil {
		return nil, nil, err
	}
	state, err := newConnectState(input)
	if err != nil {
		finish()
		return nil, nil, err
	}
	return state, finish, nil
}

func (cs *connectState) consumeInitialAKAReauthIdentity() bool {
	if cs.identityType != akaIdentityFastReauth {
		return false
	}
	return discardStoredAKAReauthState(cs.card, cs.initialAKAState)
}

func (cs *connectState) discardRejectedAKAPseudonym(err error) bool {
	if cs.identityType != akaIdentityPseudonym || !isProtectedIKEAuthenticationFailed(err) {
		return false
	}
	return discardStoredAKATemporaryIdentities(cs.card, cs.initialAKAState)
}

func (s *Session) beginConnect() (func(), error) {
	if s.isClosed() {
		return nil, errors.New("session is closed")
	}
	s.mu.Lock()
	if s.connected {
		s.mu.Unlock()
		return nil, errors.New("already connected")
	}
	if err := s.disconnectedTunnelErr(); err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("close and redial session: %w", err)
	}
	if s.connecting {
		s.mu.Unlock()
		return nil, errors.New("connect already in progress")
	}
	s.connecting = true
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		s.connecting = false
		s.mu.Unlock()
	}, nil
}

func newConnectState(input handshake.ConnectInput) (*connectState, error) {
	selectedIdentity, err := selectInitialAKAIdentity(input.Card)
	if err != nil {
		return nil, fmt.Errorf("building aka identity: %w", err)
	}
	dhGroup := transformDH2048MODP
	if len(input.Config.DHGroups) != 0 {
		dhGroup = input.Config.DHGroups[0]
	}
	crypto, initiatorSPI, espInitiatorSPI, nonceI, err := newConnectCryptoState(dhGroup)
	if err != nil {
		return nil, err
	}
	return &connectState{
		input:           input,
		saInit:          handshake.SAInitState{InitiatorSPI: initiatorSPI, DHGroup: dhGroup, NonceI: append([]byte(nil), nonceI...), ChildInitiatorSPI: espInitiatorSPI},
		auth:            handshake.AuthState{Identity: selectedIdentity.identity, Realm: selectedIdentity.realm, CurrentMessageID: 1},
		card:            input.Card,
		imei:            input.IMEI,
		identity:        selectedIdentity.identity,
		identityType:    selectedIdentity.identityType,
		realm:           selectedIdentity.realm,
		initialAKAState: selectedIdentity.state,
		crypto:          crypto,
		initiatorSPI:    initiatorSPI,
		espInitiatorSPI: espInitiatorSPI,
		nonceI:          nonceI,
	}, nil
}

func newConnectCryptoState(dhGroup uint16) (*ikeCrypto, uint64, uint32, []byte, error) {
	crypto, err := newIKECrypto(dhGroup)
	if err != nil {
		return nil, 0, 0, nil, err
	}
	initiatorSPI := randomIKESPI()
	espInitiatorSPI := randomESPSPI()
	nonceI := randomBytes(defaultIKENonceLength)
	crypto.SetSPIs(initiatorSPI, 0)
	crypto.SetNonces(nonceI, nil)
	return crypto, initiatorSPI, espInitiatorSPI, nonceI, nil
}

func (cs *connectState) resetDHGroup(dhGroup uint16) error {
	crypto, err := newIKECrypto(dhGroup)
	if err != nil {
		return err
	}
	nonceI := randomBytes(defaultIKENonceLength)
	crypto.SetSPIs(cs.initiatorSPI, 0)
	crypto.SetNonces(nonceI, nil)
	cs.crypto = crypto
	cs.nonceI = nonceI
	cs.saInit.DHGroup = dhGroup
	cs.saInit.NonceI = append([]byte(nil), nonceI...)
	return nil
}

func marshalPayloadCopies(payloads []ike.Payload) [][]byte {
	out := make([][]byte, 0, len(payloads))
	for _, payload := range payloads {
		wire, err := payload.MarshalBinary()
		if err != nil {
			continue
		}
		out = append(out, append([]byte(nil), wire...))
	}
	return out
}

func (cs *connectState) outboundESPCodec() esp.Codec {
	return outboundESPCodec(cs.tunnel, cs.espKeys)
}

func (cs *connectState) inboundESPCodec() esp.Codec {
	return inboundESPCodec(cs.tunnel, cs.espKeys)
}

func (s *Session) connectIKEPeer(state *connectState) (*net.UDPAddr, bool) {
	if state != nil && state.useNATT {
		return cloneUDPAddr(s.outerNAT), true
	}
	return cloneUDPAddr(s.outerRemote), false
}

func outerIKEPeer(useNATT bool, outerRemote, outerNAT *net.UDPAddr) *net.UDPAddr {
	if useNATT {
		return cloneUDPAddr(outerNAT)
	}
	return cloneUDPAddr(outerRemote)
}

func outboundESPCodec(info Info, keys ESPKeys) esp.Codec {
	return newESPCodec(info.ESPResponderSPI, info, keys.EncryptionInitiator, keys.IntegrityInitiator)
}

func inboundESPCodec(info Info, keys ESPKeys) esp.Codec {
	return newESPCodec(info.ESPInitiatorSPI, info, keys.EncryptionResponder, keys.IntegrityResponder)
}

func newESPCodec(spi uint32, info Info, encryptionKeyMaterial, integrityKey []byte) esp.Codec {
	keyLen := int(info.EncryptionKeyLen / 8)
	codec := esp.Codec{
		SPI:           spi,
		Encryption:    encryptionName(info.Encryption),
		Integrity:     integrityName(info.Integrity),
		EncryptionKey: append([]byte(nil), encryptionKeyMaterial[:keyLen]...),
		IntegrityKey:  append([]byte(nil), integrityKey...),
	}
	if info.Encryption == transformENCRAESCTR {
		copy(codec.Salt[:], encryptionKeyMaterial[keyLen:])
	}
	return codec
}

func encryptionName(transform uint16) string {
	switch transform {
	case transformENCRAESCBC:
		return esp.EncryptionAESCBC
	case transformENCRAESCTR:
		return esp.EncryptionAESCTR
	default:
		return ""
	}
}

func (cs *connectState) sessionLivenessTimeout() time.Duration {
	timeout := livenessTimeout(cs.finalPayloads)
	if timeout > 0 {
		return timeout
	}
	if cs.input.Config.LivenessTimeout > 0 {
		return cs.input.Config.LivenessTimeout
	}
	return defaultLivenessTimeout
}

func livenessTimeout(payloads []ike.Payload) time.Duration {
	config := ike.FindConfigPayload(payloads)
	if config == nil {
		return 0
	}
	for _, attr := range config.Attributes {
		if attr.Type != configAttrTimeoutPeriodForLivenessCheck {
			continue
		}
		if attr.Format != attributeFormatTLV || len(attr.Value) != 4 {
			return 0
		}
		seconds := binary.BigEndian.Uint32(attr.Value)
		if seconds == 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	return 0
}

func uint32Bytes(value uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, value)
	return buf
}

func integrityName(transform uint16) string {
	switch transform {
	case transformINTEGHMACMD596:
		return esp.IntegrityHMACMD596
	case transformINTEGHMACSHA196:
		return esp.IntegrityHMACSHA196
	case transformINTEGAESXCBC96:
		return esp.IntegrityAESXCBC96
	case transformINTEGHMACSHA256:
		return esp.IntegrityHMACSHA256128
	case transformINTEGHMACSHA384:
		return esp.IntegrityHMACSHA384192
	case transformINTEGHMACSHA512:
		return esp.IntegrityHMACSHA512256
	default:
		return esp.IntegrityNone
	}
}

func randomBytes(n int) []byte {
	buf := make([]byte, n)
	_, _ = crand.Read(buf)
	return buf
}

func randomIKESPI() uint64 {
	for {
		buf := make([]byte, 8)
		_, _ = crand.Read(buf)
		if spi := binary.BigEndian.Uint64(buf); spi != 0 {
			return spi
		}
	}
}

func randomESPSPI() uint32 {
	for {
		buf := make([]byte, 4)
		_, _ = crand.Read(buf)
		if spi := binary.BigEndian.Uint32(buf); esp.ValidSPI(spi) {
			return spi
		}
	}
}

func validIKESPI(spi uint64) bool {
	return spi != 0
}

func ikeSPIInUse(spi uint64, existing ...uint64) bool {
	if spi == 0 {
		return true
	}
	for _, candidate := range existing {
		if spi == candidate {
			return true
		}
	}
	return false
}
