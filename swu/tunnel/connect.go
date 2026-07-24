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

type connectState struct {
	input                     handshake.ConnectInput
	saInit                    handshake.SAInitState
	auth                      handshake.AuthState
	established               handshake.Established
	card                      Card
	imei                      string
	identity                  string
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

func (s *Session) Connect(ctx context.Context, imei string, card Card) error {
	state, finish, err := s.prepareConnect(imei, card)
	if err != nil {
		return fmt.Errorf("connecting swu session: %w", err)
	}
	defer finish()
	if err := s.connectAttempt(ctx, state); err != nil {
		retryState, retryErr := s.retryConnectWithPermanentAKA(ctx, state, err)
		switch {
		case retryErr != nil:
			return fmt.Errorf("connecting swu session: retrying permanent aka identity: %w", retryErr)
		case retryState != nil:
			state = retryState
		default:
			return fmt.Errorf("connecting swu session: %w", err)
		}
	}
	s.commitConnect(state)
	s.startBackgroundLoops()
	s.logger.Info("SWu security associations established", "inner_ip", state.tunnel.DefaultInnerIP(), "pcscf_ip", state.tunnel.DefaultPCSCFIP(), "pcscf_ips", state.tunnel.PCSCFAddresses(), "esp_initiator_spi", state.tunnel.ESPInitiatorSPI, "esp_responder_spi", state.tunnel.ESPResponderSPI)
	return nil
}

func (s *Session) connectAttempt(ctx context.Context, state *connectState) error {
	s.logger.Info("starting SWu authentication", "remote_addr", s.outerRemote, "temporary_aka_identity", state.usesTemporaryAKAIdentity())
	if err := s.exchangeIKESAInit(ctx, state); err != nil {
		return err
	}
	s.logger.Info("IKE_SA_INIT established", "initiator_spi", state.initiatorSPI, "responder_spi", state.responderSPI, "natt_supported", state.nattSupported, "nat_detected", state.natDetected, "ike_fragmentation_supported", state.ikeFragmentationSupported)
	if err := s.exchangeIKEAuth(ctx, state); err != nil {
		return err
	}
	return nil
}

func (s *Session) retryConnectWithPermanentAKA(ctx context.Context, state *connectState, err error) (*connectState, error) {
	if !state.shouldRetryPermanentAKA(err) {
		return nil, nil
	}
	s.logger.Info("temporary AKA identity rejected; retrying with permanent identity", "cause", ErrUserUnknown)
	discardStoredAKATemporaryIdentity(state.card, state.initialAKAState)
	retryState, retryErr := newConnectState(state.input)
	if retryErr != nil {
		return nil, retryErr
	}
	retryState.usePermanentAKAIdentity()
	if err := s.connectAttempt(ctx, retryState); err != nil {
		return nil, err
	}
	return retryState, nil
}

func (s *Session) prepareConnect(imei string, card Card) (*connectState, func(), error) {
	input := handshake.ConnectInput{
		IMEI:        imei,
		Card:        card,
		OuterRemote: cloneUDPAddr(s.outerRemote),
		Logger:      s.logger,
		Config:      handshakeConfig(s.cfg),
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

func (state *connectState) usesTemporaryAKAIdentity() bool {
	return state != nil && hasAKATemporaryIdentity(state.initialAKAState)
}

func (state *connectState) shouldRetryPermanentAKA(err error) bool {
	return state.usesTemporaryAKAIdentity() && errors.Is(err, ErrUserUnknown)
}

func (state *connectState) usePermanentAKAIdentity() {
	state.initialAKAState = withoutAKATemporaryIdentity(state.initialAKAState)
	state.identity = akaPermanentIdentity(state.card, state.realm, eapTypeAKA)
	state.auth.Identity = state.identity
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
	identity, realm, initialAKAState, err := initialAKAIdentity(input.Card)
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
		auth:            handshake.AuthState{Identity: identity, Realm: realm, CurrentMessageID: 1},
		card:            input.Card,
		imei:            input.IMEI,
		identity:        identity,
		realm:           realm,
		initialAKAState: initialAKAState,
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
	initiatorSPI, err := randomIKESPI()
	if err != nil {
		return nil, 0, 0, nil, fmt.Errorf("generating initiator spi: %w", err)
	}
	espInitiatorSPI, err := randomESPSPI()
	if err != nil {
		return nil, 0, 0, nil, fmt.Errorf("generating child spi: %w", err)
	}
	nonceI, err := randomBytes(defaultIKENonceLength)
	if err != nil {
		return nil, 0, 0, nil, fmt.Errorf("generating nonce: %w", err)
	}
	crypto.SetSPIs(initiatorSPI, 0)
	crypto.SetNonces(nonceI, nil)
	return crypto, initiatorSPI, espInitiatorSPI, nonceI, nil
}

func (state *connectState) resetDHGroup(dhGroup uint16) error {
	crypto, err := newIKECrypto(dhGroup)
	if err != nil {
		return err
	}
	nonceI, err := randomBytes(defaultIKENonceLength)
	if err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}
	crypto.SetSPIs(state.initiatorSPI, 0)
	crypto.SetNonces(nonceI, nil)
	state.crypto = crypto
	state.nonceI = nonceI
	state.saInit.DHGroup = dhGroup
	state.saInit.NonceI = append([]byte(nil), nonceI...)
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

func (state *connectState) outboundESPCodec() esp.Codec {
	return outboundESPCodec(state.tunnel, state.espKeys)
}

func (state *connectState) inboundESPCodec() esp.Codec {
	return inboundESPCodec(state.tunnel, state.espKeys)
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

func (state *connectState) sessionLivenessTimeout() time.Duration {
	timeout := livenessTimeout(state.finalPayloads)
	if timeout > 0 {
		return timeout
	}
	if state.input.Config.LivenessTimeout > 0 {
		return state.input.Config.LivenessTimeout
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

func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := crand.Read(buf)
	return buf, err
}

func randomIKESPI() (uint64, error) {
	for {
		buf := make([]byte, 8)
		if _, err := crand.Read(buf); err != nil {
			return 0, err
		}
		if spi := binary.BigEndian.Uint64(buf); spi != 0 {
			return spi, nil
		}
	}
}

func randomESPSPI() (uint32, error) {
	for {
		buf := make([]byte, 4)
		if _, err := crand.Read(buf); err != nil {
			return 0, err
		}
		if spi := binary.BigEndian.Uint32(buf); esp.ValidSPI(spi) {
			return spi, nil
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
