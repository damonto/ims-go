package tunnel

import (
	"encoding"
	"errors"
	"fmt"
	"time"

	"github.com/damonto/vowifi-go/swu/ike"
)

var (
	_ encoding.BinaryMarshaler   = backoffTimerNotifyData{}
	_ encoding.BinaryUnmarshaler = (*backoffTimerNotifyData)(nil)
)

type backoffTimerError struct {
	delay       time.Duration
	deactivated bool
	cause       uint16
	err         error
}

type BackoffScope int

const (
	BackoffScopeEPDG BackoffScope = iota + 1
	BackoffScopePLMNAPN
)

type BackoffPolicy struct {
	Delay       time.Duration
	Deactivated bool
	Scope       BackoffScope
}

const (
	backoffTimerDataLen byte = 2
	backoffTimerLen     byte = 1

	gprsTimer3ValueMask byte = 0x1f
	gprsTimer3UnitShift      = 5

	gprsTimer3Unit10Minutes byte = 0
	gprsTimer3Unit1Hour     byte = 1
	gprsTimer3Unit10Hours   byte = 2
	gprsTimer3Unit2Seconds  byte = 3
	gprsTimer3Unit30Seconds byte = 4
	gprsTimer3Unit1Minute   byte = 5
	gprsTimer3Unit320Hours  byte = 6
	gprsTimer3UnitDisabled  byte = 7

	gprsTimer3Duration10Minutes = 10 * time.Minute
	gprsTimer3Duration1Hour     = time.Hour
	gprsTimer3Duration10Hours   = 10 * time.Hour
	gprsTimer3Duration2Seconds  = 2 * time.Second
	gprsTimer3Duration30Seconds = 30 * time.Second
	gprsTimer3Duration1Minute   = time.Minute
	gprsTimer3Duration320Hours  = 320 * time.Hour
)

type backoffDelayCarrier interface {
	BackoffDelay() time.Duration
}

type backoffDeactivatedCarrier interface {
	BackoffDeactivated() bool
}

type backoffPolicyCarrier interface {
	BackoffPolicy() BackoffPolicy
}

type backoffTimerNotifyData struct {
	Value byte
}

func (d backoffTimerNotifyData) MarshalBinary() ([]byte, error) {
	return []byte{backoffTimerLen, d.Value}, nil
}

func (d *backoffTimerNotifyData) UnmarshalBinary(data []byte) error {
	if len(data) != int(backoffTimerDataLen) {
		return fmt.Errorf("parsing BACKOFF_TIMER notify: data length %d does not match %d", len(data), backoffTimerDataLen)
	}
	if data[0] != backoffTimerLen {
		return fmt.Errorf("parsing BACKOFF_TIMER notify: value length %d does not match %d", data[0], backoffTimerLen)
	}
	d.Value = data[1]
	return nil
}

func (d backoffTimerNotifyData) Duration() (time.Duration, bool) {
	return gprsTimer3Duration(d.Value)
}

func (d backoffTimerNotifyData) Deactivated() bool {
	return gprsTimer3Deactivated(d.Value)
}

func (e *backoffTimerError) Error() string {
	return e.err.Error()
}

func (e *backoffTimerError) Unwrap() error {
	return e.err
}

func (e *backoffTimerError) BackoffDelay() time.Duration {
	return e.delay
}

func (e *backoffTimerError) BackoffDeactivated() bool {
	return e.deactivated
}

func (e *backoffTimerError) BackoffPolicy() BackoffPolicy {
	return BackoffPolicy{
		Delay:       e.delay,
		Deactivated: e.deactivated,
		Scope:       backoffScopeForNotify(e.cause),
	}
}

// BackoffDelay returns the finite ePDG backoff delay carried by an IKE error.
// The caller owns scheduling; SWu only preserves the protocol constraint.
func BackoffDelay(err error) (time.Duration, bool) {
	var backoff backoffDelayCarrier
	if !errors.As(err, &backoff) || backoff.BackoffDelay() <= 0 {
		return 0, false
	}
	return backoff.BackoffDelay(), true
}

func BackoffDeactivated(err error) bool {
	var backoff backoffDeactivatedCarrier
	return errors.As(err, &backoff) && backoff.BackoffDeactivated()
}

func BackoffPolicyFor(err error) (BackoffPolicy, bool) {
	var backoff backoffPolicyCarrier
	if !errors.As(err, &backoff) {
		return BackoffPolicy{}, false
	}
	policy := backoff.BackoffPolicy()
	return policy, policy.Deactivated || policy.Delay > 0
}

func backoffTimerDelay(notify *ike.NotifyPayload) (time.Duration, bool) {
	delay, deactivated, ok := backoffTimerValue(notify)
	return delay, ok && !deactivated && delay > 0
}

func backoffTimerValue(notify *ike.NotifyPayload) (time.Duration, bool, bool) {
	if notify.NotifyType != notifyTypeBackoffTimer {
		return 0, false, false
	}
	var data backoffTimerNotifyData
	if err := data.UnmarshalBinary(notify.Data); err != nil {
		return 0, false, false
	}
	if data.Deactivated() {
		return 0, true, true
	}
	delay, ok := data.Duration()
	return delay, false, ok || delay == 0
}

func ikeErrorNotify(notifyType uint16) bool {
	return notifyType < notifyTypeStatusMin
}

func backoffScopeForNotify(notifyType uint16) BackoffScope {
	if notifyType == notifyTypeNoAPNSubscription {
		return BackoffScopePLMNAPN
	}
	return BackoffScopeEPDG
}

func gprsTimer3Duration(value byte) (time.Duration, bool) {
	timer := int(value & gprsTimer3ValueMask)
	if timer == 0 {
		return 0, false
	}
	switch value >> gprsTimer3UnitShift {
	case gprsTimer3Unit10Minutes:
		return time.Duration(timer) * gprsTimer3Duration10Minutes, true
	case gprsTimer3Unit1Hour:
		return time.Duration(timer) * gprsTimer3Duration1Hour, true
	case gprsTimer3Unit10Hours:
		return time.Duration(timer) * gprsTimer3Duration10Hours, true
	case gprsTimer3Unit2Seconds:
		return time.Duration(timer) * gprsTimer3Duration2Seconds, true
	case gprsTimer3Unit30Seconds:
		return time.Duration(timer) * gprsTimer3Duration30Seconds, true
	case gprsTimer3Unit1Minute:
		return time.Duration(timer) * gprsTimer3Duration1Minute, true
	case gprsTimer3Unit320Hours:
		return time.Duration(timer) * gprsTimer3Duration320Hours, true
	default:
		return 0, false
	}
}

func gprsTimer3Deactivated(value byte) bool {
	return value>>gprsTimer3UnitShift == gprsTimer3UnitDisabled
}
