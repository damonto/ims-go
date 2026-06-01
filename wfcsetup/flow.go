package wfcsetup

import (
	"context"
	"errors"
)

type flow interface {
	Check(context.Context) (Result, error)
	E911UpdateSupport(context.Context) (E911UpdateSupport, error)
}

type flowFactory func(Request) (flow, bool, error)

var flowFactories = []flowFactory{
	newVZWFlow,
	newCanadaFlow,
	newTelusFlow,
	newO2UKFlow,
	newNSDSFlow,
	newTS43Flow,
}

func Check(ctx context.Context, req Request) (Result, error) {
	if err := req.validate(); err != nil {
		return Result{}, err
	}
	f, fallback, err := resolve(req)
	if err != nil {
		return Result{}, err
	}
	if f == nil {
		return fallback, nil
	}
	return f.Check(ctx)
}

func CheckE911UpdateSupport(ctx context.Context, req Request) (E911UpdateSupport, error) {
	req.Purpose = PurposeEmergencyAddressUpdate
	if err := req.validate(); err != nil {
		return E911UpdateSupport{}, err
	}
	f, _, err := resolve(req)
	if err != nil {
		return E911UpdateSupport{}, err
	}
	if f == nil {
		return E911UpdateSupport{
			Supported: false,
			Reason:    "no wfc setup profile matched",
		}, nil
	}
	return f.E911UpdateSupport(ctx)
}

func resolve(req Request) (flow, Result, error) {
	for _, factory := range flowFactories {
		f, ok, err := factory(req)
		if err != nil {
			return nil, Result{}, err
		}
		if ok {
			return f, Result{}, nil
		}
	}
	return nil, configNotFoundResult(req.Purpose), nil
}

func configNotFoundResult(purpose Purpose) Result {
	switch purpose {
	case PurposeActivation:
		return Result{Action: ActionAllowActivation, Entitled: true}
	case PurposeActivationRecheck:
		return Result{Action: ActionNone}
	case PurposeEmergencyAddressRecheck:
		return Result{Action: ActionNone}
	default:
		return Result{Action: ActionDenied}
	}
}

func resultError(result Result) error {
	if result.Entitled {
		return nil
	}
	err := ErrDenied
	switch result.Action {
	case ActionOpenWebsheet:
		err = ErrUserActionRequired
	case ActionWait:
		err = ErrPending
	}
	return &Error{Err: err, Result: result}
}

func wrapResultError(result Result, err error) error {
	if err == nil {
		return resultError(result)
	}
	var setupErr *Error
	if errors.As(err, &setupErr) {
		return err
	}
	return &Error{Err: err, Result: result}
}
