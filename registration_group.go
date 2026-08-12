package ims

import (
	"context"
	"fmt"

	"github.com/damonto/ims-go/ims/registration"
	usim "github.com/damonto/wwan-go/sim"
)

const (
	defaultVoWiFiRegistrationID         uint32 = 1
	defaultVoLTERegistrationID          uint32 = 2
	defaultVoWiFiRegistrationPreference        = 1000
	defaultVoLTERegistrationPreference         = 500
)

// NewRegistrationGroup returns an empty group ready to be shared by Clients.
func NewRegistrationGroup() *registration.Group {
	return &registration.Group{}
}

func (c ServiceConfig) coordinatedAKA(authenticate func(context.Context, []byte, []byte) (usim.AKAResult, error)) func(context.Context, []byte, []byte) (usim.AKAResult, error) {
	if c.RegistrationGroup == nil {
		return authenticate
	}
	return func(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
		release, err := c.RegistrationGroup.BeginAKA(ctx, c.RegistrationPreference)
		if err != nil {
			return usim.AKAResult{}, fmt.Errorf("waiting for USIM AKA access: %w", err)
		}
		defer release()
		return authenticate(ctx, rand, autn)
	}
}
