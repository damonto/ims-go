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

// RegistrationGroup coordinates multiple Clients that use the same USIM and
// public IMS identity. Share one group between the VoWiFi and VoLTE configs.
type RegistrationGroup = registration.Group

// NewRegistrationGroup returns an empty group ready to be shared by Clients.
func NewRegistrationGroup() *RegistrationGroup {
	return &RegistrationGroup{}
}

func (cfg IMSConfig) coordinatedCard(card Card) Card {
	if cfg.RegistrationGroup == nil {
		return card
	}
	return registrationGroupCard{
		Card:       card,
		group:      cfg.RegistrationGroup,
		preference: cfg.RegistrationPreference,
	}
}

type registrationGroupCard struct {
	Card
	group      *RegistrationGroup
	preference int
}

func (c registrationGroupCard) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	release, err := c.group.BeginAKA(ctx, c.preference)
	if err != nil {
		return usim.AKAResult{}, fmt.Errorf("waiting for USIM AKA access: %w", err)
	}
	defer release()
	return c.Card.AKA(ctx, rand, autn)
}
