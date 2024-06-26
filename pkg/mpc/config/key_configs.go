package config

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
)

type KeyConfig struct {
	keyID     string
	group     curve.Curve
	threshold int
	selfID    party.ID
	partyIDs  party.IDSlice
}

func NewKeyConfig(
	keyID string,
	group curve.Curve,
	threshold int,
	selfID party.ID,
	partyIDs party.IDSlice,
) *KeyConfig {
	return &KeyConfig{
		keyID:     keyID,
		group:     group,
		threshold: threshold,
		selfID:    selfID,
		partyIDs:  partyIDs,
	}
}

func (c *KeyConfig) ID() string {
	return c.keyID
}

func (c *KeyConfig) Group() curve.Curve {
	return c.group
}

func (c *KeyConfig) Threshold() int {
	return c.threshold
}

func (c *KeyConfig) SelfID() party.ID {
	return c.selfID
}

func (c *KeyConfig) PartyIDs() party.IDSlice {
	return c.partyIDs
}
