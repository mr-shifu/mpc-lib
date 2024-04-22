package config

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
)

type SignConfig struct {
	id        string
	keyID     string
	group     curve.Curve
	threshold int
	selfID    party.ID
	partyIDs  party.IDSlice
	message   []byte
}

func NewSignConfig(
	id string,
	keyID string,
	group curve.Curve,
	threshold int,
	selfID party.ID,
	partyIDs party.IDSlice,
	msg []byte,
) *SignConfig {
	return &SignConfig{
		id:        id,
		keyID:     keyID,
		group:     group,
		threshold: threshold,
		selfID:    selfID,
		partyIDs:  partyIDs,
		message:   msg,
	}
}

func (c *SignConfig) ID() string {
	return c.id
}

func (c *SignConfig) KeyID() string {
	return c.keyID
}

func (c *SignConfig) Group() curve.Curve {
	return c.group
}

func (c *SignConfig) Threshold() int {
	return c.threshold
}

func (c *SignConfig) SelfID() party.ID {
	return c.selfID
}

func (c *SignConfig) PartyIDs() party.IDSlice {
	return c.partyIDs
}

func (c *SignConfig) Message() []byte {
	return c.message
}
