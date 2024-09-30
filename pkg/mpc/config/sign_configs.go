package config

import (
	"github.com/mr-shifu/mpc-lib/core/party"
)

type SignConfig struct {
	id        string
	keyID     string
	selfID    party.ID
	partyIDs  party.IDSlice
	message   []byte
}

func NewSignConfig(
	id string,
	keyID string,
	selfID party.ID,
	partyIDs party.IDSlice,
	msg []byte,
) *SignConfig {
	return &SignConfig{
		id:        id,
		keyID:     keyID,
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

func (c *SignConfig) SelfID() party.ID {
	return c.selfID
}

func (c *SignConfig) PartyIDs() party.IDSlice {
	return c.partyIDs
}

func (c *SignConfig) Message() []byte {
	return c.message
}
