package config

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
)

type SignConfig interface {
	ID() string
	KeyID() string
	Group() curve.Curve
	Threshold() int
	SelfID() party.ID
	PartyIDs() party.IDSlice
}

type SignConfigManager interface {
	ImportConfig(config SignConfig) error
	GetConfig(id string) SignConfig
}
