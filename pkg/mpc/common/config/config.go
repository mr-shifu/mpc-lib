package config

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
)

type ConfigStore interface {
	Import(ID string, config interface{}) error
	Get(ID string) (interface{}, error)
}

type KeyConfig interface {
	ID() string
	Group() curve.Curve
	Threshold() int
	SelfID() party.ID
	PartyIDs() party.IDSlice
}

type KeyConfigManager interface {
	ImportConfig(config KeyConfig) error
	GetConfig(id string) (KeyConfig, error)
}

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
	GetConfig(id string) (SignConfig, error)
}
