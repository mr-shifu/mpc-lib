package mpckey

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
)

type MPCKey struct {
	ID        string
	Group     curve.Curve
	Threshold int
	SelfID    party.ID
	PartyIDs  party.IDSlice
	RID       []byte
	ChainKey  []byte
}

type MPCKeystore interface {
	Get(keyID string) (MPCKey, error)
	Import(key MPCKey) error
	Update(key MPCKey) error
	Delete(keyID string) error
}
