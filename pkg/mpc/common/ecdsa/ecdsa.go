package ecdsa

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	comm_vss "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
)

type ECDSAKeyManager interface {
	GenerateKey(keyID string, partyID string) (comm_ecdsa.ECDSAKey, error)
	ImportKey(keyID string, partyID string, raw interface{}) (comm_ecdsa.ECDSAKey, error)
	GetKey(keyID string, partyID string) (comm_ecdsa.ECDSAKey, error)
	GetAllKeys(keyID string) (map[string]comm_ecdsa.ECDSAKey, error)
	GetVSSKey(keyID string, partyID string) (comm_vss.VssKey, error)
	GenerateMPCKeyFromShares(keyID string, selfID party.ID, group curve.Curve) error
}
