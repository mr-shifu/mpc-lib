package vss

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
	comm_vss "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
)

type VssKeyManager interface {
	GenerateSecrets(keyID string, partyID string, secret curve.Scalar, degree int) (comm_vss.VssKey, error)
	ImportKey(keyID string, partyID string, data []byte) (comm_vss.VssKey, error)
	GetKey(keyID string, partyID string) (comm_vss.VssKey, error)
	GenerateVSSShare(keyID string, vss_partyID party.ID, ec_partyID party.ID, group curve.Curve) error
	ImportShare(keyID string, vss_partyID party.ID, ec_partyID party.ID, share comm_ecdsa.ECDSAKey) error
	GetShare(keyID string, vss_partyID party.ID, ec_partyID party.ID) (comm_ecdsa.ECDSAKey, error)
}
