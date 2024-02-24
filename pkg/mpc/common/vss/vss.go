package vss

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	comm_vss "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
)

type VssKeyManager interface {
	GenerateSecrets(keyID string, partyID string, secret curve.Scalar, degree int) (comm_vss.VssKey, error)
	ImportKey(keyID string, partyID string, data []byte) (comm_vss.VssKey, error)
	GetKey(keyID string, partyID string) (comm_vss.VssKey, error)
}
