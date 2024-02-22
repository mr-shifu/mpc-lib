package vss

import (
	comm_vss "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
)

type VssKeyManager interface {
	GenerateKey(keyID string, partyID string) (comm_vss.VssKey, error)
	ImportKey(keyID string, partyID string, data []byte) (comm_vss.VssKey, error)
	GetKey(keyID string, partyID string) (comm_vss.VssKey, error)
}
