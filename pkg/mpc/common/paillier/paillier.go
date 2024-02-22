package paillier

import (
	comm_paillier "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/paillier"
	comm_pedersen "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/pedersen"
)

type PaillierKeyManager interface {
	GenerateKey(keyID string, partyID string) (comm_paillier.PaillierKey, error)
	ImportKey(keyID string, partyID string, data []byte) (comm_paillier.PaillierKey, error)
	GetKey(keyID string, partyID string) (comm_paillier.PaillierKey, error)
	DerivePedersenKey(keyID string, partyID string) (comm_pedersen.PedersenKey, error)
}
