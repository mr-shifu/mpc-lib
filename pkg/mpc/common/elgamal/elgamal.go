package elgamal

import (
	comm_elgamal "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/elgamal"
)

type ElgamalKeyManager interface {
	GenerateKey(keyID string, partyID string) (comm_elgamal.ElgamalKey, error)
	ImportKey(keyID string, partyID string, data interface{}) (comm_elgamal.ElgamalKey, error)
	GetKey(keyID string, partyID string) (comm_elgamal.ElgamalKey, error)
}
